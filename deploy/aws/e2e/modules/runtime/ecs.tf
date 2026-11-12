resource "aws_cloudwatch_log_group" "ecs_exec" {
  name              = "/ecs/${var.name_prefix}/exec"
  retention_in_days = 1
  tags              = var.tags
}

resource "aws_cloudwatch_log_group" "service" {
  for_each = toset(["console", "coord", "relay"])

  name              = "/ecs/${var.name_prefix}/${each.value}"
  retention_in_days = 1
  tags              = merge(var.tags, { Component = each.value })
}

resource "aws_ecs_cluster" "this" {
  name = var.name_prefix

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  configuration {
    execute_command_configuration {
      logging = "OVERRIDE"

      log_configuration {
        cloud_watch_encryption_enabled = false
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.ecs_exec.name
      }
    }
  }

  tags = var.tags
}

resource "aws_ecs_task_definition" "console" {
  family                   = "${var.name_prefix}-console"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_console_task.arn

  volume {
    name = "console-cache"
  }

  volume {
    name = "console-tmp"
  }

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([
    {
      name                   = "console-volumes"
      image                  = var.console_image
      essential              = false
      user                   = "0"
      readonlyRootFilesystem = true
      entryPoint             = ["/bin/sh", "-c"]
      command                = ["chown blaktail:blaktail /tmp /app/.next/cache && chmod 0700 /tmp /app/.next/cache"]
      mountPoints = [
        { sourceVolume = "console-cache", containerPath = "/app/.next/cache", readOnly = false },
        { sourceVolume = "console-tmp", containerPath = "/tmp", readOnly = false },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = merge(local.log_options, {
          awslogs-group         = aws_cloudwatch_log_group.service["console"].name
          awslogs-stream-prefix = "console-volumes"
        })
      }
    },
    {
      name                   = "console"
      image                  = var.console_image
      essential              = true
      command                = ["bun", "--bun", "next", "start", "-p", "3000"]
      readonlyRootFilesystem = true
      dependsOn              = [{ containerName = "console-volumes", condition = "SUCCESS" }]
      portMappings = [{
        name          = "console-http"
        containerPort = 3000
        hostPort      = 3000
        protocol      = "tcp"
      }]
      environment = [
        { name = "BLAKTAIL_REGION", value = var.region },
        { name = "BETTER_AUTH_URL", value = local.public_url },
        { name = "BETTER_AUTH_TRUSTED_ORIGINS", value = local.public_url },
        { name = "COORD_BASE_URL", value = local.public_url },
        # API Gateway and the internal ALB each append one X-Forwarded-For hop.
        { name = "BLAKTAIL_TRUSTED_PROXY_HOPS", value = "2" },
      ]
      secrets = [
        { name = "DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.console.arn}:DATABASE_URL::" },
        { name = "BETTER_AUTH_SECRET", valueFrom = "${aws_secretsmanager_secret.console.arn}:BETTER_AUTH_SECRET::" },
        { name = "BLAKTAIL_AUTH_HMAC_SECRET", valueFrom = "${aws_secretsmanager_secret.console.arn}:BLAKTAIL_AUTH_HMAC_SECRET::" },
      ]
      mountPoints = [
        { sourceVolume = "console-cache", containerPath = "/app/.next/cache", readOnly = false },
        { sourceVolume = "console-tmp", containerPath = "/tmp", readOnly = false },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = merge(local.log_options, {
          awslogs-group         = aws_cloudwatch_log_group.service["console"].name
          awslogs-stream-prefix = "console"
        })
      }
    },
  ])

  tags = var.tags

  depends_on = [aws_secretsmanager_secret_version.console]
}

resource "aws_ecs_service" "console" {
  name                   = "${var.name_prefix}-console"
  cluster                = aws_ecs_cluster.this.id
  task_definition        = aws_ecs_task_definition.console.arn
  desired_count          = var.deploy_services ? var.console_desired_count : 0
  launch_type            = "FARGATE"
  platform_version       = "LATEST"
  enable_execute_command = true

  network_configuration {
    subnets          = aws_subnet.tasks[*].id
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.console.arn
    container_name   = "console"
    container_port   = 3000
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = var.tags

  depends_on = [aws_lb_listener.internal, aws_route_table_association.tasks]
}

resource "aws_ecs_task_definition" "coord" {
  family                   = "${var.name_prefix}-coord"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  volume {
    name = "coord-tls"
  }

  container_definitions = jsonencode([
    {
      name                   = "certgen"
      image                  = var.coord_proxy_image
      essential              = false
      readonlyRootFilesystem = true
      entryPoint             = ["/bin/sh", "-c"]
      command = [
        "umask 077; openssl req -x509 -newkey rsa:2048 -nodes -keyout /tls/tls.key -out /tls/tls.crt -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 >/dev/null 2>&1; chown 10001:10001 /tls/tls.crt /tls/tls.key; chmod 0444 /tls/tls.crt; chmod 0400 /tls/tls.key"
      ]
      mountPoints = [{
        sourceVolume  = "coord-tls"
        containerPath = "/tls"
        readOnly      = false
      }]
      logConfiguration = {
        logDriver = "awslogs"
        options = merge(local.log_options, {
          awslogs-group         = aws_cloudwatch_log_group.service["coord"].name
          awslogs-stream-prefix = "certgen"
        })
      }
    },
    {
      name                   = "coord"
      image                  = var.coord_image
      essential              = true
      entryPoint             = ["/usr/local/bin/blaktail-coord"]
      readonlyRootFilesystem = true
      dependsOn              = [{ containerName = "certgen", condition = "SUCCESS" }]
      environment = [
        { name = "BLAKTAIL_DEPLOYMENT_PROFILE", value = "e2e" },
        { name = "BLAKTAIL_REGION", value = var.region },
        { name = "BLAKTAIL_BIND", value = "0.0.0.0:8443" },
        { name = "BLAKTAIL_COORD_METRICS_BIND", value = "0.0.0.0:9701" },
        { name = "BLAKTAIL_COORD_ALLOW_PUBLIC_METRICS", value = "true" },
        { name = "BLAKTAIL_DATABASE_BACKEND", value = "postgres" },
        { name = "BLAKTAIL_DATABASE_STORAGE", value = "network" },
        { name = "BLAKTAIL_RELAYS", value = local.relay_endpoint },
        { name = "BLAKTAIL_CONSOLE_URL", value = local.public_url },
        { name = "BLAKTAIL_TLS_CERT", value = "/tls/tls.crt" },
        { name = "BLAKTAIL_TLS_KEY", value = "/tls/tls.key" },
      ]
      secrets = [
        { name = "BLAKTAIL_AUTH_HMAC_SECRET", valueFrom = "${aws_secretsmanager_secret.control_plane.arn}:BLAKTAIL_AUTH_HMAC_SECRET::" },
        { name = "BLAKTAIL_RELAY_AUTH_SECRET", valueFrom = "${aws_secretsmanager_secret.control_plane.arn}:BLAKTAIL_RELAY_AUTH_SECRET::" },
        { name = "BLAKTAIL_COORD_DIAGNOSTICS_TOKEN", valueFrom = "${aws_secretsmanager_secret.control_plane.arn}:BLAKTAIL_DIAGNOSTICS_TOKEN::" },
        { name = "BLAKTAIL_DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.control_plane.arn}:BLAKTAIL_DATABASE_URL::" },
      ]
      mountPoints = [
        { sourceVolume = "coord-tls", containerPath = "/tls", readOnly = true },
      ]
      portMappings = [
        { name = "coord-tls", containerPort = 8443, hostPort = 8443, protocol = "tcp" },
        { name = "coord-metrics", containerPort = 9701, hostPort = 9701, protocol = "tcp" },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = merge(local.log_options, {
          awslogs-group         = aws_cloudwatch_log_group.service["coord"].name
          awslogs-stream-prefix = "coord"
        })
      }
    },
    {
      name      = "coord-proxy"
      image     = var.coord_proxy_image
      essential = true
      dependsOn = [
        { containerName = "certgen", condition = "SUCCESS" },
        { containerName = "coord", condition = "START" },
      ]
      command = ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
      portMappings = [{
        name          = "coord-http"
        containerPort = 8080
        hostPort      = 8080
        protocol      = "tcp"
      }]
      logConfiguration = {
        logDriver = "awslogs"
        options = merge(local.log_options, {
          awslogs-group         = aws_cloudwatch_log_group.service["coord"].name
          awslogs-stream-prefix = "proxy"
        })
      }
    },
  ])

  tags = var.tags

  depends_on = [aws_secretsmanager_secret_version.control_plane]
}

resource "aws_ecs_task_definition" "coord_migration" {
  family                   = "${var.name_prefix}-coord-migration"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  volume {
    name = "coord-tls"
  }

  container_definitions = jsonencode([
    {
      name                   = "certgen"
      image                  = var.coord_proxy_image
      essential              = false
      readonlyRootFilesystem = true
      entryPoint             = ["/bin/sh", "-c"]
      command = [
        "umask 077; openssl req -x509 -newkey rsa:2048 -nodes -keyout /tls/tls.key -out /tls/tls.crt -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1 >/dev/null 2>&1; chown 10001:10001 /tls/tls.crt /tls/tls.key; chmod 0444 /tls/tls.crt; chmod 0400 /tls/tls.key"
      ]
      mountPoints = [{
        sourceVolume  = "coord-tls"
        containerPath = "/tls"
        readOnly      = false
      }]
      logConfiguration = {
        logDriver = "awslogs"
        options = merge(local.log_options, {
          awslogs-group         = aws_cloudwatch_log_group.service["coord"].name
          awslogs-stream-prefix = "migration-certgen"
        })
      }
    },
    {
      name                   = "coord-migration"
      image                  = var.coord_image
      essential              = true
      readonlyRootFilesystem = true
      entryPoint             = ["/bin/sh", "-c"]
      command = [
        "/usr/local/bin/blaktail-config dump-config --service coordinator --redacted && exec /usr/local/bin/blaktail-coord migrate"
      ]
      dependsOn = [{ containerName = "certgen", condition = "SUCCESS" }]
      environment = [
        { name = "BLAKTAIL_DEPLOYMENT_PROFILE", value = "e2e" },
        { name = "BLAKTAIL_REGION", value = var.region },
        { name = "BLAKTAIL_BIND", value = "0.0.0.0:8443" },
        { name = "BLAKTAIL_COORD_METRICS_BIND", value = "0.0.0.0:9701" },
        { name = "BLAKTAIL_COORD_ALLOW_PUBLIC_METRICS", value = "true" },
        { name = "BLAKTAIL_DATABASE_BACKEND", value = "postgres" },
        { name = "BLAKTAIL_DATABASE_STORAGE", value = "network" },
        { name = "BLAKTAIL_RELAYS", value = local.relay_endpoint },
        { name = "BLAKTAIL_CONSOLE_URL", value = local.public_url },
        { name = "BLAKTAIL_TLS_CERT", value = "/tls/tls.crt" },
        { name = "BLAKTAIL_TLS_KEY", value = "/tls/tls.key" },
      ]
      secrets = [
        { name = "BLAKTAIL_AUTH_HMAC_SECRET", valueFrom = "${aws_secretsmanager_secret.control_plane.arn}:BLAKTAIL_AUTH_HMAC_SECRET::" },
        { name = "BLAKTAIL_RELAY_AUTH_SECRET", valueFrom = "${aws_secretsmanager_secret.control_plane.arn}:BLAKTAIL_RELAY_AUTH_SECRET::" },
        { name = "BLAKTAIL_COORD_DIAGNOSTICS_TOKEN", valueFrom = "${aws_secretsmanager_secret.control_plane.arn}:BLAKTAIL_DIAGNOSTICS_TOKEN::" },
        { name = "BLAKTAIL_DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.control_plane.arn}:BLAKTAIL_DATABASE_URL::" },
      ]
      mountPoints = [
        { sourceVolume = "coord-tls", containerPath = "/tls", readOnly = true },
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = merge(local.log_options, {
          awslogs-group         = aws_cloudwatch_log_group.service["coord"].name
          awslogs-stream-prefix = "migration"
        })
      }
    },
  ])

  tags = var.tags

  depends_on = [aws_secretsmanager_secret_version.control_plane]
}

resource "aws_ecs_service" "coord" {
  name                   = "${var.name_prefix}-coord"
  cluster                = aws_ecs_cluster.this.id
  task_definition        = aws_ecs_task_definition.coord.arn
  desired_count          = var.deploy_services ? var.coord_desired_count : 0
  launch_type            = "FARGATE"
  platform_version       = "LATEST"
  enable_execute_command = true

  network_configuration {
    subnets          = aws_subnet.tasks[*].id
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.coord.arn
    container_name   = "coord-proxy"
    container_port   = 8080
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = var.tags

  depends_on = [aws_lb_listener_rule.coord, aws_route_table_association.tasks]
}

resource "aws_ecs_task_definition" "relay" {
  family                   = "${var.name_prefix}-relay"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    name                   = "relay"
    image                  = var.relay_image
    essential              = true
    readonlyRootFilesystem = true
    environment = [
      { name = "BLAKTAIL_REGION", value = var.region },
      { name = "BLAKTAIL_RELAY_BIND", value = "0.0.0.0:3478" },
      { name = "BLAKTAIL_RELAY_METRICS_BIND", value = "0.0.0.0:9702" },
      { name = "BLAKTAIL_RELAY_ALLOW_PUBLIC_METRICS", value = "true" },
    ]
    secrets = [
      { name = "BLAKTAIL_RELAY_AUTH_SECRET", valueFrom = "${aws_secretsmanager_secret.control_plane.arn}:BLAKTAIL_RELAY_AUTH_SECRET::" },
      { name = "BLAKTAIL_RELAY_DIAGNOSTICS_TOKEN", valueFrom = "${aws_secretsmanager_secret.control_plane.arn}:BLAKTAIL_DIAGNOSTICS_TOKEN::" },
    ]
    portMappings = [
      { name = "relay-udp", containerPort = 3478, hostPort = 3478, protocol = "udp" },
      { name = "relay-metrics", containerPort = 9702, hostPort = 9702, protocol = "tcp" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = merge(local.log_options, {
        awslogs-group         = aws_cloudwatch_log_group.service["relay"].name
        awslogs-stream-prefix = "relay"
      })
    }
  }])

  tags = var.tags

  depends_on = [aws_secretsmanager_secret_version.control_plane]
}

resource "aws_ecs_service" "relay" {
  name                   = "${var.name_prefix}-relay"
  cluster                = aws_ecs_cluster.this.id
  task_definition        = aws_ecs_task_definition.relay.arn
  desired_count          = var.deploy_services ? 1 : 0
  launch_type            = "FARGATE"
  platform_version       = "LATEST"
  enable_execute_command = true

  network_configuration {
    subnets          = aws_subnet.tasks[*].id
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.relay.arn
    container_name   = "relay"
    container_port   = 3478
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = var.tags

  depends_on = [aws_lb_listener.relay, aws_route_table_association.tasks]
}
