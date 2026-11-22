resource "aws_ecs_cluster" "this" {
  name = var.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = local.tags
}

resource "aws_iam_role" "execution" {
  name = "${var.name}-ecs-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  name = "${var.name}-ecs-secrets"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["secretsmanager:GetSecretValue"]
      Resource = [
        aws_secretsmanager_secret.console_env.arn,
        aws_secretsmanager_secret.coord_env.arn,
        aws_secretsmanager_secret.db_master.arn,
      ]
    }]
  })
}

locals {
  console_image   = var.console_image != "" ? var.console_image : "${aws_ecr_repository.console.repository_url}:latest"
  coord_image     = var.coord_image != "" ? var.coord_image : "${aws_ecr_repository.coord.repository_url}:latest"
  relay_image     = var.relay_image != "" ? var.relay_image : "${aws_ecr_repository.relay.repository_url}:latest"
  better_auth_url = var.better_auth_url != "" ? var.better_auth_url : "http://${aws_lb.console.dns_name}"
}

resource "aws_ecs_task_definition" "console" {
  family                   = "${var.name}-console"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }
  container_definitions = jsonencode([{
    name         = "console"
    image        = local.console_image
    portMappings = [{ containerPort = 3000, protocol = "tcp" }]
    environment = [
      { name = "BLAKTAIL_REGION", value = var.region },
      { name = "BETTER_AUTH_URL", value = local.better_auth_url },
      { name = "BETTER_AUTH_TRUSTED_ORIGINS", value = local.better_auth_url },
      { name = "COORD_BASE_URL", value = "https://${aws_lb.coord.dns_name}" },
      # The console ALB appends the client address to X-Forwarded-For.
      { name = "BLAKTAIL_TRUSTED_PROXY_HOPS", value = "1" },
    ]
    secrets = [
      { name = "DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.console_env.arn}:DATABASE_URL::" },
      { name = "BETTER_AUTH_SECRET", valueFrom = "${aws_secretsmanager_secret.console_env.arn}:BETTER_AUTH_SECRET::" },
      { name = "BLAKTAIL_AUTH_HMAC_SECRET", valueFrom = "${aws_secretsmanager_secret.console_env.arn}:BLAKTAIL_AUTH_HMAC_SECRET::" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.console.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "console"
      }
    }
  }])
  tags = local.tags
}

resource "aws_cloudwatch_log_group" "console" {
  name              = "/ecs/${var.name}/console"
  retention_in_days = 30
  tags              = local.tags
}

resource "aws_ecs_service" "console" {
  name            = "console"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.console.arn
  desired_count   = var.console_min_tasks
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = true
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

  depends_on = [aws_lb_listener.console_http]
  tags       = local.tags
}

resource "aws_ecs_task_definition" "coord" {
  family                   = "${var.name}-coord"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }
  container_definitions = jsonencode([{
    name         = "coord"
    image        = local.coord_image
    portMappings = [{ containerPort = 8443, protocol = "tcp" }]
    environment = [
      { name = "BLAKTAIL_REGION", value = var.region },
      { name = "BLAKTAIL_BIND", value = "0.0.0.0:8443" },
      { name = "BLAKTAIL_DATABASE_BACKEND", value = "postgres" },
      { name = "BLAKTAIL_DATABASE_STORAGE", value = "network" },
      { name = "BLAKTAIL_RELAYS", value = "${aws_lb.relay.dns_name}:3478" },
      { name = "BLAKTAIL_CONSOLE_URL", value = local.better_auth_url },
    ]
    secrets = [
      { name = "BLAKTAIL_AUTH_HMAC_SECRET", valueFrom = "${aws_secretsmanager_secret.coord_env.arn}:BLAKTAIL_AUTH_HMAC_SECRET::" },
      { name = "BLAKTAIL_RELAY_AUTH_SECRET", valueFrom = "${aws_secretsmanager_secret.coord_env.arn}:BLAKTAIL_RELAY_AUTH_SECRET::" },
      { name = "BLAKTAIL_DATABASE_URL", valueFrom = "${aws_secretsmanager_secret.coord_env.arn}:BLAKTAIL_DATABASE_URL::" },
      { name = "BLAKTAIL_TLS_CERT_PEM", valueFrom = "${aws_secretsmanager_secret.coord_env.arn}:BLAKTAIL_TLS_CERT_PEM::" },
      { name = "BLAKTAIL_TLS_KEY_PEM", valueFrom = "${aws_secretsmanager_secret.coord_env.arn}:BLAKTAIL_TLS_KEY_PEM::" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.coord.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "coord"
      }
    }
  }])
  tags = local.tags
}

resource "aws_cloudwatch_log_group" "coord" {
  name              = "/ecs/${var.name}/coord"
  retention_in_days = 30
  tags              = local.tags
}

resource "aws_ecs_service" "coord" {
  name            = "coord"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.coord.arn
  desired_count   = var.coord_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.coord.arn
    container_name   = "coord"
    container_port   = 8443
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  depends_on = [aws_lb_listener.coord]
  tags       = local.tags
}

resource "aws_ecs_task_definition" "relay" {
  family                   = "${var.name}-relay"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }
  container_definitions = jsonencode([{
    name         = "relay"
    image        = local.relay_image
    portMappings = [{ containerPort = 3478, protocol = "udp" }]
    environment = [
      { name = "BLAKTAIL_REGION", value = var.region },
      { name = "BLAKTAIL_RELAY_BIND", value = "0.0.0.0:3478" },
    ]
    secrets = [
      { name = "BLAKTAIL_RELAY_AUTH_SECRET", valueFrom = "${aws_secretsmanager_secret.coord_env.arn}:BLAKTAIL_RELAY_AUTH_SECRET::" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.relay.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "relay"
      }
    }
  }])
  tags = local.tags
}

resource "aws_cloudwatch_log_group" "relay" {
  name              = "/ecs/${var.name}/relay"
  retention_in_days = 30
  tags              = local.tags
}

resource "aws_ecs_service" "relay" {
  name            = "relay"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.relay.arn
  desired_count   = var.relay_min_tasks
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.relay.arn
    container_name   = "relay"
    container_port   = 3478
  }

  depends_on = [aws_lb_listener.relay]
  tags       = local.tags
}
