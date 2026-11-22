resource "aws_lb" "console" {
  name               = "${var.name}-console"
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = data.aws_subnets.default.ids
  tags               = local.tags
}

resource "aws_lb_target_group" "console" {
  name                 = "${var.name}-console"
  port                 = 3000
  protocol             = "HTTP"
  vpc_id               = data.aws_vpc.default.id
  target_type          = "ip"
  deregistration_delay = 30

  health_check {
    path                = "/sign-in"
    matcher             = "200-399"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = local.tags
}

resource "aws_lb_listener" "console_http" {
  load_balancer_arn = aws_lb.console.arn
  port              = 80
  protocol          = "HTTP"

  # With a certificate, plain HTTP only redirects to HTTPS so session cookies
  # and sign-in forms never cross the network in clear text. Without one
  # (dev), it forwards as before.
  dynamic "default_action" {
    for_each = var.console_acm_certificate_arn == "" ? [] : [1]
    content {
      type = "redirect"

      redirect {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }

  dynamic "default_action" {
    for_each = var.console_acm_certificate_arn == "" ? [1] : []
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.console.arn
    }
  }
}

resource "aws_lb_listener" "console_https" {
  count             = var.console_acm_certificate_arn == "" ? 0 : 1
  load_balancer_arn = aws_lb.console.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.console_acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.console.arn
  }
}

# Coord: TCP pass-through so the binary keeps terminating TLS itself.
resource "aws_lb" "coord" {
  name               = "${var.name}-coord"
  load_balancer_type = "network"
  subnets            = data.aws_subnets.default.ids
  tags               = local.tags
}

resource "aws_lb_target_group" "coord" {
  name        = "${var.name}-coord"
  port        = 8443
  protocol    = "TCP"
  vpc_id      = data.aws_vpc.default.id
  target_type = "ip"

  health_check {
    protocol            = "TCP"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = local.tags
}

resource "aws_lb_listener" "coord" {
  load_balancer_arn = aws_lb.coord.arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.coord.arn
  }
}

# Relay: plain UDP datagram balancing; stateless, scale freely.
resource "aws_lb" "relay" {
  name               = "${var.name}-relay"
  load_balancer_type = "network"
  subnets            = data.aws_subnets.default.ids
  tags               = local.tags
}

resource "aws_lb_target_group" "relay" {
  name        = "${var.name}-relay"
  port        = 3478
  protocol    = "UDP"
  vpc_id      = data.aws_vpc.default.id
  target_type = "ip"

  health_check {
    enabled = false
  }

  tags = local.tags
}

resource "aws_lb_listener" "relay" {
  load_balancer_arn = aws_lb.relay.arn
  port              = 3478
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.relay.arn
  }
}
