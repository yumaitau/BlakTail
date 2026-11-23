variable "name" {
  description = "Resource name prefix."
  type        = string
  default     = "blaktail"
}

# The relay refuses non-Australian regions; keep the whole stack onshore.
variable "region" {
  description = "AWS region. Must be an approved Australian region (ap-southeast-2 for AWS)."
  type        = string
  default     = "ap-southeast-2"

  validation {
    condition     = contains(["ap-southeast-2"], var.region)
    error_message = "BlakTail is pinned to ap-southeast-2 (Sydney)."
  }
}

variable "coord_image" {
  description = "blaktail-coord container image (ECR URI). Empty = build repos below and push yourself."
  type        = string
  default     = ""
}

variable "relay_image" {
  description = "blaktail-relay container image (ECR URI)."
  type        = string
  default     = ""
}

variable "console_image" {
  description = "Console container image (ECR URI)."
  type        = string
  default     = ""
}

variable "coord_tls_cert_pem" {
  description = "Coord TLS certificate PEM (public cert chain presented to clients)."
  type        = string
  sensitive   = true
}

variable "coord_tls_key_pem" {
  description = "Coord TLS private key PEM."
  type        = string
  sensitive   = true
}

variable "console_acm_certificate_arn" {
  description = "ACM certificate for the console ALB HTTPS listener. Empty = HTTP-only listener (dev)."
  type        = string
  default     = ""
}

variable "better_auth_url" {
  description = "Public console base URL. Empty = http://<ALB DNS name>."
  type        = string
  default     = ""
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "db_multi_az" {
  description = "Multi-AZ RDS for production."
  type        = bool
  default     = true
}

variable "db_deletion_protection" {
  description = "Block deletion of the RDS instance. Set false only before an intentional destroy."
  type        = bool
  default     = true
}

variable "coord_desired_count" {
  description = "Coordinator replicas. Keep zero for the first apply, run the explicit migration task, then set at least two."
  type        = number
  default     = 0

  validation {
    condition     = var.coord_desired_count == 0 || (var.coord_desired_count >= 2 && var.coord_desired_count <= 6 && floor(var.coord_desired_count) == var.coord_desired_count)
    error_message = "coord_desired_count must be zero for migration or an integer from two to six."
  }
}

variable "console_min_tasks" {
  type    = number
  default = 2
}

variable "console_max_tasks" {
  type    = number
  default = 6
}

variable "relay_min_tasks" {
  description = "Relay task floor. Current in-memory registration map requires one task."
  type        = number
  default     = 1

  validation {
    condition     = var.relay_min_tasks == 1
    error_message = "blaktail-relay currently requires exactly one task; sharded relay discovery is not implemented."
  }
}

variable "relay_max_tasks" {
  description = "Relay task ceiling. Current in-memory registration map requires one task."
  type        = number
  default     = 1

  validation {
    condition     = var.relay_max_tasks == 1
    error_message = "blaktail-relay currently requires exactly one task; sharded relay discovery is not implemented."
  }
}
