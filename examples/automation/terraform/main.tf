# Read-only by default. Reads a self-hosted BlakTail coordinator through the
# generic `http` provider. Set manage_posture_check = true (and give the
# client policy:write) to let Terraform own one posture check through the
# generic `restapi` provider. No tokens or ids are stored in this directory;
# keep terraform.tfstate out of git (it can contain response bodies).

terraform {
  required_version = ">= 1.6"
  required_providers {
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
    restapi = {
      source  = "Mastercard/restapi"
      version = "~> 1.20"
    }
  }
}

variable "coordinator_url" {
  description = "Your coordinator, e.g. https://coord.example.org.au"
  type        = string
}

variable "organisation_id" {
  type = string
}

variable "access_token" {
  description = "A bto_ access token from POST /oauth/token (or a bta_ secret). Pass via TF_VAR_access_token."
  type        = string
  sensitive   = true
}

variable "manage_posture_check" {
  description = "Opt in to writes. Needs the policy:write scope."
  type        = bool
  default     = false
}

variable "posture_min_agent_version" {
  type    = string
  default = "0.2.0"
}

variable "posture_version" {
  description = "Current version of the check, for updates (PUT returns 412 if stale). Read it from output.posture_checks."
  type        = number
  default     = 1
}

locals {
  headers = {
    Authorization             = "Bearer ${var.access_token}"
    "X-BlakTail-Organisation" = var.organisation_id
    Accept                    = "application/json"
  }
}

data "http" "posture_checks" {
  url             = "${var.coordinator_url}/api/v1/posture-checks"
  request_headers = local.headers
  lifecycle {
    postcondition {
      condition     = self.status_code == 200
      error_message = "Listing posture checks failed (needs devices:read)."
    }
  }
}

data "http" "join_keys" {
  url             = "${var.coordinator_url}/api/v1/keys"
  request_headers = local.headers
  lifecycle {
    postcondition {
      condition     = self.status_code == 200
      error_message = "Listing join keys failed (needs keys:read)."
    }
  }
}

data "http" "audit_chain" {
  url             = "${var.coordinator_url}/api/v1/audit/verify"
  request_headers = local.headers
  lifecycle {
    postcondition {
      condition     = self.status_code == 200
      error_message = "Audit verify failed (needs audit:read)."
    }
  }
}

output "posture_checks" {
  value = [
    for check in jsondecode(data.http.posture_checks.response_body).data :
    { id = check.id, name = check.name, version = check.version, referenced_by = check.referenced_by }
  ]
}

output "active_join_keys" {
  value = [
    for key in jsondecode(data.http.join_keys.response_body).data :
    { id = key.id, name = key.name, expires_at = key.expires_at } if key.state == "active"
  ]
}

output "audit_chain_intact" {
  value = jsondecode(data.http.audit_chain.response_body).data.intact
}

# --- Optional write: one posture check owned by Terraform -------------------

provider "restapi" {
  uri                  = var.coordinator_url
  headers              = local.headers
  write_returns_object = true
  # The API wraps objects in {"data": …}; ids come from data/id.
  id_attribute = "data/id"
}

resource "restapi_object" "baseline_posture" {
  count = var.manage_posture_check ? 1 : 0

  path          = "/api/v1/posture-checks"
  update_path   = "/api/v1/posture-checks/{id}"
  destroy_path  = "/api/v1/posture-checks/{id}"
  update_method = "PUT"

  data = jsonencode({
    name       = "baseline"
    definition = { min_agent_version = var.posture_min_agent_version }
  })
  # PUT takes {version, definition}; a stale version is refused with 412.
  update_data = jsonencode({
    version    = var.posture_version
    definition = { min_agent_version = var.posture_min_agent_version }
  })

  # There is no single-object GET; read back by searching the list.
  read_path = "/api/v1/posture-checks"
  read_search = {
    search_key   = "id"
    search_value = "{id}"
    results_key  = "data"
  }
}
