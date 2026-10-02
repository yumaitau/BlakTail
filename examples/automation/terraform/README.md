# Terraform example (generic providers)

BlakTail has no dedicated Terraform provider. This example uses
`hashicorp/http` for reads and, only when you opt in, `Mastercard/restapi`
for one posture check. It targets your self-hosted coordinator; there is no
hosted API endpoint.

```sh
cd examples/automation/terraform
export TF_VAR_coordinator_url=https://coord.example.org.au
export TF_VAR_organisation_id=00000000-0000-0000-0000-000000000000
read -rs TF_VAR_access_token && export TF_VAR_access_token   # bto_… or bta_…
terraform init
terraform plan          # read-only: three GETs, no resources
terraform apply         # prints posture checks, active join keys, audit chain status
```

Writes (disposable organisation first, client needs `policy:write`):

```sh
terraform apply -var manage_posture_check=true
# change the requirement: pass the version you read from output.posture_checks
terraform apply -var manage_posture_check=true -var posture_min_agent_version=0.3.0 -var posture_version=1
terraform destroy -var manage_posture_check=true   # 409 while a policy rule references it
```

Import an existing check: `terraform import 'restapi_object.baseline_posture[0]' <check id>`.

Limits, stated plainly:

- Updates use optimistic concurrency. Terraform does not track the check's
  `version`, so you pass it; a stale value fails with `412` instead of
  overwriting someone else's change.
- Drift in fields Terraform does not send (for example `description` edited
  in the console) is not detected.
- `terraform validate` passes against the pinned providers, but the example
  has not been applied against a live coordinator in CI; the API
  behaviour it relies on is covered by coordinator tests.
- State files can include response bodies; keep them out of git and in your
  own onshore backend.
