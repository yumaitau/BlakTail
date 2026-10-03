# Automation examples

Copyable `/api/v1` walkthroughs against **your own** self-hosted coordinator.
Nothing here contains a real token, organisation id or state file. Use a
disposable organisation first. See [../../docs/admin-api.md](../../docs/admin-api.md)
and [../../docs/openapi/admin-v1.yaml](../../docs/openapi/admin-v1.yaml).

| File | What it does |
| --- | --- |
| [curl.md](curl.md) | Read-only tour, then opt-in writes with etags and versions |
| [terraform/](terraform/) | Read-only Terraform by default using the generic `http` provider; optional posture-check management with `Mastercard/restapi` |

## Credentials

An owner creates an automation client in Settings → Automation and picks the
fewest scopes. For the read-only examples:

- `status:read`, `devices:read`, `keys:read`, `audit:read`, `webhooks:read`

Add `policy:write` only if you enable the posture-check resource, and
`audit:export` only for exports. The `bta_` secret is shown once. Prefer
exchanging it for a one-hour `bto_` access token (`POST /oauth/token`) in
pipelines, rotate the client from Settings when people change, and suspend
it if it leaks.

```sh
export BLAKTAIL_URL=https://coord.example.org.au     # your coordinator
export BLAKTAIL_ORG=00000000-0000-0000-0000-000000000000
read -rs BLAKTAIL_CLIENT_SECRET                       # paste bta_… , not echoed
```

Never commit these values, `terraform.tfstate` or plan files: state can hold
response bodies.
