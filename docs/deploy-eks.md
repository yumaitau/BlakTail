# Deploy the control plane to EKS (Auto Mode)

Manifests in [`deploy/eks/`](../deploy/eks) run the console, coordinator and relay
on an existing EKS Auto Mode cluster in Sydney (`ap-southeast-2`). The first
production deployment is `yumait-prod`:

| Name | Purpose | Path |
| --- | --- | --- |
| `console.blaktail.yumait.au` | Operator console | ALB, HTTPS (ACM) → console pods |
| `coord.blaktail.yumait.au` | Coordinator API for agents | ALB, HTTPS (ACM) → coordinator pods (re-encrypted with an internal CA) |
| `relay.blaktail.yumait.au:3478/udp` | Encrypted UDP relay | NLB → relay pod |
| `relay-wss.blaktail.yumait.au` | WebSocket-over-443 relay fallback | ALB, HTTPS (ACM) → relay pod |

TLS ends on the ALB in Sydney with an ACM certificate, and the Cloudflare DNS
records are **DNS-only** (not proxied), so traffic is never decrypted outside
Australia. Don't turn on Cloudflare proxying for these names.

## What lives where

- **Images:** ECR `blaktail/{console,coord,relay}`, tagged with the git commit
  (built `linux/arm64`; pods run on the Graviton node pool, on-demand only).
- **Database:** private RDS PostgreSQL 16 `blaktail-eks-postgres` (encrypted,
  7-day backups, deletion protection) with separate `blaktail_console` and
  `blaktail_coord` databases owned by least-privilege roles.
- **Secrets:** AWS Secrets Manager, synced by External Secrets:
  `blaktail-eks-runtime` (app secrets and database URLs),
  `blaktail-eks-db-admin` (used only by the `blaktail-db-init` Job),
  `blaktail-eks-internal-ca` (internal CA for coordinator TLS; renew the
  `blaktail-coord-tls` Kubernetes secret from it before it expires in 825 days),
  `blaktail-eks-owner-password` (first owner's initial password).

## Deploy or upgrade

```sh
C=arn:aws:eks:ap-southeast-2:<account>:cluster/<cluster>
TAG=$(git rev-parse --short=12 HEAD)
# Build arm64 images and push to ECR, then set the tag in kustomization.yaml.
kubectl --context $C apply -f deploy/eks/namespace.yaml
kubectl --context $C apply -f deploy/eks/secrets.yaml -f deploy/eks/config.yaml
kubectl --context $C apply -f deploy/eks/db-init.yaml          # first deploy only
# Migrations run as Jobs; delete completed ones before re-running on upgrade.
kubectl --context $C -n blaktail delete job blaktail-coord-migrate blaktail-console-migrate --ignore-not-found
kubectl --context $C apply -k deploy/eks
```

First deploy only: create the first owner with `deploy/eks/bootstrap-owner.yaml`
(fill in the placeholders; it reads the password from Secrets Manager, copies it
to a mode-0600 file and deletes it afterwards). Then delete the Job and the
`blaktail-owner-password` ExternalSecret. The owner should change the password
after first sign-in; the Secrets Manager secret can then be deleted.

## Cluster gotchas found during the first deploy

- **EBS encryption key.** The account's default EBS encryption key is a
  customer-managed key that EKS Auto Mode can't use, so nodes from the built-in
  `default` NodeClass fail to launch (`Client.InvalidKMSKey.InvalidState`).
  Auto Mode reverts edits to its built-in NodeClass, so the `graviton` NodePool
  now uses a custom NodeClass, `aws-ebs`, that pins the AWS-managed `aws/ebs`
  key (as the `boomerang` NodeClass already does). A custom `general-aws-ebs`
  NodePool (same amd64 c/m/r on-demand requirements as the built-in
  `general-purpose` pool, weight 50) on that NodeClass gives other workloads
  somewhere to land; the built-in pools still can't launch until the account
  default key is usable by EKS Auto Mode.
- **Load balancer tags.** Don't add `alb.ingress.kubernetes.io/tags` or other
  custom tags: Auto Mode's managed load-balancing policy only allows its own tag
  keys when creating listener rules, so extra tags make `CreateRule` fail.
- **UDP health checks.** The relay NLB health-checks TCP 9702 (the relay's
  metrics listener, token-protected) because UDP has no health check.
