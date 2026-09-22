#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/common.sh"

test_root=$(mktemp -d "${TMPDIR:-/tmp}/blaktail-e2e-static.XXXXXX")
cleanup() {
  case "$test_root" in
    "${TMPDIR:-/tmp}"/blaktail-e2e-static.*) rm -rf -- "$test_root" ;;
    *) die "refusing unsafe static-test cleanup" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

valid_environment() {
  EXPECTED_AWS_ACCOUNT=123456789012
  AWS_REGION=ap-southeast-2
  RUN_ID=20260823e2e00001
  EXPIRES_AT=2099-01-01T00:00:00Z
  DOCKER_CONTEXT=m3-max
  TF_DIR=deploy/aws/e2e
  WORK_DIR=$test_root/work
  export EXPECTED_AWS_ACCOUNT AWS_REGION RUN_ID EXPIRES_AT DOCKER_CONTEXT TF_DIR WORK_DIR
}

valid_environment
validate_base_inputs

if (valid_environment; EXPECTED_AWS_ACCOUNT=123; validate_base_inputs) 2>/dev/null; then
  die "wrong account did not fail closed"
fi
if (valid_environment; AWS_REGION=us-east-1; validate_base_inputs) 2>/dev/null; then
  die "wrong region did not fail closed"
fi
if (valid_environment; RUN_ID='bad-run'; validate_base_inputs) 2>/dev/null; then
  die "invalid RunId did not fail closed"
fi
if (valid_environment; DOCKER_CONTEXT=default; validate_base_inputs) 2>/dev/null; then
  die "wrong Docker context did not fail closed"
fi
if ! (valid_environment; DOCKER_CONTEXT=homelab; validate_base_inputs); then
  die "homelab Docker context must be accepted"
fi
if (valid_environment; TF_DIR=deploy/aws; validate_base_inputs) 2>/dev/null; then
  die "wrong Terraform directory did not fail closed"
fi
if (assert_digest_ref 'example.invalid/blaktail/coord:latest') 2>/dev/null; then
  die "mutable image did not fail closed"
fi
assert_digest_ref 'example.invalid/blaktail/coord@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

sh -n "$SCRIPT_DIR"/*.sh
grep -q '^  workflow_dispatch:' "$REPO_ROOT/.github/workflows/aws-e2e.yml"
grep -q 'runs-on: \[self-hosted, linux\]' "$REPO_ROOT/.github/workflows/aws-e2e.yml"
grep -q 'id-token: write' "$REPO_ROOT/.github/workflows/aws-e2e.yml"
grep -q 'environment: aws-e2e' "$REPO_ROOT/.github/workflows/aws-e2e.yml"
grep -q 'cancel-in-progress: false' "$REPO_ROOT/.github/workflows/aws-e2e.yml"
grep -q 'if: always()' "$REPO_ROOT/.github/workflows/aws-e2e.yml"
if grep -Eq '^  (push|pull_request|schedule):' "$REPO_ROOT/.github/workflows/aws-e2e.yml"; then
  die "AWS E2E workflow must remain manual-only"
fi
grep -q 'CONFIRM_DESTROY' "$SCRIPT_DIR/destroy.sh"
grep -q 'partial destroy requires protected destroy context' "$SCRIPT_DIR/destroy.sh"
grep -q 'delete-task-definitions' "$SCRIPT_DIR/destroy.sh"
grep -q 'terraform.tfstate.backup' "$SCRIPT_DIR/destroy.sh"
grep -q 'enroll-ubuntu.url' "$SCRIPT_DIR/destroy.sh"
grep -q 'owner.cookies' "$SCRIPT_DIR/destroy.sh"
grep -q 'PublicIpAddress == null' "$SCRIPT_DIR/common.sh"
grep -q 'covers_ssh' "$SCRIPT_DIR/common.sh"
grep -q 'assignPublicIp:"DISABLED"' "$SCRIPT_DIR/migrate-console.sh"
grep -q 'coord_migration' "$SCRIPT_DIR/migrate-console.sh"
grep -q 'dump-config --service console --redacted' "$SCRIPT_DIR/migrate-console.sh"
grep -q 'config-validation.log' "$SCRIPT_DIR/collect-evidence.sh"
grep -q 'BLAKTAIL_DATABASE_BACKEND", value = "postgres"' \
  "$REPO_ROOT/deploy/aws/e2e/modules/runtime/ecs.tf"
grep -q 'BLAKTAIL_DATABASE_STORAGE", value = "network"' \
  "$REPO_ROOT/deploy/aws/e2e/modules/runtime/ecs.tf"
grep -q 'BLAKTAIL_DATABASE_URL.*valueFrom' \
  "$REPO_ROOT/deploy/aws/e2e/modules/runtime/ecs.tf"
if grep -q 'BLAKTAIL_ALLOW_UNSAFE_EFS_SQLITE' \
  "$REPO_ROOT/deploy/aws/e2e/modules/runtime/ecs.tf"; then
  die "AWS E2E coordinator must not use unsafe SQLite/EFS"
fi
grep -q 'readonlyRootFilesystem = true' \
  "$REPO_ROOT/deploy/aws/e2e/modules/runtime/ecs.tf"
grep -q 'containerName = "console-volumes", condition = "SUCCESS"' \
  "$REPO_ROOT/deploy/aws/e2e/modules/runtime/ecs.tf"
grep -q 'chown blaktail:blaktail /tmp /app/.next/cache' \
  "$REPO_ROOT/deploy/aws/e2e/modules/runtime/ecs.tf"
grep -q 'bootstrap.mjs init' "$SCRIPT_DIR/bootstrap-owner.sh"
grep -q 'bootstrap.mjs claim' "$SCRIPT_DIR/bootstrap-owner.sh"
grep -q 'supported_bootstrap:true' "$SCRIPT_DIR/bootstrap-owner.sh"
grep -q 'bun scripts/s3-get.mjs' "$SCRIPT_DIR/bootstrap-owner.sh"
if grep -q 'aws s3 cp.*CREDENTIAL_KEY' "$SCRIPT_DIR/bootstrap-owner.sh"; then
  die "owner task must not depend on the AWS CLI"
fi
grep -q 'EMAIL_PASSWORD_SIGN_UP_DISABLED' "$SCRIPT_DIR/verify-auth.sh"
grep -q '>All networks<' "$SCRIPT_DIR/verify-auth.sh"
grep -q 'owner-auth.ok' "$SCRIPT_DIR/verify-auth.sh"
grep -q 'owner-auth.ok' "$SCRIPT_DIR/collect-evidence.sh"
grep -q 'coord-ha.ok' "$SCRIPT_DIR/collect-evidence.sh"
grep -q 'ecs stop-task' "$SCRIPT_DIR/prove-coord-ha.sh"
grep -q 'failed_health_probes' "$SCRIPT_DIR/prove-coord-ha.sh"
grep -q 'restore-db-instance-from-db-snapshot' "$SCRIPT_DIR/prove-db-restore.sh"
grep -q 'temporary_resources_deleted' "$SCRIPT_DIR/prove-db-restore.sh"
grep -q 'db-restore.ok' "$SCRIPT_DIR/collect-evidence.sh"
grep -q 'scripts/aws-e2e/prove-coord-ha.sh' "$REPO_ROOT/.github/workflows/aws-e2e.yml"
grep -q 'scripts/aws-e2e/prove-db-restore.sh' "$REPO_ROOT/.github/workflows/aws-e2e.yml"
grep -q 'Refresh short-lived AWS credentials for teardown' \
  "$REPO_ROOT/.github/workflows/aws-e2e.yml"
if grep -E 'sign-up/email|INSERT INTO membership|DELETE FROM membership' \
  "$SCRIPT_DIR/bootstrap-owner.sh" "$SCRIPT_DIR/recover-owner.sh" >/dev/null; then
  die "AWS owner ceremony must use supported bootstrap CLI only"
fi
for checked_file in "$SCRIPT_DIR"/*.sh "$REPO_ROOT/.github/workflows/aws-e2e.yml"; do
  [ "$checked_file" = "$SCRIPT_DIR/static-test.sh" ] && continue
  if grep -E ':[[:space:]]*latest|:latest' "$checked_file" >/dev/null; then
    die "mutable latest image reference found: $checked_file"
  fi
done
for checked_file in "$SCRIPT_DIR"/*.sh "$REPO_ROOT/.github/workflows/aws-e2e.yml"; do
  [ "$checked_file" = "$SCRIPT_DIR/static-test.sh" ] && continue
  if grep -F 'session-ses_fd2c.md' "$checked_file" >/dev/null; then
    die "session export referenced by automation: $checked_file"
  fi
done
printf 'AWS E2E static safety checks passed\n'
