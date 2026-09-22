#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/common.sh"

validate_base_inputs
validate_expiry
for command_name in aws docker git jq tar terraform; do
  require_command "$command_name"
done
[ -d "$TF_DIR_ABS" ] || die "Terraform directory missing: $TF_DIR_ABS"
assert_aws_identity

require_arm64_builder

terraform_exec version >/dev/null
printf 'preflight ok: account=%s region=%s run_id=%s docker=%s\n' \
  "$EXPECTED_AWS_ACCOUNT" "$AWS_REGION" "$RUN_ID" "$DOCKER_CONTEXT"

