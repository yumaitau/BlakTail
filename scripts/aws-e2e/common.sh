#!/bin/sh
set -eu

case $- in
  *x*) set +x ;;
esac
umask 077

die() {
  printf 'aws-e2e: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

SCRIPT_DIR=${SCRIPT_DIR:-$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)}
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
AWS_REGION=${AWS_REGION:-ap-southeast-2}
DOCKER_CONTEXT=${DOCKER_CONTEXT:-homelab}
TF_DIR=${TF_DIR:-deploy/aws/e2e}

require_remote_docker_context() {
  case "$DOCKER_CONTEXT" in
    m3-max | homelab) ;;
    *) die "DOCKER_CONTEXT must be a remote SSH builder (m3-max or homelab)" ;;
  esac
}

require_arm64_builder() {
  docker_arch=$(docker --context "$DOCKER_CONTEXT" info --format '{{.Architecture}}')
  case "$docker_arch" in
    aarch64 | arm64) return 0 ;;
    x86_64 | amd64)
      platforms=$(
        docker --context "$DOCKER_CONTEXT" buildx inspect --bootstrap 2>/dev/null \
          | awk -F': ' '/^Platforms:/ { print $2 }'
      )
      printf '%s' "$platforms" | grep -q 'linux/arm64' && return 0
      die "Docker context $DOCKER_CONTEXT cannot build linux/arm64"
      ;;
    *) die "Docker context $DOCKER_CONTEXT is unavailable or not a builder: $docker_arch" ;;
  esac
}

validate_base_inputs() {
  case ${EXPECTED_AWS_ACCOUNT:-} in
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]) ;;
    *) die "EXPECTED_AWS_ACCOUNT must be a 12-digit account ID" ;;
  esac
  [ "$AWS_REGION" = ap-southeast-2 ] || die "AWS_REGION must be ap-southeast-2"
  case ${RUN_ID:-} in
    '' | *[!a-z0-9]*) die "RUN_ID must contain lowercase letters or digits" ;;
  esac
  [ "${#RUN_ID}" -ge 6 ] && [ "${#RUN_ID}" -le 20 ] || \
    die "RUN_ID must be 6 to 20 characters"
  [ "$TF_DIR" = deploy/aws/e2e ] || die "TF_DIR must be deploy/aws/e2e"
  require_remote_docker_context

  WORK_DIR=${WORK_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/blaktail-e2e-$RUN_ID}
  case "$WORK_DIR" in
    /*) ;;
    *) die "WORK_DIR must be absolute" ;;
  esac
  [ "$WORK_DIR" != / ] || die "WORK_DIR cannot be /"
  case "$WORK_DIR" in
    "$REPO_ROOT" | "$REPO_ROOT"/*) die "WORK_DIR must be outside repository" ;;
  esac
  mkdir -p "$WORK_DIR"
  chmod 0700 "$WORK_DIR"

  TF_DIR_ABS=$REPO_ROOT/$TF_DIR
  STATE_FILE=$WORK_DIR/terraform.tfstate
  TF_DATA_DIR=$WORK_DIR/terraform-data
  CONTEXT_TFVARS=$WORK_DIR/context.tfvars.json
  IMAGES_TFVARS=$WORK_DIR/images.tfvars.json
  STAGE_FILE=$WORK_DIR/stage
  PACKAGE_DIR=$WORK_DIR/agent-packages
  export AWS_REGION AWS_DEFAULT_REGION="$AWS_REGION" TF_DATA_DIR WORK_DIR \
    TF_DIR_ABS STATE_FILE CONTEXT_TFVARS IMAGES_TFVARS STAGE_FILE PACKAGE_DIR
}

validate_expiry() {
  require_command jq
  [ -n "${EXPIRES_AT:-}" ] || die "EXPIRES_AT is required"
  expires_epoch=$(printf '%s' "$EXPIRES_AT" | jq -Rer 'fromdateiso8601' 2>/dev/null) || \
    die "EXPIRES_AT must be UTC RFC3339, for example 2026-08-23T12:00:00Z"
  now_epoch=$(date -u +%s)
  [ "$expires_epoch" -gt "$now_epoch" ] || die "EXPIRES_AT must be in future"
  [ "$expires_epoch" -le "$((now_epoch + 86400))" ] || die "EXPIRES_AT must be within 24 hours"
}

aws_cli() {
  AWS_PAGER='' aws --no-cli-pager --region "$AWS_REGION" "$@"
}

assert_aws_identity() {
  require_command aws
  actual_account=$(aws_cli sts get-caller-identity --query Account --output text)
  [ "$actual_account" = "$EXPECTED_AWS_ACCOUNT" ] || \
    die "AWS account mismatch: expected $EXPECTED_AWS_ACCOUNT, got $actual_account"
}

terraform_exec() {
  require_command terraform
  if [ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ]; then
    terraform -chdir="$TF_DIR_ABS" "$@"
    return
  fi

  require_command jq
  if [ -n "${AWS_PROFILE:-}" ]; then
    credential_json=$(AWS_PAGER='' aws --profile "$AWS_PROFILE" configure export-credentials --format process)
  else
    credential_json=$(AWS_PAGER='' aws configure export-credentials --format process)
  fi
  credential_access=$(printf '%s' "$credential_json" | jq -er .AccessKeyId)
  credential_secret=$(printf '%s' "$credential_json" | jq -er .SecretAccessKey)
  credential_token=$(printf '%s' "$credential_json" | jq -r '.SessionToken // ""')
  credential_json=
  AWS_ACCESS_KEY_ID=$credential_access \
    AWS_SECRET_ACCESS_KEY=$credential_secret \
    AWS_SESSION_TOKEN=$credential_token \
    terraform -chdir="$TF_DIR_ABS" "$@"
  credential_access=
  credential_secret=
  credential_token=
}

write_context_tfvars() {
  bootstrap_only=$1
  deploy_services=$2
  console_desired_count=$3
  context_tmp=$(mktemp "$WORK_DIR/context.XXXXXX")
  jq -n \
    --arg expected_aws_account "$EXPECTED_AWS_ACCOUNT" \
    --arg region "$AWS_REGION" \
    --arg run_id "$RUN_ID" \
    --arg expires_at "$EXPIRES_AT" \
    --argjson bootstrap_only "$bootstrap_only" \
    --argjson deploy_services "$deploy_services" \
    --argjson console_desired_count "$console_desired_count" \
    '{expected_aws_account: $expected_aws_account, region: $region, run_id: $run_id,
      expires_at: $expires_at, bootstrap_only: $bootstrap_only,
      deploy_services: $deploy_services, console_desired_count: $console_desired_count}' \
    >"$context_tmp"
  mv "$context_tmp" "$CONTEXT_TFVARS"
}

tf_output_json() {
  [ -f "$STATE_FILE" ] || die "Terraform state missing: $STATE_FILE"
  terraform_exec output -state="$STATE_FILE" -json "$1"
}

tf_output_raw() {
  [ -f "$STATE_FILE" ] || die "Terraform state missing: $STATE_FILE"
  terraform_exec output -state="$STATE_FILE" -raw "$1"
}

assert_stack_identity() {
  state_run_id=$(tf_output_raw run_id)
  state_region=$(tf_output_raw region)
  state_prefix=$(tf_output_raw name_prefix)
  [ "$state_run_id" = "$RUN_ID" ] || die "Terraform RunId mismatch"
  [ "$state_region" = "$AWS_REGION" ] || die "Terraform region mismatch"
  [ "$state_prefix" = "blaktail-e2e-$RUN_ID" ] || die "Terraform name prefix mismatch"
}

assert_digest_ref() {
  image_ref=$1
  case "$image_ref" in
    *@sha256:*) ;;
    *) die "mutable or invalid image reference rejected: $image_ref" ;;
  esac
  image_name=${image_ref%@sha256:*}
  image_leaf=${image_name##*/}
  case "$image_leaf" in
    *:*) die "image reference must not include a mutable tag: $image_ref" ;;
  esac
  image_digest=${image_ref##*@sha256:}
  [ "${#image_digest}" -eq 64 ] || die "invalid image digest: $image_ref"
  case "$image_digest" in
    *[!0-9a-f]*) die "invalid image digest: $image_ref" ;;
  esac
}

validate_image_tfvars() {
  require_command jq
  [ -f "$IMAGES_TFVARS" ] || die "image tfvars missing: $IMAGES_TFVARS"
  for image_key in console_image coord_image relay_image coord_proxy_image; do
    image_value=$(jq -er --arg key "$image_key" '.[$key]' "$IMAGES_TFVARS") || \
      die "$image_key missing from image tfvars"
    assert_digest_ref "$image_value"
  done
}

require_resource_tag() {
  resource_arn=$1
  resource_run_id=$(aws_cli resourcegroupstaggingapi get-resources \
    --resource-arn-list "$resource_arn" \
    --query 'ResourceTagMappingList[0].Tags[?Key==`RunId`].Value | [0]' \
    --output text)
  [ "$resource_run_id" = "$RUN_ID" ] || die "resource RunId mismatch: $resource_arn"
}

assert_network_guards() {
  require_command jq
  instance_id_json=$(tf_output_json agent_instance_ids)
  [ "$(printf '%s' "$instance_id_json" | jq '[.ubuntu, .al2023] | map(select(length > 0)) | length')" -eq 2 ] || \
    die "expected exactly two agent instances"
  instance_ids=$(printf '%s' "$instance_id_json" | jq -r '.ubuntu, .al2023')
  instance_json=$(aws_cli ec2 describe-instances --instance-ids $instance_ids --output json)
  printf '%s' "$instance_json" | jq -e --arg run_id "$RUN_ID" '
    [.Reservations[].Instances[]] | length == 2 and
    all(.[]; .PublicIpAddress == null and
      any(.Tags[]?; .Key == "RunId" and .Value == $run_id))
  ' >/dev/null || die "agent has public IP or wrong RunId tag"

  agent_security_group_ids=$(printf '%s' "$instance_json" | \
    jq -r '.Reservations[].Instances[].SecurityGroups[].GroupId' | sort -u)
  [ -n "$agent_security_group_ids" ] || die "agent security groups missing"
  agent_security_group_json=$(aws_cli ec2 describe-security-groups \
    --group-ids $agent_security_group_ids --output json)
  printf '%s' "$agent_security_group_json" | jq -e '
    def covers_ssh:
      .IpProtocol == "-1" or
      (.IpProtocol == "tcp" and (.FromPort // 0) <= 22 and (.ToPort // 65535) >= 22);
    all(.SecurityGroups[].IpPermissions[]?; (covers_ssh | not))
  ' >/dev/null || die "agent security group has inbound SSH"

  security_group_id=$(tf_output_raw tasks_security_group_id)
  security_group_json=$(aws_cli ec2 describe-security-groups --group-ids "$security_group_id" --output json)
  printf '%s' "$security_group_json" | jq -e --arg run_id "$RUN_ID" '
    def covers_ssh:
      .IpProtocol == "-1" or
      (.IpProtocol == "tcp" and (.FromPort // 0) <= 22 and (.ToPort // 65535) >= 22);
    (.SecurityGroups | length == 1) and
    all(.SecurityGroups[]; any(.Tags[]?; .Key == "RunId" and .Value == $run_id)) and
    all(.SecurityGroups[].IpPermissions[]?; (covers_ssh | not))
  ' >/dev/null || die "tasks security group has inbound SSH or wrong RunId tag"
}

prepare_git_context() {
  require_command git
  require_command tar
  build_context=$(mktemp -d "$WORK_DIR/build-context.XXXXXX")
  git -C "$REPO_ROOT" archive --format=tar HEAD | tar -xf - -C "$build_context"
  for overlay in \
    deploy/docker/agent-package.Dockerfile \
    deploy/docker/e2e-coord-proxy.Dockerfile \
    deploy/docker/e2e-coord-proxy.Caddyfile; do
    [ -f "$REPO_ROOT/$overlay" ] || continue
    mkdir -p "$build_context/$(dirname -- "$overlay")"
    cp "$REPO_ROOT/$overlay" "$build_context/$overlay"
  done
  printf '%s\n' "$build_context"
}

wait_ssm_command() {
  command_id=$1
  instance_id=$2
  ssm_command_timeout=${SSM_COMMAND_TIMEOUT:-900}
  case "$ssm_command_timeout" in '' | *[!0-9]*) die "SSM_COMMAND_TIMEOUT must be seconds" ;; esac
  [ "$ssm_command_timeout" -ge 60 ] && [ "$ssm_command_timeout" -le 900 ] || \
    die "SSM_COMMAND_TIMEOUT must be between 60 and 900 seconds"
  command_deadline=$(( $(date -u +%s) + ssm_command_timeout ))
  while [ "$(date -u +%s)" -lt "$command_deadline" ]; do
    command_status=$(aws_cli ssm get-command-invocation \
      --command-id "$command_id" --instance-id "$instance_id" \
      --query Status --output text 2>/dev/null || printf Pending)
    case "$command_status" in
      Success) return 0 ;;
      Pending | InProgress | Delayed) sleep 5 ;;
      *) die "SSM command failed for $instance_id: $command_status" ;;
    esac
  done
  die "SSM command timed out for $instance_id after $ssm_command_timeout seconds"
}

ssm_send_script() {
  instance_id=$1
  command_comment=$2
  remote_script=$3
  parameter_file=$(mktemp "$WORK_DIR/ssm-parameters.XXXXXX")
  jq -n --arg command "$remote_script" '{commands: [$command]}' >"$parameter_file"
  if ! SSM_COMMAND_ID=$(aws_cli ssm send-command \
    --instance-ids "$instance_id" \
    --document-name AWS-RunShellScript \
    --comment "$command_comment" \
    --timeout-seconds 900 \
    --parameters "file://$parameter_file" \
    --query 'Command.CommandId' --output text); then
    rm -f -- "$parameter_file"
    die "could not send SSM command to $instance_id"
  fi
  rm -f -- "$parameter_file"
  case "$SSM_COMMAND_ID" in
    ????????-????-????-????-????????????) ;;
    *) die "invalid SSM command ID returned" ;;
  esac
}

ssm_command_output() {
  aws_cli ssm get-command-invocation \
    --command-id "$1" --instance-id "$2" \
    --query StandardOutputContent --output text
}

assert_ssm_online() {
  instance_id=$1
  ssm_online_timeout=${SSM_ONLINE_TIMEOUT:-600}
  case "$ssm_online_timeout" in '' | *[!0-9]*) die "SSM_ONLINE_TIMEOUT must be seconds" ;; esac
  [ "$ssm_online_timeout" -ge 60 ] && [ "$ssm_online_timeout" -le 1200 ] || \
    die "SSM_ONLINE_TIMEOUT must be between 60 and 1200 seconds"
  ssm_deadline=$(( $(date -u +%s) + ssm_online_timeout ))
  while [ "$(date -u +%s)" -lt "$ssm_deadline" ]; do
    ssm_status=$(aws_cli ssm describe-instance-information \
      --filters "Key=InstanceIds,Values=$instance_id" \
      --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || printf None)
    [ "$ssm_status" = Online ] && return
    sleep 10
  done
  die "SSM instance is not online: $instance_id"
}
