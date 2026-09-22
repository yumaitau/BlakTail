#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/common.sh"

validate_base_inputs
for command_name in aws docker git jq tar terraform; do
  require_command "$command_name"
done
assert_aws_identity
assert_stack_identity
case "$(cat "$STAGE_FILE" 2>/dev/null || true)" in
  bootstrap | prepare | activate) ;;
  *) die "bootstrap, prepare, or activate stage required" ;;
esac

require_arm64_builder

repositories=$(tf_output_json ecr_repository_urls)
registry=$(printf '%s' "$repositories" | jq -er '.console | split("/")[0]')
build_revision=$(git rev-parse --short=12 HEAD)
case "$build_revision" in
  '' | *[!0-9a-f]*) die "invalid Git build revision" ;;
esac
aws_cli ecr get-login-password | \
  docker --context "$DOCKER_CONTEXT" login --username AWS --password-stdin "$registry" >/dev/null

build_context=$(prepare_git_context)
cleanup() {
  docker --context "$DOCKER_CONTEXT" logout "$registry" >/dev/null 2>&1 || :
  case "$build_context" in
    "$WORK_DIR"/build-context.*) rm -rf -- "$build_context" ;;
    *) die "refusing unsafe build-context cleanup" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

build_one() {
  build_name=$1
  build_dockerfile=$2
  repository_url=$(printf '%s' "$repositories" | jq -er --arg key "$build_name" '.[$key]') || \
    die "missing ECR repository output: $build_name"
  repository_name=${repository_url#*/}
  build_tag=e2e-$RUN_ID-$build_revision
  docker --context "$DOCKER_CONTEXT" buildx build \
    --platform linux/arm64 --provenance=false --sbom=false --push \
    --file "$build_context/$build_dockerfile" \
    --tag "$repository_url:$build_tag" "$build_context"
  digest=$(aws_cli ecr describe-images --repository-name "$repository_name" \
    --image-ids imageTag="$build_tag" --query 'imageDetails[0].imageDigest' --output text)
  BUILT_REF=$repository_url@$digest
  assert_digest_ref "$BUILT_REF"
}

build_one console apps/console/Dockerfile
console_ref=$BUILT_REF
build_one coord deploy/docker/coord.Dockerfile
coord_ref=$BUILT_REF
build_one relay deploy/docker/relay.Dockerfile
relay_ref=$BUILT_REF
build_one coord_proxy deploy/docker/e2e-coord-proxy.Dockerfile
coord_proxy_ref=$BUILT_REF

images_tmp=$(mktemp "$WORK_DIR/images.XXXXXX")
jq -n \
  --arg console_image "$console_ref" \
  --arg coord_image "$coord_ref" \
  --arg relay_image "$relay_ref" \
  --arg coord_proxy_image "$coord_proxy_ref" \
  '{console_image: $console_image, coord_image: $coord_image,
    relay_image: $relay_image, coord_proxy_image: $coord_proxy_image}' >"$images_tmp"
mv "$images_tmp" "$IMAGES_TFVARS"
validate_image_tfvars
printf 'immutable ARM64 images ready: %s\n' "$IMAGES_TFVARS"
