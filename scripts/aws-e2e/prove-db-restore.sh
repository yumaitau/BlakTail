#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/common.sh"

validate_base_inputs
validate_expiry
for command_name in aws jq terraform; do
  require_command "$command_name"
done
assert_aws_identity
assert_stack_identity
assert_network_guards
[ "$(cat "$STAGE_FILE" 2>/dev/null || true)" = activate ] || die "activated stack required"
[ -s "$WORK_DIR/coord-ha.ok" ] || die "coordinator HA proof required before restore drill"

name_prefix=$(tf_output_raw name_prefix)
cluster_name=$(tf_output_raw cluster_name)
source_db=$name_prefix
snapshot_id=$name_prefix-restore-proof
restore_db=$name_prefix-restore
restore_task_arn=
cleanup_pending=true

cleanup_restore_resources() {
  if [ -n "$restore_task_arn" ]; then
    task_status=$(aws_cli ecs describe-tasks --cluster "$cluster_name" --tasks "$restore_task_arn" \
      --query 'tasks[0].lastStatus' --output text 2>/dev/null || printf None)
    if [ "$task_status" != STOPPED ] && [ "$task_status" != None ]; then
      aws_cli ecs stop-task --cluster "$cluster_name" --task "$restore_task_arn" \
        --reason "BlakTail E2E restore proof cleanup $RUN_ID" >/dev/null 2>&1 || true
      aws_cli ecs wait tasks-stopped --cluster "$cluster_name" \
        --tasks "$restore_task_arn" >/dev/null 2>&1 || true
    fi
  fi

  if aws_cli rds describe-db-instances --db-instance-identifier "$restore_db" \
    >/dev/null 2>&1; then
    restore_status=$(aws_cli rds describe-db-instances --db-instance-identifier "$restore_db" \
      --query 'DBInstances[0].DBInstanceStatus' --output text 2>/dev/null || printf unknown)
    case "$restore_status" in
      available) ;;
      deleting) ;;
      *) aws_cli rds wait db-instance-available --db-instance-identifier "$restore_db" \
        >/dev/null 2>&1 || true ;;
    esac
    if aws_cli rds describe-db-instances --db-instance-identifier "$restore_db" \
      >/dev/null 2>&1; then
      restore_status=$(aws_cli rds describe-db-instances --db-instance-identifier "$restore_db" \
        --query 'DBInstances[0].DBInstanceStatus' --output text 2>/dev/null || printf unknown)
      if [ "$restore_status" != deleting ]; then
        aws_cli rds delete-db-instance --db-instance-identifier "$restore_db" \
          --skip-final-snapshot --delete-automated-backups >/dev/null 2>&1 || true
      fi
      aws_cli rds wait db-instance-deleted --db-instance-identifier "$restore_db" \
        >/dev/null 2>&1 || true
    fi
  fi

  if aws_cli rds describe-db-snapshots --db-snapshot-identifier "$snapshot_id" \
    >/dev/null 2>&1; then
    snapshot_status=$(aws_cli rds describe-db-snapshots --db-snapshot-identifier "$snapshot_id" \
      --query 'DBSnapshots[0].Status' --output text 2>/dev/null || printf unknown)
    case "$snapshot_status" in
      available) ;;
      deleting) ;;
      *) aws_cli rds wait db-snapshot-completed --db-snapshot-identifier "$snapshot_id" \
        >/dev/null 2>&1 || true ;;
    esac
    if aws_cli rds describe-db-snapshots --db-snapshot-identifier "$snapshot_id" \
      >/dev/null 2>&1; then
      snapshot_status=$(aws_cli rds describe-db-snapshots --db-snapshot-identifier "$snapshot_id" \
        --query 'DBSnapshots[0].Status' --output text 2>/dev/null || printf unknown)
      if [ "$snapshot_status" != deleting ]; then
        aws_cli rds delete-db-snapshot --db-snapshot-identifier "$snapshot_id" \
          >/dev/null 2>&1 || true
      fi
      aws_cli rds wait db-snapshot-deleted --db-snapshot-identifier "$snapshot_id" \
        >/dev/null 2>&1 || true
    fi
  fi
}

cleanup_on_exit() {
  exit_status=$?
  trap - EXIT HUP INT TERM
  set +e
  if [ "$cleanup_pending" = true ]; then
    cleanup_restore_resources
  fi
  exit "$exit_status"
}
trap cleanup_on_exit EXIT HUP INT TERM

if aws_cli rds describe-db-snapshots --db-snapshot-identifier "$snapshot_id" \
  >/dev/null 2>&1; then
  die "restore proof snapshot already exists: $snapshot_id"
fi
if aws_cli rds describe-db-instances --db-instance-identifier "$restore_db" \
  >/dev/null 2>&1; then
  die "restore proof instance already exists: $restore_db"
fi

source_json=$(aws_cli rds describe-db-instances --db-instance-identifier "$source_db" --output json)
printf '%s' "$source_json" | jq -e '
  (.DBInstances | length == 1) and
  (.DBInstances[0].DBInstanceStatus == "available") and
  (.DBInstances[0].Engine == "postgres") and
  (.DBInstances[0].StorageEncrypted == true) and
  (.DBInstances[0].MultiAZ == true) and
  (.DBInstances[0].PubliclyAccessible == false) and
  (.DBInstances[0].BackupRetentionPeriod >= 1)
' >/dev/null || die "source database is not an available encrypted private Multi-AZ Postgres instance"
source_arn=$(printf '%s' "$source_json" | jq -er '.DBInstances[0].DBInstanceArn')
source_tags=$(aws_cli rds list-tags-for-resource --resource-name "$source_arn" --output json)
printf '%s' "$source_tags" | jq -e --arg run_id "$RUN_ID" '
  any(.TagList[]?; .Key == "RunId" and .Value == $run_id)
' >/dev/null || die "source database RunId tag mismatch"
db_subnet_group=$(printf '%s' "$source_json" | jq -er '.DBInstances[0].DBSubnetGroup.DBSubnetGroupName')
db_security_groups=$(printf '%s' "$source_json" | \
  jq -er '.DBInstances[0].VpcSecurityGroups | if length > 0 then .[].VpcSecurityGroupId else error("missing") end')

aws_cli rds create-db-snapshot \
  --db-instance-identifier "$source_db" \
  --db-snapshot-identifier "$snapshot_id" \
  --tags \
    "Key=RunId,Value=$RUN_ID" \
    "Key=ExpiresAt,Value=$EXPIRES_AT" \
    "Key=Owner,Value=blaktail-e2e" \
    "Key=Purpose,Value=end-to-end-test" >/dev/null
aws_cli rds wait db-snapshot-completed --db-snapshot-identifier "$snapshot_id"
snapshot_json=$(aws_cli rds describe-db-snapshots --db-snapshot-identifier "$snapshot_id" --output json)
printf '%s' "$snapshot_json" | jq -e '
  (.DBSnapshots | length == 1) and (.DBSnapshots[0].Status == "available") and
  (.DBSnapshots[0].Encrypted == true) and (.DBSnapshots[0].Engine == "postgres")
' >/dev/null || die "encrypted Postgres snapshot proof failed"

aws_cli rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier "$restore_db" \
  --db-snapshot-identifier "$snapshot_id" \
  --db-instance-class db.t4g.micro \
  --db-subnet-group-name "$db_subnet_group" \
  --vpc-security-group-ids $db_security_groups \
  --no-multi-az \
  --no-publicly-accessible \
  --no-deletion-protection \
  --tags \
    "Key=RunId,Value=$RUN_ID" \
    "Key=ExpiresAt,Value=$EXPIRES_AT" \
    "Key=Owner,Value=blaktail-e2e" \
    "Key=Purpose,Value=backup-restore-proof" >/dev/null
aws_cli rds wait db-instance-available --db-instance-identifier "$restore_db"
restore_json=$(aws_cli rds describe-db-instances --db-instance-identifier "$restore_db" --output json)
printf '%s' "$restore_json" | jq -e '
  (.DBInstances | length == 1) and
  (.DBInstances[0].DBInstanceStatus == "available") and
  (.DBInstances[0].StorageEncrypted == true) and
  (.DBInstances[0].PubliclyAccessible == false)
' >/dev/null || die "restored database is not available, encrypted, and private"
restore_endpoint=$(printf '%s' "$restore_json" | jq -er '.DBInstances[0].Endpoint | "\(.Address):\(.Port)"')
restore_arn=$(printf '%s' "$restore_json" | jq -er '.DBInstances[0].DBInstanceArn')
restore_tags=$(aws_cli rds list-tags-for-resource --resource-name "$restore_arn" --output json)
printf '%s' "$restore_tags" | jq -e --arg run_id "$RUN_ID" '
  any(.TagList[]?; .Key == "RunId" and .Value == $run_id)
' >/dev/null || die "restored database RunId tag mismatch"

task_definitions=$(tf_output_json task_definition_arns)
console_task_definition=$(printf '%s' "$task_definitions" | jq -er .console)
security_group_id=$(tf_output_raw tasks_security_group_id)
subnet_json=$(tf_output_json private_subnet_ids | jq -c '.fargate')
network_configuration=$(jq -cn \
  --argjson subnets "$subnet_json" --arg security_group "$security_group_id" \
  '{awsvpcConfiguration:{subnets:$subnets,securityGroups:[$security_group],assignPublicIp:"DISABLED"}}')
restore_marker=restore-proof:$RUN_ID
restore_code='import { SQL } from "bun";
const restoredUrl = new URL(process.env.DATABASE_URL);
restoredUrl.host = process.env.RESTORE_ENDPOINT;
const marker = process.env.RESTORE_MARKER;
const sql = new SQL(restoredUrl.toString(), { max: 1, prepare: false });
try {
  const [{ value: coordSchemaVersion }] = await sql`SELECT COALESCE(MAX(version), 0)::int AS value FROM coordinator_schema_migrations`;
  const [{ value: coordNodes }] = await sql`SELECT count(*)::int AS value FROM nodes`;
  const [{ value: consoleUsers }] = await sql`SELECT count(*)::int AS value FROM public."user"`;
  const [{ value: consoleMemberships }] = await sql`SELECT count(*)::int AS value FROM membership`;
  console.log(`${marker}:coord_schema_version=${coordSchemaVersion}`);
  console.log(`${marker}:coord_nodes=${coordNodes}`);
  console.log(`${marker}:console_users=${consoleUsers}`);
  console.log(`${marker}:console_memberships=${consoleMemberships}`);
} finally {
  await sql.close({ timeout: 5 });
}'
overrides=$(jq -cn \
  --arg code "$restore_code" \
  --arg endpoint "$restore_endpoint" \
  --arg marker "$restore_marker" \
  '{containerOverrides:[{name:"console",command:["bun","-e",$code],environment:[
    {name:"RESTORE_ENDPOINT",value:$endpoint},{name:"RESTORE_MARKER",value:$marker}
  ]}]}')
log_start_ms=$(( $(date -u +%s) * 1000 ))
restore_task_arn=$(aws_cli ecs run-task --cluster "$cluster_name" --launch-type FARGATE \
  --task-definition "$console_task_definition" --network-configuration "$network_configuration" \
  --overrides "$overrides" --started-by "$RUN_ID" \
  --tags key=RunId,value="$RUN_ID" --query 'tasks[0].taskArn' --output text)
case "$restore_task_arn" in arn:aws:ecs:*) ;; *) die "restore validation task did not start" ;; esac
aws_cli ecs wait tasks-stopped --cluster "$cluster_name" --tasks "$restore_task_arn"
restore_task_json=$(aws_cli ecs describe-tasks --cluster "$cluster_name" \
  --tasks "$restore_task_arn" --output json)
printf '%s' "$restore_task_json" | jq -e '
  (.tasks | length == 1) and (.tasks[0].stopCode == "EssentialContainerExited") and
  any(.tasks[0].containers[]; .name == "console" and .exitCode == 0)
' >/dev/null || die "restored database validation task failed"

restore_logs=
log_attempt=0
while [ "$log_attempt" -lt 12 ]; do
  log_attempt=$((log_attempt + 1))
  restore_logs=$(aws_cli logs filter-log-events \
    --log-group-name "/ecs/$name_prefix/console" \
    --start-time "$log_start_ms" \
    --filter-pattern "\"$restore_marker\"" --output json)
  if printf '%s' "$restore_logs" | jq -e --arg marker "$restore_marker:" '
    [.events[].message | select(startswith($marker))] | length >= 4
  ' >/dev/null; then
    break
  fi
  sleep 5
done
restore_values=$(printf '%s' "$restore_logs" | jq -e \
  --arg schema "$restore_marker:coord_schema_version=" \
  --arg nodes "$restore_marker:coord_nodes=" \
  --arg users "$restore_marker:console_users=" \
  --arg memberships "$restore_marker:console_memberships=" '
  def last_number($prefix):
    [.events[].message | select(startswith($prefix)) | ltrimstr($prefix) | tonumber] | last;
  {coord_schema_version:last_number($schema), coord_nodes:last_number($nodes),
   console_users:last_number($users), console_memberships:last_number($memberships)}
') || die "restore validation log evidence missing"
printf '%s' "$restore_values" | jq -e '
  .coord_schema_version == 5 and .coord_nodes == 2 and
  .console_users == 1 and .console_memberships == 1
' >/dev/null || die "restored database row and schema checks failed"

cleanup_restore_resources
if aws_cli rds describe-db-instances --db-instance-identifier "$restore_db" \
  >/dev/null 2>&1; then
  die "restored database cleanup failed"
fi
if aws_cli rds describe-db-snapshots --db-snapshot-identifier "$snapshot_id" \
  >/dev/null 2>&1; then
  die "restore proof snapshot cleanup failed"
fi
cleanup_pending=false

proof_tmp=$(mktemp "$WORK_DIR/db-restore.XXXXXX")
printf '%s' "$restore_values" | jq \
  --arg run_id "$RUN_ID" \
  --arg snapshot_id "$snapshot_id" \
  --arg restore_db "$restore_db" \
  '. + {run_id:$run_id, snapshot_id:$snapshot_id, restored_instance:$restore_db,
    encrypted:true, publicly_accessible:false, temporary_resources_deleted:true}' \
  >"$proof_tmp"
mv "$proof_tmp" "$WORK_DIR/db-restore.ok"
chmod 0600 "$WORK_DIR/db-restore.ok"
printf 'database snapshot restore complete: schema 5, two nodes, identity data, temporary restore deleted\n'
