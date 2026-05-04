#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${AWS_PROFILE:-}" && -n "${AWS_PROFILE_FALLBACK:-}" ]]; then
  export AWS_PROFILE="${AWS_PROFILE_FALLBACK}"
fi

active_slot="${ACTIVE_SLOT:?ACTIVE_SLOT is required}"
current_live_slot="${CURRENT_LIVE_SLOT:-unknown}"
desired_count="${DESIRED_COUNT:?DESIRED_COUNT is required}"
max_count="${MAX_COUNT:-${desired_count}}"
blue_asg="${BLUE_ASG_NAME:?BLUE_ASG_NAME is required}"
green_asg="${GREEN_ASG_NAME:?GREEN_ASG_NAME is required}"
active_https_tg="${ACTIVE_HTTPS_TARGET_ARN:?ACTIVE_HTTPS_TARGET_ARN is required}"
active_ssh_tg="${ACTIVE_SSH_TARGET_ARN:?ACTIVE_SSH_TARGET_ARN is required}"
blue_https_tg="${BLUE_HTTPS_TARGET_ARN:?BLUE_HTTPS_TARGET_ARN is required}"
green_https_tg="${GREEN_HTTPS_TARGET_ARN:?GREEN_HTTPS_TARGET_ARN is required}"
nlb_arn="${NLB_ARN:?NLB_ARN is required}"
blue_launch_template_version="${BLUE_LAUNCH_TEMPLATE_VERSION:?BLUE_LAUNCH_TEMPLATE_VERSION is required}"
green_launch_template_version="${GREEN_LAUNCH_TEMPLATE_VERSION:?GREEN_LAUNCH_TEMPLATE_VERSION is required}"
aws_region="${AWS_REGION:?AWS_REGION is required}"
name_prefix="${NAME_PREFIX:-forgeproxy}"
cache_ebs_enabled="${CACHE_EBS_ENABLED:-false}"
cache_volume_gb="${CACHE_VOLUME_GB:-1024}"
cache_volume_type="${CACHE_VOLUME_TYPE:-gp3}"
cache_volume_iops="${CACHE_VOLUME_IOPS:-3000}"
cache_volume_throughput_mbps="${CACHE_VOLUME_THROUGHPUT_MBPS:-125}"
cache_seed_wait_for_snapshots="${CACHE_SEED_WAIT_FOR_SNAPSHOTS:-true}"
cache_seed_snapshot_retention_count="${CACHE_SEED_SNAPSHOT_RETENTION_COUNT:-1}"

case "${active_slot}" in
  blue)
    active_asg="${blue_asg}"
    active_launch_template_version="${blue_launch_template_version}"
    ;;
  green)
    active_asg="${green_asg}"
    active_launch_template_version="${green_launch_template_version}"
    ;;
  *)
    echo "unknown ACTIVE_SLOT: ${active_slot}" >&2
    exit 1
    ;;
esac

aws_args=(--region "${aws_region}")

asg_for_slot() {
  local slot="$1"

  case "${slot}" in
    blue)
      printf '%s\n' "${blue_asg}"
      ;;
    green)
      printf '%s\n' "${green_asg}"
      ;;
    *)
      return 1
      ;;
  esac
}

current_listener_slot() {
  local listener_https_arn
  local target_group_arns

  listener_https_arn="$(aws "${aws_args[@]}" elbv2 describe-listeners \
    --load-balancer-arn "${nlb_arn}" \
    --query 'Listeners[?Port==`443`].ListenerArn | [0]' \
    --output text 2>/dev/null || true)"
  if [[ -z "${listener_https_arn}" || "${listener_https_arn}" == "None" ]]; then
    printf '%s\n' "unknown"
    return 0
  fi

  target_group_arns="$(aws "${aws_args[@]}" elbv2 describe-listeners \
    --listener-arns "${listener_https_arn}" \
    --query "Listeners[0].DefaultActions[0].ForwardConfig.TargetGroups[?Weight > \`0\`].TargetGroupArn" \
    --output text 2>/dev/null || true)"

  case "${target_group_arns}" in
    "${blue_https_tg}")
      printf '%s\n' "blue"
      ;;
    "${green_https_tg}")
      printf '%s\n' "green"
      ;;
    *)
      printf '%s\n' "unknown"
      ;;
  esac
}

asg_instance_count() {
  local asg_name="$1"

  aws "${aws_args[@]}" autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "${asg_name}" \
    --query 'length(AutoScalingGroups[0].Instances)' \
    --output text
}

describe_asg_instances() {
  local asg_name="$1"

  echo "ASG ${asg_name} instance details:"
  aws "${aws_args[@]}" autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "${asg_name}" \
    --query 'AutoScalingGroups[0].Instances[].{Id:InstanceId,State:LifecycleState,Health:HealthStatus,AZ:AvailabilityZone,LT:LaunchTemplate.Version,Protected:ProtectedFromScaleIn}' \
    --output table || true
}

describe_recent_scaling_activities() {
  local asg_name="$1"

  echo "ASG ${asg_name} recent scaling activities:"
  aws "${aws_args[@]}" autoscaling describe-scaling-activities \
    --auto-scaling-group-name "${asg_name}" \
    --max-items 5 \
    --query 'Activities[].{Start:StartTime,Status:StatusCode,Progress:Progress,Description:Description,Cause:Cause,StatusMessage:StatusMessage}' \
    --output table || true
}

wait_for_asg_instance_count() {
  local asg_name="$1"
  local expected_count="$2"
  local attempt=0
  local instance_count

  echo "Waiting for Auto Scaling Group ${asg_name} to contain ${expected_count} instances"
  while true; do
    instance_count="$(asg_instance_count "${asg_name}")"
    if [[ "${instance_count}" == "${expected_count}" ]]; then
      break
    fi
    echo "ASG ${asg_name}: ${instance_count}/${expected_count} instances present"
    if (( attempt % 6 == 0 )); then
      describe_asg_instances "${asg_name}"
      describe_recent_scaling_activities "${asg_name}"
    fi
    attempt="$(( attempt + 1 ))"
    sleep 10
  done
}

asg_running_launch_template_versions() {
  local asg_name="$1"

  aws "${aws_args[@]}" autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "${asg_name}" \
    --query 'AutoScalingGroups[0].Instances[].LaunchTemplate.Version' \
    --output text
}

enforce_blue_green_slot_flip() {
  local current_slot current_instance_count running_versions version

  current_slot="$(current_listener_slot)"
  if [[ "${current_slot}" != "${active_slot}" ]]; then
    return 0
  fi

  current_instance_count="$(asg_instance_count "${active_asg}")"
  if [[ "${current_instance_count}" == "0" ]]; then
    return 0
  fi

  running_versions="$(asg_running_launch_template_versions "${active_asg}")"
  for version in ${running_versions}; do
    if [[ "${version}" != "${active_launch_template_version}" ]]; then
      cat >&2 <<EOF
Refusing rollout: forgeproxy_active_slot is still '${active_slot}', but the currently live slot is running launch template version ${version} while Terraform wants ${active_launch_template_version}.

This would replace instances in the live slot instead of staging the new revision on the standby slot first.
Leave forgeproxy_active_slot unset for automatic alternation, or set it to the opposite color for this apply, then rerun terraform apply.
EOF
      exit 1
    fi
  done
}

target_group_attached_to_load_balancer() {
  local target_group_arn="$1"
  local attachment_count

  attachment_count="$(aws "${aws_args[@]}" elbv2 describe-target-groups \
    --target-group-arns "${target_group_arn}" \
    --query 'length(TargetGroups[0].LoadBalancerArns)' \
    --output text)"

  [[ "${attachment_count}" != "0" ]]
}

enforce_blue_green_slot_flip

reset_standby_target_slot() {
  local current_slot current_instance_count

  current_slot="$(current_listener_slot)"
  if [[ "${current_slot}" == "${active_slot}" ]]; then
    return 0
  fi
  if [[ "${current_slot}" == "unknown" ]]; then
    echo "Current live slot is unknown; not resetting target slot ${active_slot} before rollout"
    return 0
  fi

  current_instance_count="$(asg_instance_count "${active_asg}")"
  if [[ "${current_instance_count}" == "0" ]]; then
    return 0
  fi

  echo "Resetting standby target slot ${active_slot} (${active_asg}) from ${current_instance_count} stale instances to zero before rollout"
  aws "${aws_args[@]}" autoscaling update-auto-scaling-group \
    --auto-scaling-group-name "${active_asg}" \
    --min-size 0 \
    --desired-capacity 0 \
    --max-size "${max_count}"
  wait_for_asg_instance_count "${active_asg}" "0"
}

reset_standby_target_slot

asg_instance_ids() {
  local asg_name="$1"

  aws "${aws_args[@]}" autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "${asg_name}" \
    --query 'AutoScalingGroups[0].Instances[].InstanceId' \
    --output text
}

source_cache_volumes_for_instance() {
  local instance_id="$1"
  local slot="$2"

  aws "${aws_args[@]}" ec2 describe-volumes \
    --filters \
      "Name=attachment.instance-id,Values=${instance_id}" \
      "Name=tag:Role,Values=forgeproxy-cache" \
      "Name=tag:ForgeproxyNamePrefix,Values=${name_prefix}" \
      "Name=tag:DeploymentSlot,Values=${slot}" \
    --query 'Volumes[].[VolumeId, Tags[?Key==`CacheSlot`].Value | [0]]' \
    --output text
}

mark_old_target_seed_volumes_inactive() {
  local old_volume_ids

  old_volume_ids="$(aws "${aws_args[@]}" ec2 describe-volumes \
    --filters \
      "Name=tag:Role,Values=forgeproxy-cache" \
      "Name=tag:ForgeproxyNamePrefix,Values=${name_prefix}" \
      "Name=tag:DeploymentSlot,Values=${active_slot}" \
      "Name=tag:CurrentSeed,Values=true" \
    --query 'Volumes[].VolumeId' \
    --output text)"

  if [[ -z "${old_volume_ids}" || "${old_volume_ids}" == "None" ]]; then
    return 0
  fi

  echo "Marking old ${active_slot} cache seed volumes inactive: ${old_volume_ids}"
  aws "${aws_args[@]}" ec2 create-tags \
    --resources ${old_volume_ids} \
    --tags Key=CurrentSeed,Value=false
}

mark_old_target_seed_snapshots_inactive() {
  local old_snapshot_ids

  old_snapshot_ids="$(aws "${aws_args[@]}" ec2 describe-snapshots \
    --owner-ids self \
    --filters \
      "Name=tag:Role,Values=forgeproxy-cache-seed" \
      "Name=tag:ForgeproxyNamePrefix,Values=${name_prefix}" \
      "Name=tag:DeploymentSlot,Values=${active_slot}" \
      "Name=tag:CurrentSeed,Values=true" \
    --query 'Snapshots[].SnapshotId' \
    --output text)"

  if [[ -n "${old_snapshot_ids}" && "${old_snapshot_ids}" != "None" ]]; then
    echo "Marking old ${active_slot} cache seed snapshots inactive: ${old_snapshot_ids}"
    aws "${aws_args[@]}" ec2 create-tags \
      --resources ${old_snapshot_ids} \
      --tags Key=CurrentSeed,Value=false
  fi

  old_snapshot_ids="$(aws "${aws_args[@]}" ec2 describe-snapshots \
    --owner-ids self \
    --filters \
      "Name=tag:Role,Values=forgeproxy-cache-seed" \
      "Name=tag:ForgeproxyNamePrefix,Values=${name_prefix}" \
      "Name=tag:DeploymentSlot,Values=${active_slot}" \
      "Name=tag:PendingSeed,Values=true" \
    --query 'Snapshots[].SnapshotId' \
    --output text)"

  if [[ -z "${old_snapshot_ids}" || "${old_snapshot_ids}" == "None" ]]; then
    return 0
  fi

  echo "Marking pending ${active_slot} cache seed snapshots stale: ${old_snapshot_ids}"
  aws "${aws_args[@]}" ec2 create-tags \
    --resources ${old_snapshot_ids} \
    --tags Key=PendingSeed,Value=false Key=CurrentSeed,Value=false Key=StaleSeed,Value=true
}

snapshot_active_cache_volumes() {
  local source_slot="$1"
  local source_asg
  local instance_ids instance_id volume_rows row volume_id cache_slot snapshot_id created_at_unix

  source_asg="$(asg_for_slot "${source_slot}")" || return 0
  instance_ids="$(asg_instance_ids "${source_asg}")"
  if [[ -z "${instance_ids}" || "${instance_ids}" == "None" ]]; then
    echo "No source ${source_slot} instances found; standby cache volumes will be created blank"
    return 0
  fi

  for instance_id in ${instance_ids}; do
    volume_rows="$(source_cache_volumes_for_instance "${instance_id}" "${source_slot}")"
    if [[ -z "${volume_rows}" || "${volume_rows}" == "None" ]]; then
      continue
    fi

    while read -r row; do
      [[ -n "${row}" ]] || continue
      volume_id="$(awk '{print $1}' <<<"${row}")"
      cache_slot="$(awk '{print $2}' <<<"${row}")"
      [[ -n "${cache_slot}" && "${cache_slot}" != "None" ]] || cache_slot="dynamic"
      created_at_unix="$(date -u +%s)"
      echo "Creating live cache snapshot from ${source_slot} volume ${volume_id} attached to ${instance_id} (cache slot ${cache_slot})"
      snapshot_id="$(aws "${aws_args[@]}" ec2 create-snapshot \
        --volume-id "${volume_id}" \
        --description "${name_prefix} forgeproxy ${source_slot} cache slot ${cache_slot} seed for ${active_slot}" \
        --tag-specifications "ResourceType=snapshot,Tags=[{Key=Name,Value=${name_prefix}-forgeproxy-${active_slot}-cache-seed-${cache_slot}},{Key=Role,Value=forgeproxy-cache-seed},{Key=ForgeproxyNamePrefix,Value=${name_prefix}},{Key=DeploymentSlot,Value=${active_slot}},{Key=SourceSlot,Value=${source_slot}},{Key=SourceCacheSlot,Value=${cache_slot}},{Key=SourceVolumeId,Value=${volume_id}},{Key=CurrentSeed,Value=true},{Key=CreatedAtUnix,Value=${created_at_unix}},{Key=CreatedBy,Value=forgeproxy-rollout-prepare}]" \
        --query SnapshotId \
        --output text)"
      echo "${snapshot_id}"
    done <<<"${volume_rows}"
  done
}

current_seed_snapshot_ids() {
  aws "${aws_args[@]}" ec2 describe-snapshots \
    --owner-ids self \
    --filters \
      "Name=status,Values=completed" \
      "Name=tag:Role,Values=forgeproxy-cache-seed" \
      "Name=tag:ForgeproxyNamePrefix,Values=${name_prefix}" \
      "Name=tag:DeploymentSlot,Values=${active_slot}" \
      "Name=tag:CurrentSeed,Values=true" \
    --query 'Snapshots[].[SnapshotId, Tags[?Key==`SourceVolumeId`].Value | [0], Tags[?Key==`SourceCacheSlot`].Value | [0]]' \
    --output text \
    | sort -k2,2 -k3,3n \
    | awk '{print $1}'
}

current_seed_snapshot_ids_any_status() {
  aws "${aws_args[@]}" ec2 describe-snapshots \
    --owner-ids self \
    --filters \
      "Name=tag:Role,Values=forgeproxy-cache-seed" \
      "Name=tag:ForgeproxyNamePrefix,Values=${name_prefix}" \
      "Name=tag:DeploymentSlot,Values=${active_slot}" \
      "Name=tag:CurrentSeed,Values=true" \
    --query 'Snapshots[].SnapshotId' \
    --output text \
    | tr '\t' '\n'
}

delete_old_target_seed_snapshots() {
  local rows snapshot_ids snapshot_id

  if ! [[ "${cache_seed_snapshot_retention_count}" =~ ^[0-9]+$ ]]; then
    echo "Invalid CACHE_SEED_SNAPSHOT_RETENTION_COUNT=${cache_seed_snapshot_retention_count}" >&2
    return 1
  fi
  if (( cache_seed_snapshot_retention_count < 1 )); then
    return 0
  fi

  rows="$(aws "${aws_args[@]}" ec2 describe-snapshots \
    --owner-ids self \
    --filters \
      "Name=status,Values=completed" \
      "Name=tag:Role,Values=forgeproxy-cache-seed" \
      "Name=tag:ForgeproxyNamePrefix,Values=${name_prefix}" \
      "Name=tag:DeploymentSlot,Values=${active_slot}" \
    --query 'Snapshots[].[SnapshotId, Tags[?Key==`SourceVolumeId`].Value | [0], Tags[?Key==`SourceCacheSlot`].Value | [0], Tags[?Key==`CreatedAtUnix`].Value | [0]]' \
    --output text)"

  if [[ -z "${rows}" || "${rows}" == "None" ]]; then
    return 0
  fi

  snapshot_ids="$(awk -v keep="${cache_seed_snapshot_retention_count}" '
    NF >= 1 {
      snapshot_id = $1
      source_volume_id = $2
      cache_slot = $3
      created_at = $4
      if (source_volume_id == "" || source_volume_id == "None") {
        source_volume_id = ""
      }
      if (cache_slot == "" || cache_slot == "None") {
        cache_slot = "dynamic"
      }
      if (created_at !~ /^[0-9]+$/) {
        created_at = 0
      }
      group_key = source_volume_id
      if (group_key == "") {
        group_key = "cache:" cache_slot
      }
      print group_key, created_at, snapshot_id
    }
  ' <<<"${rows}" | sort -k1,1 -k2,2nr | awk -v keep="${cache_seed_snapshot_retention_count}" '
    {
      group_key = $1
      seen[group_key] += 1
      if (seen[group_key] > keep) {
        print $3
      }
    }
  ')"

  if [[ -z "${snapshot_ids}" || "${snapshot_ids}" == "None" ]]; then
    return 0
  fi

  while read -r snapshot_id; do
    [[ -n "${snapshot_id}" ]] || continue
    echo "Deleting old ${active_slot} cache seed snapshot ${snapshot_id}"
    aws "${aws_args[@]}" ec2 delete-snapshot --snapshot-id "${snapshot_id}"
  done <<<"${snapshot_ids}"
}

snapshot_volume_size_gb() {
  local snapshot_id="$1"

  aws "${aws_args[@]}" ec2 describe-snapshots \
    --snapshot-ids "${snapshot_id}" \
    --query 'Snapshots[0].VolumeSize' \
    --output text
}

target_asg_availability_zone() {
  local target_asg

  target_asg="$(asg_for_slot "${active_slot}")"
  aws "${aws_args[@]}" autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "${target_asg}" \
    --query 'AutoScalingGroups[0].AvailabilityZones[0]' \
    --output text
}

target_cache_volume_for_slot_exists() {
  local cache_slot="$1"
  local count

  count="$(aws "${aws_args[@]}" ec2 describe-volumes \
    --filters \
      "Name=tag:Role,Values=forgeproxy-cache" \
      "Name=tag:ForgeproxyNamePrefix,Values=${name_prefix}" \
      "Name=tag:DeploymentSlot,Values=${active_slot}" \
      "Name=tag:CurrentSeed,Values=true" \
      "Name=tag:CacheSlot,Values=${cache_slot}" \
    --query 'length(Volumes)' \
    --output text)"

  [[ "${count}" != "0" ]]
}

create_target_cache_volume() {
  local cache_slot="$1"
  local snapshot_id="${2:-}"
  local source_tag="none"
  local snapshot_size_gb
  local target_az
  local volume_id

  target_az="$(target_asg_availability_zone)"
  local args=(
    ec2 create-volume
    --availability-zone "${target_az}"
    --volume-type "${cache_volume_type}"
    --encrypted
    --query VolumeId
    --output text
  )

  if [[ "${cache_volume_type}" == "gp3" ]]; then
    args+=(--iops "${cache_volume_iops}" --throughput "${cache_volume_throughput_mbps}")
  fi
  if [[ -n "${snapshot_id}" ]]; then
    args+=(--snapshot-id "${snapshot_id}")
    snapshot_size_gb="$(snapshot_volume_size_gb "${snapshot_id}")"
    if (( cache_volume_gb > snapshot_size_gb )); then
      args+=(--size "${cache_volume_gb}")
    fi
    source_tag="${snapshot_id}"
  else
    args+=(--size "${cache_volume_gb}")
  fi
  args+=(--tag-specifications "ResourceType=volume,Tags=[{Key=Name,Value=${name_prefix}-forgeproxy-${active_slot}-cache-${cache_slot}},{Key=Role,Value=forgeproxy-cache},{Key=ForgeproxyNamePrefix,Value=${name_prefix}},{Key=DeploymentSlot,Value=${active_slot}},{Key=CacheSlot,Value=${cache_slot}},{Key=CurrentSeed,Value=true},{Key=AttachmentState,Value=available},{Key=SourceSnapshotId,Value=${source_tag}},{Key=CreatedBy,Value=forgeproxy-rollout-prepare}]")

  volume_id="$(aws "${aws_args[@]}" "${args[@]}")"
  echo "Created ${active_slot} cache volume ${volume_id} for cache slot ${cache_slot} from ${source_tag}"
  aws "${aws_args[@]}" ec2 wait volume-available --volume-ids "${volume_id}"
}

prepare_cache_seed_volumes() {
  local source_slot="${current_live_slot}"
  local snapshot_ids=()
  local snapshot_count=0
  local slot snapshot_index snapshot_id

  if [[ "${cache_ebs_enabled}" != "true" ]]; then
    return 0
  fi

  echo "Preparing dedicated cache EBS seed volumes for target slot ${active_slot}"
  if [[ "${source_slot}" == "${active_slot}" ]]; then
    echo "Target slot ${active_slot} is already the live slot; leaving current cache seed volumes unchanged"
    return 0
  fi

  mark_old_target_seed_volumes_inactive

  if [[ "${source_slot}" == "unknown" || -z "${source_slot}" ]]; then
    echo "No distinct live source slot is available; target cache volumes will be created blank"
  else
    mark_old_target_seed_snapshots_inactive
    snapshot_active_cache_volumes "${source_slot}"
    mapfile -t snapshot_ids < <(current_seed_snapshot_ids_any_status)
    if [[ "${#snapshot_ids[@]}" -gt 0 && "${cache_seed_wait_for_snapshots}" == "true" ]]; then
      echo "Waiting for ${#snapshot_ids[@]} cache seed snapshots to complete"
      aws "${aws_args[@]}" ec2 wait snapshot-completed --snapshot-ids "${snapshot_ids[@]}"
    fi
    mapfile -t snapshot_ids < <(current_seed_snapshot_ids)
    snapshot_count="${#snapshot_ids[@]}"
    if (( snapshot_count > 0 )); then
      delete_old_target_seed_snapshots
      mapfile -t snapshot_ids < <(current_seed_snapshot_ids)
      snapshot_count="${#snapshot_ids[@]}"
    fi
  fi

  for ((slot = 0; slot < desired_count; slot++)); do
    if target_cache_volume_for_slot_exists "${slot}"; then
      echo "Target cache volume for ${active_slot} cache slot ${slot} already exists"
      continue
    fi

    snapshot_id=""
    if (( snapshot_count > 0 )); then
      snapshot_index=$(( slot % snapshot_count ))
      snapshot_id="${snapshot_ids[${snapshot_index}]}"
    fi
    create_target_cache_volume "${slot}" "${snapshot_id}"
  done
}

prepare_cache_seed_volumes

wait_for_asg_in_service() {
  local asg_name="$1"
  local expected_count="$2"
  local attempt=0
  local in_service_count
  local instance_count
  local healthy_count

  if [[ "${expected_count}" == "0" ]]; then
    echo "Desired capacity is zero; skipping Auto Scaling Group readiness wait"
    return 0
  fi

  echo "Waiting for Auto Scaling Group ${asg_name} to reach ${expected_count} healthy InService instances"
  while true; do
    instance_count="$(aws "${aws_args[@]}" autoscaling describe-auto-scaling-groups \
      --auto-scaling-group-names "${asg_name}" \
      --query 'length(AutoScalingGroups[0].Instances)' \
      --output text)"
    in_service_count="$(aws "${aws_args[@]}" autoscaling describe-auto-scaling-groups \
      --auto-scaling-group-names "${asg_name}" \
      --query "length(AutoScalingGroups[0].Instances[?LifecycleState=='InService'])" \
      --output text)"
    healthy_count="$(aws "${aws_args[@]}" autoscaling describe-auto-scaling-groups \
      --auto-scaling-group-names "${asg_name}" \
      --query "length(AutoScalingGroups[0].Instances[?LifecycleState=='InService' && HealthStatus=='Healthy'])" \
      --output text)"
    if [[ "${instance_count}" == "${expected_count}" && "${healthy_count}" == "${expected_count}" ]]; then
      break
    fi
    echo "ASG ${asg_name}: ${healthy_count}/${expected_count} healthy InService, ${in_service_count}/${expected_count} InService, ${instance_count}/${expected_count} instances present"
    if (( attempt % 6 == 0 )); then
      describe_asg_instances "${asg_name}"
      describe_recent_scaling_activities "${asg_name}"
    fi
    attempt="$(( attempt + 1 ))"
    sleep 10
  done
}

echo "Scaling active slot ${active_slot} (${active_asg}) to ${desired_count} instances"
aws "${aws_args[@]}" autoscaling update-auto-scaling-group \
  --auto-scaling-group-name "${active_asg}" \
  --min-size "${desired_count}" \
  --desired-capacity "${desired_count}" \
  --max-size "${max_count}"

wait_for_asg_in_service "${active_asg}" "${desired_count}"

wait_for_target_group_health() {
  local target_group_arn="$1"
  local label="$2"
  local attempt=0
  local healthy_count
  local unused_count
  local total_count

  echo "Waiting for ${label} target group to report ${desired_count} healthy targets"
  while true; do
    healthy_count="$(aws "${aws_args[@]}" elbv2 describe-target-health \
      --target-group-arn "${target_group_arn}" \
      --query "length(TargetHealthDescriptions[?TargetHealth.State=='healthy'])" \
      --output text)"
    unused_count="$(aws "${aws_args[@]}" elbv2 describe-target-health \
      --target-group-arn "${target_group_arn}" \
      --query "length(TargetHealthDescriptions[?TargetHealth.State=='unused'])" \
      --output text)"
    total_count="$(aws "${aws_args[@]}" elbv2 describe-target-health \
      --target-group-arn "${target_group_arn}" \
      --query "length(TargetHealthDescriptions)" \
      --output text)"
    if [[ "${healthy_count}" == "${desired_count}" ]]; then
      break
    fi
    if ! target_group_attached_to_load_balancer "${target_group_arn}"; then
      echo "${label} target group is not attached to a listener yet; skipping health wait during bootstrap"
      break
    fi
    echo "${label} target group is not ready yet: healthy=${healthy_count}/${desired_count}, unused=${unused_count}/${total_count}"
    if (( attempt % 6 == 0 )); then
      echo "${label} target group target health details:"
      aws "${aws_args[@]}" elbv2 describe-target-health \
        --target-group-arn "${target_group_arn}" \
        --query 'TargetHealthDescriptions[].{Target:Target.Id,Port:Target.Port,State:TargetHealth.State,Reason:TargetHealth.Reason,Description:TargetHealth.Description}' \
        --output table || true
      describe_asg_instances "${active_asg}"
      describe_recent_scaling_activities "${active_asg}"
    fi
    attempt="$(( attempt + 1 ))"
    sleep 10
  done
}

wait_for_target_group_health "${active_https_tg}" "HTTPS"
wait_for_target_group_health "${active_ssh_tg}" "SSH"

echo "Active slot ${active_slot} is ready for cutover"
