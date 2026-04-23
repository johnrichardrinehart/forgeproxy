#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${AWS_PROFILE:-}" && -n "${AWS_PROFILE_FALLBACK:-}" ]]; then
  export AWS_PROFILE="${AWS_PROFILE_FALLBACK}"
fi

active_slot="${ACTIVE_SLOT:?ACTIVE_SLOT is required}"
desired_count="${DESIRED_COUNT:?DESIRED_COUNT is required}"
blue_asg="${BLUE_ASG_NAME:?BLUE_ASG_NAME is required}"
green_asg="${GREEN_ASG_NAME:?GREEN_ASG_NAME is required}"
active_https_tg="${ACTIVE_HTTPS_TARGET_ARN:?ACTIVE_HTTPS_TARGET_ARN is required}"
active_ssh_tg="${ACTIVE_SSH_TARGET_ARN:?ACTIVE_SSH_TARGET_ARN is required}"
aws_region="${AWS_REGION:?AWS_REGION is required}"

case "${active_slot}" in
  blue)
    active_asg="${blue_asg}"
    ;;
  green)
    active_asg="${green_asg}"
    ;;
  *)
    echo "unknown ACTIVE_SLOT: ${active_slot}" >&2
    exit 1
    ;;
esac

aws_args=(--region "${aws_region}")

wait_for_asg_in_service() {
  local asg_name="$1"
  local expected_count="$2"
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
    sleep 10
  done
}

echo "Scaling active slot ${active_slot} (${active_asg}) to ${desired_count} instances"
aws "${aws_args[@]}" autoscaling update-auto-scaling-group \
  --auto-scaling-group-name "${active_asg}" \
  --min-size "${desired_count}" \
  --desired-capacity "${desired_count}" \
  --max-size "${desired_count}"

wait_for_asg_in_service "${active_asg}" "${desired_count}"

wait_for_target_group_health() {
  local target_group_arn="$1"
  local label="$2"
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
    if [[ "${total_count}" == "${desired_count}" && "${unused_count}" == "${desired_count}" ]]; then
      echo "${label} target group is not attached to a listener yet; skipping health wait during bootstrap"
      break
    fi
    sleep 10
  done
}

wait_for_target_group_health "${active_https_tg}" "HTTPS"
wait_for_target_group_health "${active_ssh_tg}" "SSH"

echo "Active slot ${active_slot} is ready for cutover"
