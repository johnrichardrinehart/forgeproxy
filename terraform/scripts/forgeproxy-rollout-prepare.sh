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
blue_https_tg="${BLUE_HTTPS_TARGET_ARN:?BLUE_HTTPS_TARGET_ARN is required}"
green_https_tg="${GREEN_HTTPS_TARGET_ARN:?GREEN_HTTPS_TARGET_ARN is required}"
nlb_arn="${NLB_ARN:?NLB_ARN is required}"
blue_launch_template_version="${BLUE_LAUNCH_TEMPLATE_VERSION:?BLUE_LAUNCH_TEMPLATE_VERSION is required}"
green_launch_template_version="${GREEN_LAUNCH_TEMPLATE_VERSION:?GREEN_LAUNCH_TEMPLATE_VERSION is required}"
aws_region="${AWS_REGION:?AWS_REGION is required}"

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
    if ! target_group_attached_to_load_balancer "${target_group_arn}"; then
      echo "${label} target group is not attached to a listener yet; skipping health wait during bootstrap"
      break
    fi
    echo "${label} target group is not ready yet: healthy=${healthy_count}/${desired_count}, unused=${unused_count}/${total_count}"
    sleep 10
  done
}

wait_for_target_group_health "${active_https_tg}" "HTTPS"
wait_for_target_group_health "${active_ssh_tg}" "SSH"

echo "Active slot ${active_slot} is ready for cutover"
