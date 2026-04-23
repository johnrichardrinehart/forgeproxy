#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${AWS_PROFILE:-}" && -n "${AWS_PROFILE_FALLBACK:-}" ]]; then
  export AWS_PROFILE="${AWS_PROFILE_FALLBACK}"
fi

lb_name="${LB_NAME:?LB_NAME is required}"
blue_target_group_name="${BLUE_TARGET_GROUP_NAME:?BLUE_TARGET_GROUP_NAME is required}"
green_target_group_name="${GREEN_TARGET_GROUP_NAME:?GREEN_TARGET_GROUP_NAME is required}"
aws_region="${AWS_REGION:?AWS_REGION is required}"

aws_args=(--region "${aws_region}")

json_result() {
  local current_slot="$1"
  local target_slot="$2"

  printf '{"current_slot":"%s","target_slot":"%s"}\n' "${current_slot}" "${target_slot}"
}

resolve_target_slot() {
  local current_slot="$1"

  case "${current_slot}" in
    blue)
      printf '%s\n' "green"
      ;;
    green)
      printf '%s\n' "blue"
      ;;
    *)
      printf '%s\n' "blue"
      ;;
  esac
}

lb_arn="$(aws "${aws_args[@]}" elbv2 describe-load-balancers \
  --names "${lb_name}" \
  --query 'LoadBalancers[0].LoadBalancerArn' \
  --output text 2>/dev/null || true)"
if [[ -z "${lb_arn}" || "${lb_arn}" == "None" ]]; then
  json_result "unknown" "$(resolve_target_slot "unknown")"
  exit 0
fi

listener_arn="$(aws "${aws_args[@]}" elbv2 describe-listeners \
  --load-balancer-arn "${lb_arn}" \
  --query 'Listeners[?Port==`443`].ListenerArn | [0]' \
  --output text 2>/dev/null || true)"
if [[ -z "${listener_arn}" || "${listener_arn}" == "None" ]]; then
  json_result "unknown" "$(resolve_target_slot "unknown")"
  exit 0
fi

blue_target_group_arn="$(aws "${aws_args[@]}" elbv2 describe-target-groups \
  --names "${blue_target_group_name}" \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text 2>/dev/null || true)"
green_target_group_arn="$(aws "${aws_args[@]}" elbv2 describe-target-groups \
  --names "${green_target_group_name}" \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text 2>/dev/null || true)"
active_target_group_arn="$(aws "${aws_args[@]}" elbv2 describe-listeners \
  --listener-arns "${listener_arn}" \
  --query 'Listeners[0].DefaultActions[0].ForwardConfig.TargetGroups[?Weight > `0`].TargetGroupArn | [0]' \
  --output text 2>/dev/null || true)"

case "${active_target_group_arn}" in
  "${blue_target_group_arn}")
    current_slot="blue"
    ;;
  "${green_target_group_arn}")
    current_slot="green"
    ;;
  *)
    current_slot="unknown"
    ;;
esac

json_result "${current_slot}" "$(resolve_target_slot "${current_slot}")"
