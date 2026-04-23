#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${AWS_PROFILE:-}" && -n "${AWS_PROFILE_FALLBACK:-}" ]]; then
  export AWS_PROFILE="${AWS_PROFILE_FALLBACK}"
fi

active_slot="${ACTIVE_SLOT:?ACTIVE_SLOT is required}"
blue_asg="${BLUE_ASG_NAME:?BLUE_ASG_NAME is required}"
green_asg="${GREEN_ASG_NAME:?GREEN_ASG_NAME is required}"
aws_region="${AWS_REGION:?AWS_REGION is required}"

case "${active_slot}" in
  blue)
    inactive_asg="${green_asg}"
    ;;
  green)
    inactive_asg="${blue_asg}"
    ;;
  *)
    echo "unknown ACTIVE_SLOT: ${active_slot}" >&2
    exit 1
    ;;
esac

aws_args=(--region "${aws_region}")

echo "Scaling inactive slot (${inactive_asg}) down to zero"
aws "${aws_args[@]}" autoscaling update-auto-scaling-group \
  --auto-scaling-group-name "${inactive_asg}" \
  --min-size 0 \
  --desired-capacity 0

echo "Inactive slot ${inactive_asg} requested to scale down"
