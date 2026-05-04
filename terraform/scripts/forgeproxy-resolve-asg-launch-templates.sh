#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${AWS_PROFILE:-}" && -n "${AWS_PROFILE_FALLBACK:-}" ]]; then
  export AWS_PROFILE="${AWS_PROFILE_FALLBACK}"
fi

blue_asg_name="${BLUE_ASG_NAME:?BLUE_ASG_NAME is required}"
green_asg_name="${GREEN_ASG_NAME:?GREEN_ASG_NAME is required}"
aws_region="${AWS_REGION:?AWS_REGION is required}"

aws_args=(--region "${aws_region}")

asg_launch_template_version() {
  local asg_name="$1"
  local instance_versions
  local min_version
  local version

  instance_versions="$(aws "${aws_args[@]}" autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "${asg_name}" \
    --query 'AutoScalingGroups[0].Instances[].LaunchTemplate.Version' \
    --output text 2>/dev/null || true)"

  if [[ -n "${instance_versions}" && "${instance_versions}" != "None" ]]; then
    min_version=""
    for version in ${instance_versions}; do
      case "${version}" in
        "" | "None" | "null" | '$Latest' | '$Default' | *[!0-9]*)
          continue
          ;;
      esac
      if [[ -z "${min_version}" ]] || (( version < min_version )); then
        min_version="${version}"
      fi
    done
    if [[ -n "${min_version}" ]]; then
      printf '%s\n' "${min_version}"
      return 0
    fi
  fi

  version="$(aws "${aws_args[@]}" autoscaling describe-auto-scaling-groups \
    --auto-scaling-group-names "${asg_name}" \
    --query 'AutoScalingGroups[0].LaunchTemplate.Version' \
    --output text 2>/dev/null || true)"

  case "${version}" in
    "" | "None" | "null" | '$Latest' | '$Default')
      printf '%s\n' ""
      ;;
    *)
      printf '%s\n' "${version}"
      ;;
  esac
}

blue_version="$(asg_launch_template_version "${blue_asg_name}")"
green_version="$(asg_launch_template_version "${green_asg_name}")"

printf '{"blue_version":"%s","green_version":"%s"}\n' "${blue_version}" "${green_version}"
