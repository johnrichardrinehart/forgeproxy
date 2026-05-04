#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${repo_root}/terraform/scripts/forgeproxy-resolve-asg-launch-templates.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

mock_bin="${tmpdir}/bin"
mkdir -p "${mock_bin}"

cat >"${mock_bin}/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

scenario="${TEST_SCENARIO:?TEST_SCENARIO is required}"

if [[ "$1" == "--region" ]]; then
  shift 2
fi

service="${1:?service missing}"
command="${2:?command missing}"
shift 2

asg_name=""
query=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --auto-scaling-group-names)
      asg_name="$2"
      shift 2
      ;;
    --query)
      query="$2"
      shift 2
      ;;
    --output)
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

case "${scenario}:${service}:${command}:${asg_name}:${query}" in
  mixed_instance_versions:autoscaling:describe-auto-scaling-groups:blue-asg:AutoScalingGroups\[0\].Instances\[\].LaunchTemplate.Version)
    printf '%s\n' "9 7 8"
    ;;
  mixed_instance_versions:autoscaling:describe-auto-scaling-groups:green-asg:AutoScalingGroups\[0\].Instances\[\].LaunchTemplate.Version)
    printf '%s\n' "16 15"
    ;;
  no_instances_falls_back_to_asg:autoscaling:describe-auto-scaling-groups:blue-asg:AutoScalingGroups\[0\].Instances\[\].LaunchTemplate.Version)
    printf '%s\n' "None"
    ;;
  no_instances_falls_back_to_asg:autoscaling:describe-auto-scaling-groups:green-asg:AutoScalingGroups\[0\].Instances\[\].LaunchTemplate.Version)
    printf '%s\n' "None"
    ;;
  no_instances_falls_back_to_asg:autoscaling:describe-auto-scaling-groups:blue-asg:AutoScalingGroups\[0\].LaunchTemplate.Version)
    printf '%s\n' "7"
    ;;
  no_instances_falls_back_to_asg:autoscaling:describe-auto-scaling-groups:green-asg:AutoScalingGroups\[0\].LaunchTemplate.Version)
    printf '%s\n' '$Latest'
    ;;
  *)
    echo "unexpected aws invocation: scenario=${scenario} service=${service} command=${command} asg=${asg_name} query=${query}" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${mock_bin}/aws"

run_resolver() {
  local scenario="$1"

  env \
    PATH="${mock_bin}:${PATH}" \
    TEST_SCENARIO="${scenario}" \
    AWS_REGION="us-east-1" \
    BLUE_ASG_NAME="blue-asg" \
    GREEN_ASG_NAME="green-asg" \
    bash "${script_path}"
}

result="$(run_resolver mixed_instance_versions)"
[[ "${result}" == '{"blue_version":"7","green_version":"15"}' ]]

result="$(run_resolver no_instances_falls_back_to_asg)"
[[ "${result}" == '{"blue_version":"7","green_version":""}' ]]

echo "forgeproxy-resolve-asg-launch-templates tests passed"
