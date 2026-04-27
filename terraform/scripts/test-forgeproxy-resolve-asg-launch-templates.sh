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

case "${service}:${command}:${asg_name}:${query}" in
  autoscaling:describe-auto-scaling-groups:blue-asg:AutoScalingGroups\[0\].LaunchTemplate.Version)
    printf '%s\n' "7"
    ;;
  autoscaling:describe-auto-scaling-groups:green-asg:AutoScalingGroups\[0\].LaunchTemplate.Version)
    printf '%s\n' '$Latest'
    ;;
  autoscaling:describe-auto-scaling-groups:green-asg:AutoScalingGroups\[0\].Instances\[0\].LaunchTemplate.Version)
    printf '%s\n' "8"
    ;;
  *)
    echo "unexpected aws invocation: service=${service} command=${command} asg=${asg_name} query=${query}" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${mock_bin}/aws"

result="$(
  env \
    PATH="${mock_bin}:${PATH}" \
    AWS_REGION="us-east-1" \
    BLUE_ASG_NAME="blue-asg" \
    GREEN_ASG_NAME="green-asg" \
    bash "${script_path}"
)"

[[ "${result}" == '{"blue_version":"7","green_version":"8"}' ]]

echo "forgeproxy-resolve-asg-launch-templates tests passed"
