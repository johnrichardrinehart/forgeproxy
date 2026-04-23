#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${repo_root}/terraform/scripts/forgeproxy-resolve-slot.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

mock_bin="${tmpdir}/bin"
mkdir -p "${mock_bin}"

cat > "${mock_bin}/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

scenario="${TEST_SCENARIO:?TEST_SCENARIO is required}"

if [[ "$1" == "--region" ]]; then
  shift 2
fi

service="${1:?service missing}"
command="${2:?command missing}"
shift 2

query=""
target_group_name=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --query)
      query="$2"
      shift 2
      ;;
    --names)
      target_group_name="$2"
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

case "${scenario}:${service}:${command}:${query}" in
  bootstrap_missing_lb:elbv2:describe-load-balancers:*)
    printf '%s\n' "None"
    ;;
  live_blue:elbv2:describe-load-balancers:*)
    printf '%s\n' "nlb-arn"
    ;;
  live_blue:elbv2:describe-listeners:Listeners\[\?Port==\`443\`\].ListenerArn\ \|\ \[0\])
    printf '%s\n' "listener-arn"
    ;;
  live_blue:elbv2:describe-target-groups:TargetGroups\[0\].TargetGroupArn)
    if [[ "${target_group_name}" == "forgeproxy-blue-https-tg" ]]; then
      printf '%s\n' "blue-arn"
    else
      printf '%s\n' "green-arn"
    fi
    ;;
  live_blue:elbv2:describe-listeners:Listeners\[0\].DefaultActions\[0\].ForwardConfig.TargetGroups\[\?Weight\ \>\ \`0\`\].TargetGroupArn\ \|\ \[0\])
    printf '%s\n' "blue-arn"
    ;;
  live_green:elbv2:describe-load-balancers:*)
    printf '%s\n' "nlb-arn"
    ;;
  live_green:elbv2:describe-listeners:Listeners\[\?Port==\`443\`\].ListenerArn\ \|\ \[0\])
    printf '%s\n' "listener-arn"
    ;;
  live_green:elbv2:describe-target-groups:TargetGroups\[0\].TargetGroupArn)
    if [[ "${target_group_name}" == "forgeproxy-blue-https-tg" ]]; then
      printf '%s\n' "blue-arn"
    else
      printf '%s\n' "green-arn"
    fi
    ;;
  live_green:elbv2:describe-listeners:Listeners\[0\].DefaultActions\[0\].ForwardConfig.TargetGroups\[\?Weight\ \>\ \`0\`\].TargetGroupArn\ \|\ \[0\])
    printf '%s\n' "green-arn"
    ;;
  *)
    echo "unexpected aws invocation for scenario=${scenario}: service=${service} command=${command} query=${query}" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${mock_bin}/aws"

run_case() {
  local scenario="$1"

  env \
    PATH="${mock_bin}:${PATH}" \
    TEST_SCENARIO="${scenario}" \
    AWS_REGION="us-east-1" \
    LB_NAME="forgeproxy-nlb" \
    BLUE_TARGET_GROUP_NAME="forgeproxy-blue-https-tg" \
    GREEN_TARGET_GROUP_NAME="forgeproxy-green-https-tg" \
    bash "${script_path}"
}

bootstrap_result="$(run_case bootstrap_missing_lb)"
[[ "${bootstrap_result}" == '{"current_slot":"unknown","target_slot":"blue"}' ]]

blue_result="$(run_case live_blue)"
[[ "${blue_result}" == '{"current_slot":"blue","target_slot":"green"}' ]]

green_result="$(run_case live_green)"
[[ "${green_result}" == '{"current_slot":"green","target_slot":"blue"}' ]]

echo "forgeproxy-resolve-slot tests passed"
