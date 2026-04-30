#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${repo_root}/terraform/scripts/forgeproxy-rollout-cleanup.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

mock_bin="${tmpdir}/bin"
mkdir -p "${mock_bin}" "${tmpdir}/state"

cat >"${mock_bin}/date" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "+%s" ]]; then
  printf '%s\n' "1000"
else
  command date "$@"
fi
EOF
chmod +x "${mock_bin}/date"

cat >"${mock_bin}/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "${mock_bin}/sleep"

cat >"${mock_bin}/curl" <<'EOF'
#!/usr/bin/env bash
output_file=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --output)
      output_file="$2"
      shift 2
      ;;
    --write-out)
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
[[ -n "${output_file}" ]] && printf 'ok\n' >"${output_file}"
printf '200'
EOF
chmod +x "${mock_bin}/curl"

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
desired_capacity=""
min_size=""
max_size=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --auto-scaling-group-name)
      asg_name="$2"
      shift 2
      ;;
    --desired-capacity)
      desired_capacity="$2"
      shift 2
      ;;
    --min-size)
      min_size="$2"
      shift 2
      ;;
    --max-size)
      max_size="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

case "${service}:${command}" in
  autoscaling:update-auto-scaling-group)
    printf '%s,%s,%s,%s\n' "${asg_name}" "${min_size}" "${desired_capacity}" "${max_size}" >>"${TEST_STATE_DIR:?TEST_STATE_DIR is required}/asg-updates.csv"
    ;;
  *)
    echo "unexpected aws invocation: service=${service} command=${command}" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${mock_bin}/aws"

env \
  PATH="${mock_bin}:${PATH}" \
  TEST_STATE_DIR="${tmpdir}/state" \
  AWS_REGION="us-east-1" \
  ACTIVE_SLOT="green" \
  DESIRED_COUNT="1" \
  MAX_COUNT="4" \
  BLUE_ASG_NAME="blue-asg" \
  GREEN_ASG_NAME="green-asg" \
  NLB_DNS_NAME="nlb.example.com" \
  CLIENT_FACING_HOSTNAMES="forgeproxy.example.com" \
  CUTOVER_CHECK_INTERVAL_SECONDS="1" \
  CUTOVER_REQUIRED_CONSECUTIVE_SUCCESSES="1" \
  CUTOVER_TIMEOUT_SECONDS="60" \
  bash "${script_path}" >"${tmpdir}/cleanup.out" 2>"${tmpdir}/cleanup.err"

grep -q "Reconciling active slot (green-asg) to 1 instances" "${tmpdir}/cleanup.out"
grep -q "Scaling inactive slot (blue-asg) down to zero" "${tmpdir}/cleanup.out"
grep -q '^green-asg,1,1,4$' "${tmpdir}/state/asg-updates.csv"
grep -q '^blue-asg,0,0,4$' "${tmpdir}/state/asg-updates.csv"

echo "forgeproxy-rollout-cleanup tests passed"
