#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${repo_root}/terraform/scripts/forgeproxy-rollout-prepare.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

mock_bin="${tmpdir}/bin"
mkdir -p "${mock_bin}"

cat > "${mock_bin}/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "${mock_bin}/sleep"

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
asg_name=""
listener_arn=""
target_group_arn=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --query)
      query="$2"
      shift 2
      ;;
    --auto-scaling-group-names)
      asg_name="$2"
      shift 2
      ;;
    --listener-arns)
      listener_arn="$2"
      shift 2
      ;;
    --target-group-arn|--target-group-arns)
      target_group_arn="$2"
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
  stale_same_slot:elbv2:describe-listeners:*)
    if [[ -n "${listener_arn}" ]]; then
      printf '%s\n' "${listener_arn/https-listener/blue-https}"
    else
      printf '%s\n' "https-listener"
    fi
    ;;
  stale_same_slot:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\))
    printf '%s\n' "1"
    ;;
  stale_same_slot:autoscaling:describe-auto-scaling-groups:AutoScalingGroups\[0\].Instances\[\].LaunchTemplate.Version)
    printf '%s\n' "3"
    ;;
  bootstrap_unattached:elbv2:describe-listeners:*)
    if [[ -n "${listener_arn}" ]]; then
      printf '%s\n' "green-https"
    else
      printf '%s\n' "https-listener"
    fi
    ;;
  bootstrap_unattached:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\))
    printf '%s\n' "1"
    ;;
  bootstrap_unattached:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\[\?LifecycleState==\'InService\'\]\))
    printf '%s\n' "1"
    ;;
  bootstrap_unattached:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\[\?LifecycleState==\'InService\'\ \&\&\ HealthStatus==\'Healthy\'\]\))
    printf '%s\n' "1"
    ;;
  bootstrap_unattached:elbv2:describe-target-health:length\(TargetHealthDescriptions\[\?TargetHealth.State==\'healthy\'\]\))
    printf '%s\n' "0"
    ;;
  bootstrap_unattached:elbv2:describe-target-health:length\(TargetHealthDescriptions\[\?TargetHealth.State==\'unused\'\]\))
    printf '%s\n' "1"
    ;;
  bootstrap_unattached:elbv2:describe-target-health:length\(TargetHealthDescriptions\))
    printf '%s\n' "1"
    ;;
  bootstrap_unattached:elbv2:describe-target-groups:length\(TargetGroups\[0\].LoadBalancerArns\))
    printf '%s\n' "0"
    ;;
  attached_healthy:elbv2:describe-listeners:*)
    if [[ -n "${listener_arn}" ]]; then
      printf '%s\n' "green-https"
    else
      printf '%s\n' "https-listener"
    fi
    ;;
  attached_healthy:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\))
    printf '%s\n' "1"
    ;;
  attached_healthy:autoscaling:describe-auto-scaling-groups:AutoScalingGroups\[0\].Instances\[\].LaunchTemplate.Version)
    printf '%s\n' "9"
    ;;
  attached_healthy:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\[\?LifecycleState==\'InService\'\]\))
    printf '%s\n' "1"
    ;;
  attached_healthy:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\[\?LifecycleState==\'InService\'\ \&\&\ HealthStatus==\'Healthy\'\]\))
    printf '%s\n' "1"
    ;;
  attached_healthy:elbv2:describe-target-health:length\(TargetHealthDescriptions\[\?TargetHealth.State==\'healthy\'\]\))
    printf '%s\n' "1"
    ;;
  attached_healthy:elbv2:describe-target-health:length\(TargetHealthDescriptions\[\?TargetHealth.State==\'unused\'\]\))
    printf '%s\n' "0"
    ;;
  attached_healthy:elbv2:describe-target-health:length\(TargetHealthDescriptions\))
    printf '%s\n' "1"
    ;;
  attached_healthy:elbv2:describe-target-groups:length\(TargetGroups\[0\].LoadBalancerArns\))
    printf '%s\n' "1"
    ;;
  cache_seeded:elbv2:describe-listeners:*)
    if [[ -n "${listener_arn}" ]]; then
      printf '%s\n' "blue-https"
    else
      printf '%s\n' "https-listener"
    fi
    ;;
  cache_seeded:autoscaling:describe-auto-scaling-groups:AutoScalingGroups\[0\].Instances\[\].InstanceId)
    printf '%s\n' "i-blue-1"
    ;;
  cache_seeded:autoscaling:describe-auto-scaling-groups:AutoScalingGroups\[0\].AvailabilityZones\[0\])
    printf '%s\n' "us-east-1a"
    ;;
  cache_seeded:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\))
    printf '%s\n' "2"
    ;;
  cache_seeded:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\[\?LifecycleState==\'InService\'\]\))
    printf '%s\n' "2"
    ;;
  cache_seeded:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\[\?LifecycleState==\'InService\'\ \&\&\ HealthStatus==\'Healthy\'\]\))
    printf '%s\n' "2"
    ;;
  cache_seeded:ec2:describe-volumes:Volumes\[\].VolumeId)
    printf '%s\n' ""
    ;;
  cache_seeded:ec2:describe-volumes:Volumes\[\].\[VolumeId,\ Tags\[\?Key==\`CacheSlot\`\].Value\ \|\ \[0\]\])
    printf '%s\t%s\n' "vol-blue-1" "0"
    ;;
  cache_seeded:ec2:describe-volumes:length\(Volumes\))
    printf '%s\n' "0"
    ;;
  cache_seeded:ec2:create-snapshot:SnapshotId)
    printf '%s\n' "snap-blue-1"
    ;;
  cache_seeded:ec2:describe-snapshots:Snapshots\[\].SnapshotId)
    printf '%s\n' "snap-blue-1"
    ;;
  cache_seeded:ec2:describe-snapshots:Snapshots\[\].\[SnapshotId,\ Tags\[\?Key==\`SourceCacheSlot\`\].Value\ \|\ \[0\]\])
    printf '%s\t%s\n' "snap-blue-1" "0"
    ;;
  cache_seeded:ec2:describe-snapshots:Snapshots\[0\].VolumeSize)
    printf '%s\n' "1024"
    ;;
  cache_seeded:ec2:create-volume:VolumeId)
    printf '%s\n' "vol-green-created"
    ;;
  cache_seeded:ec2:wait:*)
    printf '%s\n' ""
    ;;
  cache_seeded:ec2:create-tags:*)
    printf '%s\n' ""
    ;;
  cache_seeded:elbv2:describe-target-health:length\(TargetHealthDescriptions\[\?TargetHealth.State==\'healthy\'\]\))
    printf '%s\n' "2"
    ;;
  cache_seeded:elbv2:describe-target-health:length\(TargetHealthDescriptions\[\?TargetHealth.State==\'unused\'\]\))
    printf '%s\n' "0"
    ;;
  cache_seeded:elbv2:describe-target-health:length\(TargetHealthDescriptions\))
    printf '%s\n' "2"
    ;;
  cache_seeded:elbv2:describe-target-groups:length\(TargetGroups\[0\].LoadBalancerArns\))
    printf '%s\n' "1"
    ;;
  *:autoscaling:update-auto-scaling-group:*)
    printf '%s\n' ""
    ;;
  *)
    echo "unexpected aws invocation for scenario=${scenario}: service=${service} command=${command} query=${query} asg=${asg_name} listener=${listener_arn} tg=${target_group_arn}" >&2
    exit 1
    ;;
esac
EOF
chmod +x "${mock_bin}/aws"

base_env=(
  PATH="${mock_bin}:${PATH}"
  AWS_REGION="us-east-1"
  ACTIVE_SLOT="blue"
  DESIRED_COUNT="1"
  BLUE_ASG_NAME="blue-asg"
  GREEN_ASG_NAME="green-asg"
  ACTIVE_HTTPS_TARGET_ARN="blue-https"
  ACTIVE_SSH_TARGET_ARN="blue-ssh"
  BLUE_HTTPS_TARGET_ARN="blue-https"
  GREEN_HTTPS_TARGET_ARN="green-https"
  LISTENER_HTTPS_ARN="https-listener"
  NLB_ARN="nlb-arn"
  BLUE_LAUNCH_TEMPLATE_VERSION="4"
  GREEN_LAUNCH_TEMPLATE_VERSION="9"
)

run_expect_fail() {
  local scenario="$1"

  if env TEST_SCENARIO="${scenario}" "${base_env[@]}" bash "${script_path}" >"${tmpdir}/${scenario}.out" 2>"${tmpdir}/${scenario}.err"; then
    echo "expected scenario ${scenario} to fail" >&2
    return 1
  fi
}

run_expect_success() {
  local scenario="$1"
  local active_slot="${2:-blue}"
  local active_https_tg="${3:-blue-https}"
  local active_ssh_tg="${4:-blue-ssh}"

  env \
    "${base_env[@]}" \
    TEST_SCENARIO="${scenario}" \
    ACTIVE_SLOT="${active_slot}" \
    ACTIVE_HTTPS_TARGET_ARN="${active_https_tg}" \
    ACTIVE_SSH_TARGET_ARN="${active_ssh_tg}" \
    bash "${script_path}" >"${tmpdir}/${scenario}.out" 2>"${tmpdir}/${scenario}.err"
}

run_expect_fail "stale_same_slot"
grep -q "Leave forgeproxy_active_slot unset for automatic alternation" "${tmpdir}/stale_same_slot.err"

run_expect_success "bootstrap_unattached"
grep -q "skipping health wait during bootstrap" "${tmpdir}/bootstrap_unattached.out"

run_expect_success "attached_healthy" "green" "green-https" "green-ssh"
grep -q "Active slot green is ready for cutover" "${tmpdir}/attached_healthy.out"

env \
  "${base_env[@]}" \
  TEST_SCENARIO="cache_seeded" \
  ACTIVE_SLOT="green" \
  CURRENT_LIVE_SLOT="blue" \
  DESIRED_COUNT="2" \
  MAX_COUNT="4" \
  ACTIVE_HTTPS_TARGET_ARN="green-https" \
  ACTIVE_SSH_TARGET_ARN="green-ssh" \
  CACHE_EBS_ENABLED="true" \
  CACHE_VOLUME_GB="4096" \
  bash "${script_path}" >"${tmpdir}/cache_seeded.out" 2>"${tmpdir}/cache_seeded.err"
grep -q "Preparing dedicated cache EBS seed volumes for target slot green" "${tmpdir}/cache_seeded.out"
grep -q "Creating live cache snapshot from blue volume vol-blue-1" "${tmpdir}/cache_seeded.out"
grep -q "Created green cache volume vol-green-created for cache slot 1 from snap-blue-1" "${tmpdir}/cache_seeded.out"

echo "forgeproxy-rollout-prepare tests passed"
