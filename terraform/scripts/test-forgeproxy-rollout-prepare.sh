#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${repo_root}/terraform/scripts/forgeproxy-rollout-prepare.sh"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

mock_bin="${tmpdir}/bin"
mkdir -p "${mock_bin}" "${tmpdir}/state"

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
desired_capacity=""
waiter_name=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --query)
      query="$2"
      shift 2
      ;;
    --auto-scaling-group-name|--auto-scaling-group-names)
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
    --desired-capacity)
      desired_capacity="$2"
      shift 2
      ;;
    --output)
      shift 2
      ;;
    *)
      if [[ "${service}" == "ec2" && "${command}" == "wait" && -z "${waiter_name}" ]]; then
        waiter_name="$1"
      fi
      shift
      ;;
  esac
done

asg_state_file() {
  local name="$1"
  printf '%s/%s.count\n' "${TEST_STATE_DIR:?TEST_STATE_DIR is required}" "${name}"
}

asg_count_for() {
  local name="$1"
  local default_count="$2"
  local state_file
  state_file="$(asg_state_file "${name}")"
  if [[ -f "${state_file}" ]]; then
    cat "${state_file}"
  else
    printf '%s\n' "${default_count}"
  fi
}

counter_file() {
  local name="$1"
  printf '%s/%s.counter\n' "${TEST_STATE_DIR:?TEST_STATE_DIR is required}" "${name}"
}

next_counter_value() {
  local name="$1"
  local state_file current_value
  state_file="$(counter_file "${name}")"
  if [[ -f "${state_file}" ]]; then
    current_value="$(cat "${state_file}")"
  else
    current_value="0"
  fi
  printf '%s\n' "${current_value}"
  printf '%s\n' "$(( current_value + 1 ))" >"${state_file}"
}

case "${scenario}:${service}:${command}:${query}" in
  target_diagnostics:elbv2:describe-listeners:*)
    if [[ -n "${listener_arn}" ]]; then
      printf '%s\n' "blue-https"
    else
      printf '%s\n' "https-listener"
    fi
    ;;
  target_diagnostics:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\))
    if [[ "${asg_name}" == "green-asg" ]]; then
      asg_count_for "${asg_name}" "0"
    else
      printf '%s\n' "1"
    fi
    ;;
  target_diagnostics:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\[\?LifecycleState==\'InService\'\]\))
    asg_count_for "${asg_name}" "1"
    ;;
  target_diagnostics:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\[\?LifecycleState==\'InService\'\ \&\&\ HealthStatus==\'Healthy\'\]\))
    asg_count_for "${asg_name}" "1"
    ;;
  target_diagnostics:elbv2:describe-target-health:length\(TargetHealthDescriptions\[\?TargetHealth.State==\'healthy\'\]\))
    if [[ "${target_group_arn}" == "green-https" ]]; then
      if [[ "$(next_counter_value "green-https-healthy")" == "0" ]]; then
        printf '%s\n' "0"
      else
        printf '%s\n' "1"
      fi
    else
      printf '%s\n' "1"
    fi
    ;;
  target_diagnostics:elbv2:describe-target-health:length\(TargetHealthDescriptions\[\?TargetHealth.State==\'unused\'\]\))
    printf '%s\n' "0"
    ;;
  target_diagnostics:elbv2:describe-target-health:length\(TargetHealthDescriptions\))
    printf '%s\n' "1"
    ;;
  target_diagnostics:elbv2:describe-target-health:TargetHealthDescriptions\[\].\{Target:Target.Id,Port:Target.Port,State:TargetHealth.State,Reason:TargetHealth.Reason,Description:TargetHealth.Description\})
    printf '%s\n' "i-unhealthy-target 443 unhealthy Target.ResponseCodeMismatch Health checks failed with these codes: [503]"
    ;;
  target_diagnostics:elbv2:describe-target-groups:length\(TargetGroups\[0\].LoadBalancerArns\))
    printf '%s\n' "1"
    ;;
  stale_standby:elbv2:describe-listeners:*)
    if [[ -n "${listener_arn}" ]]; then
      printf '%s\n' "blue-https"
    else
      printf '%s\n' "https-listener"
    fi
    ;;
  stale_standby:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\))
    if [[ "${asg_name}" == "green-asg" ]]; then
      asg_count_for "${asg_name}" "2"
    else
      printf '%s\n' "1"
    fi
    ;;
  stale_standby:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\[\?LifecycleState==\'InService\'\]\))
    asg_count_for "${asg_name}" "1"
    ;;
  stale_standby:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\[\?LifecycleState==\'InService\'\ \&\&\ HealthStatus==\'Healthy\'\]\))
    asg_count_for "${asg_name}" "1"
    ;;
  stale_standby:elbv2:describe-target-health:length\(TargetHealthDescriptions\[\?TargetHealth.State==\'healthy\'\]\))
    printf '%s\n' "1"
    ;;
  stale_standby:elbv2:describe-target-health:length\(TargetHealthDescriptions\[\?TargetHealth.State==\'unused\'\]\))
    printf '%s\n' "0"
    ;;
  stale_standby:elbv2:describe-target-health:length\(TargetHealthDescriptions\))
    printf '%s\n' "1"
    ;;
  stale_standby:elbv2:describe-target-groups:length\(TargetGroups\[0\].LoadBalancerArns\))
    printf '%s\n' "1"
    ;;
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
    if [[ "${asg_name}" == "blue-asg" ]]; then
      asg_count_for "${asg_name}" "1"
    else
      printf '%s\n' "1"
    fi
    ;;
  bootstrap_unattached:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\[\?LifecycleState==\'InService\'\]\))
    if [[ "${asg_name}" == "blue-asg" ]]; then
      asg_count_for "${asg_name}" "1"
    else
      printf '%s\n' "1"
    fi
    ;;
  bootstrap_unattached:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\[\?LifecycleState==\'InService\'\ \&\&\ HealthStatus==\'Healthy\'\]\))
    if [[ "${asg_name}" == "blue-asg" ]]; then
      asg_count_for "${asg_name}" "1"
    else
      printf '%s\n' "1"
    fi
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
    if [[ "${asg_name}" == "green-asg" ]]; then
      asg_count_for "${asg_name}" "2"
    else
      printf '%s\n' "2"
    fi
    ;;
  cache_seeded:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\[\?LifecycleState==\'InService\'\]\))
    if [[ "${asg_name}" == "green-asg" ]]; then
      asg_count_for "${asg_name}" "2"
    else
      printf '%s\n' "2"
    fi
    ;;
  cache_seeded:autoscaling:describe-auto-scaling-groups:length\(AutoScalingGroups\[0\].Instances\[\?LifecycleState==\'InService\'\ \&\&\ HealthStatus==\'Healthy\'\]\))
    if [[ "${asg_name}" == "green-asg" ]]; then
      asg_count_for "${asg_name}" "2"
    else
      printf '%s\n' "2"
    fi
    ;;
  cache_seeded:ec2:describe-volumes:Volumes\[\].VolumeId)
    printf '%s\n' ""
    ;;
  cache_seeded:ec2:describe-volumes:Volumes\[\].\[VolumeId,\ Tags\[\?Key==\`CacheSlot\`\].Value\ \|\ \[0\]\])
    printf '%s\t%s\n' "vol-blue-1" "dynamic"
    printf '%s\t%s\n' "vol-blue-2" "dynamic"
    ;;
  cache_seeded:ec2:describe-volumes:length\(Volumes\))
    printf '%s\n' "0"
    ;;
  cache_seeded:ec2:create-snapshot:SnapshotId)
    if [[ "$(next_counter_value "create-snapshot")" == "0" ]]; then
      printf '%s\n' "snap-blue-1"
    else
      printf '%s\n' "snap-blue-2"
    fi
    ;;
  cache_seeded:ec2:describe-snapshots:Snapshots\[\].SnapshotId)
    printf '%s\t%s\n' "snap-blue-1" "snap-blue-2"
    ;;
  cache_seeded:ec2:describe-snapshots:Snapshots\[\].\[SnapshotId,\ State,\ Progress\])
    printf '%s\t%s\t%s\n' "snap-blue-1" "completed" "100%"
    printf '%s\t%s\t%s\n' "snap-blue-2" "completed" "100%"
    ;;
  cache_seeded:ec2:describe-snapshots:Snapshots\[\].\[SnapshotId,\ Tags\[\?Key==\`SourceCacheSlot\`\].Value\ \|\ \[0\]\])
    printf '%s\t%s\n' "snap-blue-1" "dynamic"
    printf '%s\t%s\n' "snap-blue-2" "dynamic"
    ;;
  cache_seeded:ec2:describe-snapshots:Snapshots\[\].\[SnapshotId,\ Tags\[\?Key==\`SourceVolumeId\`\].Value\ \|\ \[0\],\ Tags\[\?Key==\`SourceCacheSlot\`\].Value\ \|\ \[0\]\])
    printf '%s\t%s\t%s\n' "snap-blue-1" "vol-blue-1" "dynamic"
    printf '%s\t%s\t%s\n' "snap-blue-2" "vol-blue-2" "dynamic"
    ;;
  cache_seeded:ec2:describe-snapshots:Snapshots\[\].\[SnapshotId,\ Tags\[\?Key==\`SourceVolumeId\`\].Value\ \|\ \[0\],\ Tags\[\?Key==\`SourceCacheSlot\`\].Value\ \|\ \[0\],\ Tags\[\?Key==\`CreatedAtUnix\`\].Value\ \|\ \[0\]\])
    printf '%s\t%s\t%s\t%s\n' "snap-blue-1" "vol-blue-1" "dynamic" "200"
    printf '%s\t%s\t%s\t%s\n' "snap-blue-2" "vol-blue-2" "dynamic" "200"
    printf '%s\t%s\t%s\t%s\n' "snap-old-1" "vol-blue-1" "dynamic" "100"
    printf '%s\t%s\t%s\t%s\n' "snap-old-2" "vol-blue-2" "dynamic" "100"
    ;;
  cache_seeded:ec2:describe-snapshots:Snapshots\[0\].VolumeSize)
    printf '%s\n' "1024"
    ;;
  cache_seeded:ec2:delete-snapshot:*)
    printf '%s\n' ""
    ;;
  cache_seeded:ec2:create-volume:VolumeId)
    printf '%s\n' "vol-green-created"
    ;;
  cache_seeded:ec2:wait:*)
    if [[ "${waiter_name}" == "snapshot-completed" ]]; then
      echo "unexpected built-in snapshot waiter" >&2
      exit 1
    fi
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
  *:autoscaling:describe-auto-scaling-groups:AutoScalingGroups\[0\].Instances\[\].\{Id:InstanceId,State:LifecycleState,Health:HealthStatus,AZ:AvailabilityZone,LT:LaunchTemplate.Version,Protected:ProtectedFromScaleIn\})
    printf '%s\n' "i-mock InService Healthy us-east-1a 1 false"
    ;;
  *:autoscaling:describe-scaling-activities:Activities\[\].\{Start:StartTime,Status:StatusCode,Progress:Progress,Description:Description,Cause:Cause,StatusMessage:StatusMessage\})
    printf '%s\n' "2026-01-01T00:00:00Z Successful 100 mock-scaling-activity mock-cause mock-status"
    ;;
  *:elbv2:describe-target-health:TargetHealthDescriptions\[\].\{Target:Target.Id,Port:Target.Port,State:TargetHealth.State,Reason:TargetHealth.Reason,Description:TargetHealth.Description\})
    printf '%s\n' "i-mock 443 initial Elb.InitialHealthChecking Initial health checks in progress"
    ;;
  *:autoscaling:update-auto-scaling-group:*)
    if [[ -n "${desired_capacity}" ]]; then
      printf '%s\n' "${desired_capacity}" >"$(asg_state_file "${asg_name}")"
    fi
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
  TEST_STATE_DIR="${tmpdir}/state"
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

  rm -f "${tmpdir}/state"/*
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

  rm -f "${tmpdir}/state"/*
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

run_expect_success "stale_standby" "green" "green-https" "green-ssh"
grep -q "Resetting standby target slot green (green-asg) from 2 stale instances to zero before rollout" "${tmpdir}/stale_standby.out"
grep -q "Scaling active slot green (green-asg) to 1 instances" "${tmpdir}/stale_standby.out"

run_expect_success "target_diagnostics" "green" "green-https" "green-ssh"
grep -q "HTTPS target group target health details" "${tmpdir}/target_diagnostics.out"
grep -q "Target.ResponseCodeMismatch" "${tmpdir}/target_diagnostics.out"

rm -f "${tmpdir}/state"/*
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
grep -q "Creating live cache snapshot from blue volume vol-blue-2" "${tmpdir}/cache_seeded.out"
grep -q "Deleting old green cache seed snapshot snap-old-1" "${tmpdir}/cache_seeded.out"
grep -q "Deleting old green cache seed snapshot snap-old-2" "${tmpdir}/cache_seeded.out"
grep -q "Created green cache volume vol-green-created for cache slot 0 from snap-blue-1" "${tmpdir}/cache_seeded.out"
grep -q "Created green cache volume vol-green-created for cache slot 1 from snap-blue-2" "${tmpdir}/cache_seeded.out"

echo "forgeproxy-rollout-prepare tests passed"
