import json
import logging
import os
import ssl
import time
from decimal import Decimal
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import boto3

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)

ASG_NAME_PREFIX = os.environ["ASG_NAME_PREFIX"]
STATE_TABLE = os.environ["HEALTH_CHECK_STATE_TABLE"]
TARGET_GROUP_ARNS = json.loads(os.environ["TARGET_GROUP_ARNS"])
RAW_TARGET_INSTANCE_PRIVATE_IPS = json.loads(os.environ["TARGET_INSTANCE_PRIVATE_IPS"])
TERMINATION_THRESHOLD = int(os.environ["TERMINATION_THRESHOLD"])
OBSERVATION_INTERVAL_SECS = int(os.environ["OBSERVATION_INTERVAL_SECS"])
READYZ_HOST = os.environ.get("READYZ_HOST", "")
READYZ_TIMEOUT_SECS = int(os.environ.get("READYZ_TIMEOUT_SECS", "5"))

ELBV2 = boto3.client("elbv2")
AUTOSCALING = boto3.client("autoscaling")
DYNAMODB = boto3.resource("dynamodb")
TABLE = DYNAMODB.Table(STATE_TABLE)
TLS_CONTEXT = ssl._create_unverified_context()

if isinstance(RAW_TARGET_INSTANCE_PRIVATE_IPS, dict):
    TARGET_INSTANCE_PRIVATE_IP_BY_ID = {
        str(instance_id): str(instance_ip)
        for instance_id, instance_ip in RAW_TARGET_INSTANCE_PRIVATE_IPS.items()
        if instance_id and instance_ip
    }
    TARGET_INSTANCE_PRIVATE_IPS = list(TARGET_INSTANCE_PRIVATE_IP_BY_ID.values())
elif isinstance(RAW_TARGET_INSTANCE_PRIVATE_IPS, list):
    TARGET_INSTANCE_PRIVATE_IP_BY_ID = {}
    TARGET_INSTANCE_PRIVATE_IPS = [
        str(instance_ip)
        for instance_ip in RAW_TARGET_INSTANCE_PRIVATE_IPS
        if instance_ip
    ]
else:
    TARGET_INSTANCE_PRIVATE_IP_BY_ID = {}
    TARGET_INSTANCE_PRIVATE_IPS = []

UNHEALTHY_STATES = {"unhealthy"}
RUNNABLE_LIFECYCLE_STATES = {"InService"}
PENDING_LIFECYCLE_PREFIXES = ("Pending",)
TERMINATING_LIFECYCLE_PREFIXES = ("Terminating",)


def handler(_event, _context):
    target_health = describe_target_health()
    instance_ids = sorted(target_health.keys())
    asg_instances = describe_asg_instances(instance_ids)

    summary = {
        "healthy": 0,
        "unhealthy": 0,
        "reset": 0,
        "skipped": 0,
        "warmup": 0,
        "reported_unhealthy_to_asg": 0,
    }

    for instance_id in instance_ids:
        asg_instance = asg_instances.get(instance_id)
        if not should_evaluate_instance(instance_id, asg_instance):
            delete_counter(instance_id)
            summary["skipped"] += 1
            continue

        states = target_health[instance_id]
        if is_unhealthy(states):
            if is_startup_warmup(
                instance_id,
                states,
            ):
                delete_counter(instance_id)
                summary["warmup"] += 1
                continue

            summary["unhealthy"] += 1
            count = increment_counter(instance_id, states)
            if count >= TERMINATION_THRESHOLD:
                mark_instance_unhealthy(instance_id)
                summary["reported_unhealthy_to_asg"] += 1
        else:
            if is_healthy(states):
                summary["healthy"] += 1
            else:
                summary["reset"] += 1
            delete_counter(instance_id)

    LOG.info("forgeproxy health-check summary: %s", json.dumps(summary, sort_keys=True))
    return summary


def describe_target_health():
    by_instance = {}
    for name, target_group_arn in TARGET_GROUP_ARNS.items():
        response = ELBV2.describe_target_health(TargetGroupArn=target_group_arn)
        for description in response.get("TargetHealthDescriptions", []):
            target = description.get("Target", {})
            instance_id = target.get("Id")
            if not instance_id:
                continue
            health = description.get("TargetHealth", {})
            by_instance.setdefault(instance_id, {})[name] = {
                "state": health.get("State", "unknown"),
                "reason": health.get("Reason", ""),
                "description": health.get("Description", ""),
            }
    return by_instance


def describe_asg_instances(instance_ids):
    if not instance_ids:
        return {}

    instances = {}
    for batch in chunks(instance_ids, 50):
        response = AUTOSCALING.describe_auto_scaling_instances(InstanceIds=batch)
        for instance in response.get("AutoScalingInstances", []):
            instances[instance["InstanceId"]] = instance
    return instances


def chunks(values, size):
    for index in range(0, len(values), size):
        yield values[index : index + size]


def should_evaluate_instance(instance_id, asg_instance):
    if asg_instance is None:
        LOG.info("Skipping %s: target is not an Auto Scaling instance", instance_id)
        return False

    asg_name = asg_instance.get("AutoScalingGroupName", "")
    if not asg_name.startswith(ASG_NAME_PREFIX):
        LOG.info("Skipping %s: ASG %s does not match %s*", instance_id, asg_name, ASG_NAME_PREFIX)
        return False

    lifecycle_state = asg_instance.get("LifecycleState", "")
    if lifecycle_state in RUNNABLE_LIFECYCLE_STATES:
        health_status = asg_instance.get("HealthStatus", "")
        if health_status != "Healthy":
            LOG.info("Skipping %s: ASG health status is %s", instance_id, health_status)
            return False
        return True

    if lifecycle_state.startswith(PENDING_LIFECYCLE_PREFIXES):
        LOG.info("Skipping %s: lifecycle state is %s", instance_id, lifecycle_state)
        return False

    if lifecycle_state.startswith(TERMINATING_LIFECYCLE_PREFIXES):
        LOG.info("Skipping %s: lifecycle state is %s", instance_id, lifecycle_state)
        return False

    LOG.info("Skipping %s: lifecycle state is %s", instance_id, lifecycle_state)
    return False


def is_unhealthy(states):
    return any(target["state"] in UNHEALTHY_STATES for target in states.values())


def is_startup_warmup(instance_id, states):
    if not has_readyz_503(states):
        return False

    instance_ips = target_readyz_ips(instance_id)
    if not instance_ips:
        LOG.warning("Cannot evaluate warm-up state for %s: private IP missing", instance_id)
        return False

    for instance_ip in instance_ips:
        status, body = fetch_readyz(instance_ip)
        warmup = response_indicates_startup_warmup(status, body)
        if not warmup:
            continue

        LOG.info(
            "Suppressing unhealthy ASG report for %s because direct /readyz on %s reports startup warm-up: %s",
            instance_id,
            instance_ip,
            json.dumps(states, sort_keys=True),
        )
        return True

    return False


def target_readyz_ips(instance_id):
    instance_ip = TARGET_INSTANCE_PRIVATE_IP_BY_ID.get(instance_id)
    if instance_ip:
        return [instance_ip]
    if TARGET_INSTANCE_PRIVATE_IP_BY_ID:
        return []
    return TARGET_INSTANCE_PRIVATE_IPS


def has_readyz_503(states):
    return any(is_readyz_503(target) for target in states.values())


def is_readyz_503(target):
    return (
        target.get("state") == "unhealthy"
        and target.get("reason") == "Target.ResponseCodeMismatch"
        and "503" in target.get("description", "")
    )


def fetch_readyz(instance_ip):
    url = f"https://{instance_ip}/readyz"
    headers = {}
    if READYZ_HOST:
        headers["Host"] = READYZ_HOST
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=READYZ_TIMEOUT_SECS, context=TLS_CONTEXT) as response:
            return response.status, response.read(4096).decode("utf-8", errors="replace")
    except HTTPError as error:
        return error.code, error.read(4096).decode("utf-8", errors="replace")
    except (TimeoutError, URLError, OSError) as error:
        LOG.warning("Direct /readyz probe failed for %s: %s", instance_ip, error)
        return None, ""


def response_indicates_startup_warmup(status, body):
    if status != 503:
        return False

    normalized_body = body.lower()
    if "pre-warm is not complete" in normalized_body:
        return True

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return False

    prewarm = payload.get("checks", {}).get("prewarm", {})
    detail = str(prewarm.get("detail", "")).lower()
    return prewarm.get("ok") is False and (
        "pre-warm" in detail or "prewarm" in detail
    )


def is_healthy(states):
    return set(states.keys()) == set(TARGET_GROUP_ARNS.keys()) and all(
        target["state"] == "healthy" for target in states.values()
    )


def increment_counter(instance_id, states):
    now = int(time.time())
    ttl = now + max(OBSERVATION_INTERVAL_SECS * TERMINATION_THRESHOLD * 3, 3600)
    current = TABLE.get_item(Key={"instance_id": instance_id}).get("Item", {})
    count = int(current.get("failure_count", 0)) + 1

    TABLE.put_item(
        Item={
            "instance_id": instance_id,
            "failure_count": Decimal(count),
            "first_seen_at": Decimal(int(current.get("first_seen_at", now))),
            "last_seen_at": Decimal(now),
            "expires_at": Decimal(ttl),
            "target_states": json.dumps(states, sort_keys=True),
        }
    )

    LOG.info(
        "Observed unhealthy target state for %s (%s/%s): %s",
        instance_id,
        count,
        TERMINATION_THRESHOLD,
        json.dumps(states, sort_keys=True),
    )
    return count


def delete_counter(instance_id):
    TABLE.delete_item(Key={"instance_id": instance_id})


def mark_instance_unhealthy(instance_id):
    LOG.warning(
        "Reporting %s unhealthy to Auto Scaling after %s consecutive unhealthy observations",
        instance_id,
        TERMINATION_THRESHOLD,
    )
    AUTOSCALING.set_instance_health(
        InstanceId=instance_id,
        HealthStatus="Unhealthy",
        ShouldRespectGracePeriod=True,
    )
