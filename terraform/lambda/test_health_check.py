import importlib
import os
import unittest
from unittest import mock


def load_health_check(target_instance_private_ips=None):
    env = {
        "ASG_NAME_PREFIX": "forgeproxy-forgeproxy-",
        "AWS_DEFAULT_REGION": "us-east-1",
        "HEALTH_CHECK_STATE_TABLE": "health-state",
        "OBSERVATION_INTERVAL_SECS": "60",
        "READYZ_HOST": "proxy.example.com",
        "READYZ_TIMEOUT_SECS": "5",
        "TARGET_GROUP_ARNS": '{"https":"arn:https","ssh":"arn:ssh"}',
        "TARGET_INSTANCE_PRIVATE_IPS": (
            target_instance_private_ips
            or '{"i-warmup":"10.0.1.10","i-old":"10.0.1.11","i-timeout":"10.0.1.12"}'
        ),
        "TERMINATION_THRESHOLD": "10",
    }
    with mock.patch.dict(os.environ, env, clear=False):
        with mock.patch("boto3.client"), mock.patch("boto3.resource"):
            return importlib.reload(importlib.import_module("health_check"))


class WarmupSuppressionTest(unittest.TestCase):
    def setUp(self):
        self.health_check = load_health_check()
        self.readyz_503 = {
            "https": {
                "state": "unhealthy",
                "reason": "Target.ResponseCodeMismatch",
                "description": "Health checks failed with these codes: [503]",
            },
            "ssh": {"state": "healthy", "reason": "", "description": ""},
        }

    def test_suppresses_readyz_503_when_direct_body_reports_prewarm(self):
        with mock.patch.object(
            self.health_check,
            "fetch_readyz",
            return_value=(503, "forgeproxy repository pre-warm is not complete\n"),
        ):
            self.assertTrue(
                self.health_check.is_startup_warmup(
                    "i-warmup",
                    self.readyz_503,
                )
            )

    def test_does_not_suppress_readyz_503_without_prewarm_body(self):
        with mock.patch.object(
            self.health_check,
            "fetch_readyz",
            return_value=(503, "upstream dependency failed\n"),
        ):
            self.assertFalse(
                self.health_check.is_startup_warmup(
                    "i-old",
                    self.readyz_503,
                )
            )

    def test_does_not_suppress_non_readyz_failure(self):
        states = {
            "https": {
                "state": "unhealthy",
                "reason": "Target.Timeout",
                "description": "Request timed out",
            }
        }

        with mock.patch.object(self.health_check, "fetch_readyz") as fetch_readyz:
            self.assertFalse(
                self.health_check.is_startup_warmup(
                    "i-timeout",
                    states,
                )
            )
            fetch_readyz.assert_not_called()

    def test_does_not_suppress_when_private_ip_is_missing(self):
        with mock.patch.object(self.health_check, "fetch_readyz") as fetch_readyz:
            self.assertFalse(
                self.health_check.is_startup_warmup(
                    "i-missing",
                    self.readyz_503,
                )
            )
            fetch_readyz.assert_not_called()

    def test_supports_private_ip_list_when_instance_id_map_is_unavailable(self):
        health_check = load_health_check('["10.0.1.10","10.0.1.11"]')

        with mock.patch.object(
            health_check,
            "fetch_readyz",
            side_effect=[
                (503, "upstream dependency failed\n"),
                (503, "forgeproxy repository pre-warm is not complete\n"),
            ],
        ) as fetch_readyz:
            self.assertTrue(
                health_check.is_startup_warmup(
                    "i-without-map",
                    self.readyz_503,
                )
            )
            self.assertEqual(fetch_readyz.call_count, 2)

    def test_json_prewarm_detail_is_supported(self):
        body = (
            '{"checks":{"prewarm":{"ok":false,'
            '"detail":"startup repository pre-warm is still running"}}}'
        )

        self.assertTrue(
            self.health_check.response_indicates_startup_warmup(503, body)
        )


if __name__ == "__main__":
    unittest.main()
