import unittest

from defenseclaw.commands.cmd_upgrade import _api_bind_host
from defenseclaw.config import Config, GatewayConfig, GuardrailConfig, OpenShellConfig


class TestUpgradeAPIBindHost(unittest.TestCase):
    def test_defaults_to_loopback(self):
        cfg = Config()
        self.assertEqual(_api_bind_host(cfg), "127.0.0.1")

    def test_prefers_gateway_api_bind(self):
        cfg = Config(gateway=GatewayConfig(api_bind="10.0.0.8"))
        self.assertEqual(_api_bind_host(cfg), "10.0.0.8")

    def test_uses_guardrail_host_in_standalone_mode(self):
        cfg = Config(
            openshell=OpenShellConfig(mode="standalone"),
            guardrail=GuardrailConfig(host="192.168.65.2"),
        )
        self.assertEqual(_api_bind_host(cfg), "192.168.65.2")
