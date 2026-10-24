# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Setup refuses an agent version with no hook contract in both modes (GAP-0554).

Observe-mode setup warned "Continuing in observe mode", then the gateway
refused the connector on restart and stayed down for every connector.
"""

import os
import unittest
from unittest.mock import patch

from defenseclaw.commands import cmd_setup
from defenseclaw.connector_contracts import STATUS_UNKNOWN, resolve_connector_contract
from defenseclaw.inventory import agent_discovery as ad


def _discovery(connector: str, version: str) -> ad.AgentDiscovery:
    signal = ad.AgentSignal(
        name=connector,
        installed=True,
        config_path="",
        binary_path=f"/usr/local/bin/{connector}",
        version=version,
        error="",
    )
    return ad.AgentDiscovery(scanned_at="t", agents={connector: signal}, cache_hit=False)


class NoContractVersionGateTests(unittest.TestCase):
    def _check(self, connector: str, version: str, mode: str, env: dict[str, str]) -> bool:
        with patch.dict(os.environ, env, clear=False):
            return cmd_setup._check_connector_version_supported_for_setup(
                connector,
                mode=mode,
                emit=False,
                _allow_prompt=False,
                _discovery=_discovery(connector, version),
            )

    def test_versions_below_every_contract_are_refused_in_both_modes(self):
        no_drift = {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": ""}
        # The T6 repro: a Claude Code below claudecode-hooks-v1.
        version = "2.1.100 (Claude Code)"
        self.assertEqual(resolve_connector_contract("claudecode", version).status, STATUS_UNKNOWN)
        for mode in ("observe", "action"):
            with self.subTest(mode=mode):
                self.assertFalse(self._check("claudecode", version, mode, no_drift))
        # The exploratory override still lets setup continue.
        self.assertTrue(self._check("claudecode", version, "observe", {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": "1"}))

    def test_every_hook_connector_is_refused_in_observe_mode(self):
        for connector in sorted(cmd_setup._CONNECTOR_META):
            version = "0.0.1"
            if resolve_connector_contract(connector, version).status != STATUS_UNKNOWN:
                continue
            with self.subTest(connector=connector):
                self.assertFalse(
                    self._check(connector, version, "observe", {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": ""})
                )


if __name__ == "__main__":
    unittest.main()
