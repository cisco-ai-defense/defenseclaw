# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Setup names the next step for the cause of an unread agent version (GAP-2479).

A version probe that timed out, or an agent that did not run, got only the
exploratory drift override as advice. Each cause now names its own step, as
the gateway's refusal does; an untrusted install path keeps its own hints.
"""

import os
import unittest
from unittest.mock import MagicMock, patch

from defenseclaw.commands import cmd_setup
from defenseclaw.inventory import agent_discovery as ad

NO_DRIFT = {"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT": ""}


def _unversioned(connector: str, error: str) -> ad.AgentDiscovery:
    signal = ad.AgentSignal(
        name=connector,
        installed=True,
        config_path="",
        binary_path=f"/usr/local/bin/{connector}",
        version="",
        error=error,
    )
    return ad.AgentDiscovery(scanned_at="t", agents={connector: signal}, cache_hit=False)


class UnreadVersionNextStepTests(unittest.TestCase):
    def _advice(self, error: str, mode: str) -> tuple[bool, str]:
        ux = MagicMock()
        with patch.dict(os.environ, NO_DRIFT, clear=False), patch.object(cmd_setup, "ux", ux):
            ok = cmd_setup._check_connector_version_supported_for_setup(
                "claudecode",
                mode=mode,
                emit=True,
                _allow_prompt=False,
                _discovery=_unversioned("claudecode", error),
            )
        lines = [str(call.args[0]) for name in ("err", "warn", "subhead") for call in getattr(ux, name).call_args_list]
        return ok, "\n".join(lines)

    def test_timed_out_probe_names_a_start_once_step(self):
        for mode in ("action", "observe"):
            with self.subTest(mode=mode):
                ok, text = self._advice(f"/usr/local/bin/claude: {ad.VERSION_PROBE_TIMED_OUT}", mode)
                self.assertEqual(ok, mode == "observe")
                self.assertIn("did not answer its version probe in time", text)
                self.assertIn("start it once from this account", text)
                self.assertNotIn("putting its runtime on PATH", text)

    def test_agent_that_did_not_run_names_the_runtime_step(self):
        ok, text = self._advice("version probe exited 127: /usr/bin/env: node: No such file or directory", "action")
        self.assertFalse(ok)
        self.assertIn("putting its runtime on PATH", text)
        self.assertNotIn("start it once", text)

    def test_untrusted_path_keeps_its_own_hints_only(self):
        hints = MagicMock()
        with patch.object(cmd_setup, "_emit_untrusted_prefix_setup_hints", hints):
            ok, text = self._advice(ad.UNTRUSTED_PREFIX_ERROR, "action")
        self.assertFalse(ok)
        hints.assert_called_once()
        self.assertNotIn("start it once", text)
        self.assertNotIn("putting its runtime on PATH", text)


if __name__ == "__main__":
    unittest.main()
