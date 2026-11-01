# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""GAP-1610: Doctor names a kept Codex exporter that looks like an earlier DefenseClaw render.

OSS Windows 1.0.2 -> 1.0.5: setup codex put back a pre-setup [otel] exporter
(127.0.0.1:19010, both x-defenseclaw markers, a bearer no file records).
The ownership rule keeps it (GAP-1511); Doctor warns with the fields and the
manual step (LEAD DECISION 05:36, option (b)) and never fails on it.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from defenseclaw.commands.cmd_doctor import _check_codex_otel_alignment, _DoctorResult

_BEARER = "e" * 64


def _exporter(port: int, *, source: str = "codex", bearer: bool = True, host: str = "127.0.0.1") -> str:
    body = "[otel]\nenvironment = 'windows'\n"
    for key, path in (("exporter", "logs"), ("metrics_exporter", "metrics"), ("trace_exporter", "traces")):
        body += f"[otel.{key}.otlp-http]\nendpoint = 'http://{host}:{port}/v1/{path}'\nprotocol = 'json'\n"
        body += f"[otel.{key}.otlp-http.headers]\n"
        if bearer:
            body += f"authorization = 'Bearer {_BEARER}'\n"
        body += "x-defenseclaw-client = 'codex-otel/1.0'\n"
        if source:
            body += f"x-defenseclaw-source = '{source}'\n"
    return body


class TestDoctorWarnsOnAKeptMarkedCodexExporter(unittest.TestCase):
    def setUp(self) -> None:
        trusted = patch(
            "defenseclaw.commands.cmd_doctor._trusted_gateway_listener",
            return_value=SimpleNamespace(trusted=True, detail="verified"),
        )
        trusted.start()
        self.addCleanup(trusted.stop)

    def _run(self, body: str, *, token: str = "") -> list[dict]:
        payload = {"runtime": {"environment": "windows"}, "health": {"telemetry": {"state": "running"}}}
        with (
            tempfile.TemporaryDirectory() as home,
            tempfile.TemporaryDirectory() as data_dir,
            patch.dict(os.environ, {"CODEX_HOME": home}, clear=False),
            patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(200, json.dumps(payload))),
        ):
            Path(data_dir, "hooks").mkdir()
            if token:
                Path(data_dir, "hooks", ".otlp-codex.token").write_text(token + "\n", encoding="ascii")
            Path(home, "config.toml").write_text("[features]\nhooks = true\n" + body, encoding="utf-8")
            cfg = MagicMock()
            cfg.environment = "windows"
            cfg.data_dir = data_dir
            cfg.gateway.api_port = 18970
            cfg.gateway.resolved_token.return_value = "test-gateway-token"
            result = _DoctorResult()
            _check_codex_otel_alignment(cfg, result)
        return result.checks

    def test_a_restored_pre_setup_exporter_on_a_retired_port_is_named_with_the_manual_step(self) -> None:
        checks = self._run(_exporter(19010))
        self.assertEqual(checks[0]["status"], "pass", checks)
        warns = [c for c in checks if c["status"] == "warn" and c["label"] == "Codex OTel ownership"]
        self.assertEqual(len(warns), 1, checks)
        detail = warns[0]["detail"] + " " + str(warns[0].get("remediation", ""))
        for text in ("otel.exporter", "otel.metrics_exporter", "otel.trace_exporter", "127.0.0.1:19010", "delete the"):
            self.assertIn(text, detail)
        self.assertNotIn(_BEARER, detail)
        self.assertNotIn("fail", [c["status"] for c in checks])

    def test_other_shapes_get_no_warning(self) -> None:
        for name, body, token in (
            ("operator collector without a bearer", _exporter(4318, bearer=False), ""),
            ("one marker only", _exporter(19010, source=""), ""),
            ("a remote collector", _exporter(4318, host="collector.example.test"), ""),
            ("the gateway's own port", _exporter(18970), ""),
        ):
            with self.subTest(name=name):
                checks = self._run(body, token=token)
                self.assertFalse(
                    [c for c in checks if c["status"] == "warn" and c["label"] == "Codex OTel ownership"], checks
                )

    def test_a_known_credential_still_fails_and_is_not_also_warned(self) -> None:
        checks = self._run(_exporter(19010), token=_BEARER)
        self.assertEqual(checks[0]["status"], "fail", checks)
        self.assertFalse([c for c in checks if c["status"] == "warn" and c["label"] == "Codex OTel ownership"], checks)


if __name__ == "__main__":
    unittest.main()
