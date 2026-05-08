# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands.cmd_doctor import (
    _ANTHROPIC_DEFAULT_PROBE_MODEL,
    _anthropic_probe_model,
    _bedrock_region,
    _check_guardrail_proxy,
    _check_hilt_support,
    _check_llm_api_key,
    _check_sidecar,
    _DoctorResult,
    _probe_splunk_hec,
    _verify_bedrock,
)
from defenseclaw.config import Config, GatewayConfig, GuardrailConfig, LLMConfig, OpenShellConfig


class DoctorGuardrailTests(unittest.TestCase):
    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(200, "ok"))
    def test_empty_guardrail_model_is_warning_not_failure(self, _mock_probe):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, model="", port=4000),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        result = _DoctorResult()

        _check_guardrail_proxy(cfg, result)

        self.assertEqual(result.failed, 0)
        self.assertEqual(result.warned, 1)
        self.assertEqual(result.passed, 1)
        warn_checks = [c for c in result.checks if c["status"] == "warn"]
        self.assertTrue(any("fetch-interceptor" in c["detail"] for c in warn_checks))

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    def test_sidecar_check_surfaces_disabled_summary(self, mock_probe):
        """When the sidecar publishes details.summary on a disabled
        subsystem (today: gateway standalone-mode short-circuit in
        runGatewayLoop), doctor must include that summary in its
        skip-row detail. The pre-fix generic message
        "disabled (reported by sidecar)" gave operators no way to
        tell apart "intentionally disabled" (codex+loopback) from
        "broken but the sidecar quietly gave up", which is what
        made the codex+standalone reconnect-spam regression so
        hard to diagnose.
        """
        import json as _json

        health_body = _json.dumps({
            "gateway": {
                "state": "disabled",
                "details": {
                    "summary": "no OpenClaw fleet configured (standalone mode)",
                    "connector": "codex",
                    "host": "127.0.0.1",
                    "port": 18789,
                    "hint": "set gateway.host to a real OpenClaw upstream and restart",
                },
            },
            "watcher": {"state": "running"},
            "guardrail": {"state": "running", "details": {"mode": "observe"}},
            "api": {"state": "running"},
        })
        mock_probe.return_value = (200, health_body)

        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(connector="codex"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.claw.mode = "codex"
        result = _DoctorResult()

        _check_sidecar(cfg, result)

        gateway_rows = [
            c for c in result.checks
            if c.get("label", "").strip().endswith("gateway")
        ]
        self.assertEqual(
            len(gateway_rows), 1,
            f"expected exactly one gateway row, got {gateway_rows!r}",
        )
        row = gateway_rows[0]
        # Skip (not warn) — gateway has no on/off config knob, so
        # _subsystem_expected_enabled returns None and we fall to
        # the "skip" branch; the post-fix change appends the summary.
        self.assertEqual(row["status"], "skip")
        self.assertIn(
            "no OpenClaw fleet configured (standalone mode)",
            row["detail"],
            f"summary should be surfaced in detail; got: {row['detail']!r}",
        )

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    def test_sidecar_check_falls_back_to_generic_message_without_summary(self, mock_probe):
        """An older sidecar build (or a different subsystem with no
        publishable summary) must still produce the generic "disabled
        (reported by sidecar)" message — the post-fix code only adds
        the summary when one is present and is otherwise unchanged.
        """
        import json as _json

        health_body = _json.dumps({
            "gateway": {"state": "disabled"},  # no details
            "watcher": {"state": "running"},
            "guardrail": {"state": "running"},
            "api": {"state": "running"},
        })
        mock_probe.return_value = (200, health_body)

        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(connector="codex"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.claw.mode = "codex"
        result = _DoctorResult()
        _check_sidecar(cfg, result)
        gateway_rows = [
            c for c in result.checks
            if c.get("label", "").strip().endswith("gateway")
        ]
        self.assertEqual(len(gateway_rows), 1)
        self.assertEqual(gateway_rows[0]["status"], "skip")
        self.assertEqual(
            gateway_rows[0]["detail"],
            "disabled (reported by sidecar)",
        )

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    def test_codex_observability_mode_skips_proxy_port_probe(self, mock_probe):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(
                enabled=True,
                model="",
                port=4000,
                connector="codex",
                codex_enforcement_enabled=False,
            ),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.claw.mode = "codex"
        result = _DoctorResult()

        _check_guardrail_proxy(cfg, result)

        mock_probe.assert_not_called()
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.warned, 0)
        self.assertEqual(result.passed, 1)
        self.assertIn("intentionally closed", result.checks[0]["detail"])

    @patch("defenseclaw.commands.cmd_doctor._http_probe")
    def test_hook_only_connector_skips_proxy_port_probe(self, mock_probe):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(
                enabled=True,
                model="",
                port=4000,
                connector="geminicli",
            ),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.claw.mode = "geminicli"
        result = _DoctorResult()

        _check_guardrail_proxy(cfg, result)

        mock_probe.assert_not_called()
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.warned, 0)
        self.assertEqual(result.passed, 1)
        self.assertIn("observability-only for geminicli", result.checks[0]["detail"])

    def test_hilt_disabled_is_pass(self):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, mode="action", connector="openclaw"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        result = _DoctorResult()
        _check_hilt_support(cfg, "openclaw", result)
        self.assertEqual(result.passed, 1)
        self.assertEqual(result.warned, 0)

    def test_hilt_codex_partial_support_warns(self):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, mode="action", connector="codex"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.guardrail.hilt.enabled = True
        result = _DoctorResult()
        _check_hilt_support(cfg, "codex", result)
        self.assertEqual(result.failed, 0)
        self.assertEqual(result.warned, 1)
        self.assertIn("no native ask surface", result.checks[0]["detail"])

    def test_hilt_new_connector_support_matrix(self):
        cfg = Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(enabled=True, mode="action", connector="copilot"),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        cfg.guardrail.hilt.enabled = True

        result = _DoctorResult()
        _check_hilt_support(cfg, "copilot", result)
        self.assertEqual(result.passed, 1)
        self.assertIn("preToolUse ask supported", result.checks[0]["detail"])

        result = _DoctorResult()
        _check_hilt_support(cfg, "cursor", result)
        self.assertEqual(result.warned, 1)
        self.assertIn("documented ask-capable", result.checks[0]["detail"])

        result = _DoctorResult()
        _check_hilt_support(cfg, "geminicli", result)
        self.assertEqual(result.warned, 1)
        self.assertIn("no native human approval surface", result.checks[0]["detail"])


class DoctorLLMKeyProviderRoutingTests(unittest.TestCase):
    """Regression: provider routing must be prefix-based, not substring-based.

    A Bedrock inference profile id such as
    "amazon-bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0" contains the
    substring "anthropic" but is NOT an Anthropic endpoint. The doctor must
    not ship a BIFROST_API_KEY / ABSK bearer to api.anthropic.com based on a
    substring match — doing so makes the whole "LLM API key" check fail with
    a spurious 401 even when the deployment is perfectly healthy.
    """

    def _make_cfg(self, *, model: str, api_key_env: str) -> Config:
        return Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(
                enabled=True,
                model=model,
                port=4000,
                api_key_env=api_key_env,
            ),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )

    @patch.dict(os.environ, {"BIFROST_API_KEY": "ABSKtest-not-an-anthropic-key"}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key",
           return_value="ABSKtest-not-an-anthropic-key")
    @patch("defenseclaw.commands.cmd_doctor._verify_bedrock")
    @patch("defenseclaw.commands.cmd_doctor._verify_anthropic")
    @patch("defenseclaw.commands.cmd_doctor._verify_openai")
    def test_bedrock_inference_profile_routes_to_bedrock(
        self, mock_openai, mock_anthropic, mock_bedrock, _mock_resolve,
    ):
        cfg = self._make_cfg(
            model="amazon-bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
            api_key_env="BIFROST_API_KEY",
        )
        r = _DoctorResult()

        _check_llm_api_key(cfg, r)

        mock_bedrock.assert_called_once()
        mock_anthropic.assert_not_called()
        mock_openai.assert_not_called()

    @patch.dict(os.environ, {"DEFENSECLAW_LLM_KEY": "ABSKtoken=="}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="ABSKtoken==")
    @patch("defenseclaw.commands.cmd_doctor._verify_bedrock")
    def test_explicit_bedrock_provider_routes_even_with_bare_model(
        self, mock_bedrock, _mock_resolve,
    ):
        cfg = self._make_cfg(
            model="us.anthropic.claude-haiku-4-5-20251001-v1:0",
            api_key_env="DEFENSECLAW_LLM_KEY",
        )
        cfg.llm = LLMConfig(
            provider="bedrock",
            model="us.anthropic.claude-haiku-4-5-20251001-v1:0",
            api_key_env="DEFENSECLAW_LLM_KEY",
        )
        r = _DoctorResult()

        _check_llm_api_key(cfg, r)

        mock_bedrock.assert_called_once()

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="sk-ant-test")
    @patch("defenseclaw.commands.cmd_doctor._verify_anthropic")
    def test_anthropic_prefix_routes_to_anthropic_verify(
        self, mock_anthropic, _mock_resolve,
    ):
        cfg = self._make_cfg(
            model="anthropic/claude-sonnet-4-5-20250514",
            api_key_env="ANTHROPIC_API_KEY",
        )
        r = _DoctorResult()

        _check_llm_api_key(cfg, r)

        mock_anthropic.assert_called_once()

    @patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="sk-test")
    @patch("defenseclaw.commands.cmd_doctor._verify_openai")
    def test_openai_prefix_routes_to_openai_verify(
        self, mock_openai, _mock_resolve,
    ):
        cfg = self._make_cfg(model="openai/gpt-4o", api_key_env="OPENAI_API_KEY")
        r = _DoctorResult()

        _check_llm_api_key(cfg, r)

        mock_openai.assert_called_once()

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="sk-ant-test")
    @patch("defenseclaw.commands.cmd_doctor._verify_anthropic")
    @patch("defenseclaw.commands.cmd_doctor._verify_openai")
    def test_env_name_fallback_only_when_model_has_no_prefix(
        self, mock_openai, mock_anthropic, _mock_resolve,
    ):
        # Empty model string — env-name fallback kicks in and routes to
        # Anthropic. Previously an env_name prefix of "ANTHROPIC_" would
        # *always* match even when model had a contradicting prefix;
        # that ambiguous routing is the bug M7 fixes.
        cfg = self._make_cfg(model="", api_key_env="ANTHROPIC_API_KEY")
        r = _DoctorResult()

        _check_llm_api_key(cfg, r)

        mock_anthropic.assert_called_once()
        mock_openai.assert_not_called()

    @patch.dict(os.environ, {"ANTHROPIC_API_KEY": "ABSK-bedrock-in-anthropic-slot"}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key",
           return_value="ABSK-bedrock-in-anthropic-slot")
    @patch("defenseclaw.commands.cmd_doctor._verify_anthropic")
    @patch("defenseclaw.commands.cmd_doctor._verify_openai")
    def test_model_prefix_wins_over_env_name(
        self, mock_openai, mock_anthropic, _mock_resolve,
    ):
        # Operator accidentally stored a Bedrock bearer token in a variable
        # called ANTHROPIC_API_KEY. The model says amazon-bedrock/... so
        # we must NOT probe api.anthropic.com with that key.
        cfg = self._make_cfg(
            model="amazon-bedrock/us.anthropic.claude-haiku-4-5",
            api_key_env="ANTHROPIC_API_KEY",
        )
        r = _DoctorResult()

        _check_llm_api_key(cfg, r)

        mock_anthropic.assert_not_called()
        mock_openai.assert_not_called()


class AnthropicProbeModelTests(unittest.TestCase):
    """Tests for the hardcoded-probe-model fix (M6)."""

    def test_prefers_configured_anthropic_model(self):
        got = _anthropic_probe_model("anthropic/claude-opus-4-20250805")
        self.assertEqual(got, "claude-opus-4-20250805")

    def test_env_override(self):
        with patch.dict(os.environ,
                        {"DEFENSECLAW_ANTHROPIC_PROBE_MODEL": "claude-3-opus-20240229"},
                        clear=False):
            got = _anthropic_probe_model("")
        self.assertEqual(got, "claude-3-opus-20240229")

    def test_default_when_no_configured_model(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DEFENSECLAW_ANTHROPIC_PROBE_MODEL", None)
            got = _anthropic_probe_model("")
        self.assertEqual(got, _ANTHROPIC_DEFAULT_PROBE_MODEL)


class DoctorObservabilityLabelTests(unittest.TestCase):
    @patch(
        "defenseclaw.commands.cmd_doctor._resolve_audit_sink_endpoint_and_token",
        return_value=("https://splunk.example.com:8088/services/collector/event", "hec-token"),
    )
    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(200, "ok"))
    def test_splunk_enterprise_probe_label(self, _mock_probe, _mock_resolve):
        cfg = SimpleNamespace(data_dir="/tmp/defenseclaw")
        dest = SimpleNamespace(
            name="splunk-enterprise-splunk-example-com",
            kind="splunk_hec",
            preset_id="splunk-enterprise",
            endpoint="https://splunk.example.com:8088/services/collector/event",
        )
        result = _DoctorResult()

        _probe_splunk_hec(cfg, dest, result)

        self.assertEqual(result.passed, 1)
        self.assertEqual(
            result.checks[0]["label"],
            "splunk-enterprise-splunk-example-com (Splunk Enterprise (HEC))",
        )


class DoctorCacheWriteTests(unittest.TestCase):
    """P3-#21: `_write_doctor_cache` must emit a JSON file that the
    Go TUI can parse into a ``DoctorCache`` via
    ``internal/tui/doctor_cache.go``. Keep these assertions in
    lockstep with ``TestDoctorCache_PythonCompatibleTimestamp`` on
    the Go side.
    """

    def _run_write(self, tmpdir, result):
        from defenseclaw.commands.cmd_doctor import (
            DOCTOR_CACHE_FILENAME,
            _write_doctor_cache,
        )
        cfg = Config(
            data_dir=tmpdir,
            audit_db=os.path.join(tmpdir, "audit.db"),
            quarantine_dir=os.path.join(tmpdir, "quarantine"),
            plugin_dir=os.path.join(tmpdir, "plugins"),
            policy_dir=os.path.join(tmpdir, "policies"),
            guardrail=GuardrailConfig(),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        _write_doctor_cache(cfg, result)
        return os.path.join(tmpdir, DOCTOR_CACHE_FILENAME)

    def test_writes_cache_with_counts_and_checks(self):
        import json
        import tempfile
        r = _DoctorResult()
        r.passed = 3
        r.failed = 1
        r.warned = 2
        r.skipped = 0
        r.checks = [
            {"status": "pass", "label": "Config", "detail": "/etc/dc"},
            {"status": "fail", "label": "Sidecar", "detail": "unreachable"},
            {"status": "warn", "label": "Guardrail", "detail": "model empty"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = self._run_write(tmp, r)
            self.assertTrue(os.path.isfile(path), path)
            with open(path) as fh:
                payload = json.load(fh)
        self.assertEqual(payload["passed"], 3)
        self.assertEqual(payload["failed"], 1)
        self.assertEqual(payload["warned"], 2)
        self.assertEqual(payload["skipped"], 0)
        self.assertEqual(len(payload["checks"]), 3)
        # captured_at must be an ISO-8601 with Z suffix so Go's
        # time.Time parser accepts it.
        self.assertIn("captured_at", payload)
        self.assertTrue(payload["captured_at"].endswith("Z"),
                        payload["captured_at"])

    def test_skips_write_when_no_data_dir(self):
        from defenseclaw.commands.cmd_doctor import _write_doctor_cache
        # A cfg with data_dir="" must not raise and must not touch
        # the filesystem — we silently no-op so nothing is logged
        # to stderr for the common "--help" / embedded-runner case.
        cfg = Config(
            data_dir="",
            audit_db="",
            quarantine_dir="",
            plugin_dir="",
            policy_dir="",
            guardrail=GuardrailConfig(),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )
        _write_doctor_cache(cfg, _DoctorResult())

    def test_atomic_replace(self):
        # Two back-to-back writes must leave exactly one cache file
        # — no `.tmp` residue — so the TUI never sees a half-written
        # JSON document.
        import tempfile
        r1 = _DoctorResult(); r1.passed = 1
        r2 = _DoctorResult(); r2.failed = 7
        with tempfile.TemporaryDirectory() as tmp:
            self._run_write(tmp, r1)
            self._run_write(tmp, r2)
            files = sorted(os.listdir(tmp))
        self.assertEqual(files, ["doctor_cache.json"], files)

    def test_concurrent_writes_do_not_corrupt_cache(self):
        # Regression: earlier revisions used a fixed ".tmp" suffix for
        # the staging file, so two concurrent doctor runs raced on the
        # same path and one could either crash or rename a partial
        # file over the other's finished cache. We now mint a unique
        # tempfile per write via tempfile.NamedTemporaryFile, which
        # this test locks in.
        import json
        import tempfile
        import threading

        with tempfile.TemporaryDirectory() as tmp:
            def write_one(i):
                r = _DoctorResult()
                r.passed = i
                self._run_write(tmp, r)

            threads = [
                threading.Thread(target=write_one, args=(i,))
                for i in range(1, 9)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            cache_path = os.path.join(tmp, "doctor_cache.json")
            # Exactly one canonical cache file, no orphaned tempfiles.
            entries = sorted(os.listdir(tmp))
            self.assertEqual(entries, ["doctor_cache.json"], entries)
            # And the survivor is syntactically valid JSON — the key
            # property the Go loader depends on.
            with open(cache_path) as fh:
                payload = json.load(fh)
            self.assertIn("passed", payload)
            self.assertIn("captured_at", payload)


class DoctorJsonOutputTests(unittest.TestCase):
    """Test --json-output flag on doctor."""

    def test_doctor_result_to_dict(self):
        r = _DoctorResult()
        r.passed = 2
        r.warned = 1
        r.failed = 0
        r.checks.append({"status": "pass", "label": "Config", "detail": "found"})
        r.checks.append({"status": "pass", "label": "Audit DB", "detail": "ok"})
        r.checks.append({"status": "warn", "label": "Scanner", "detail": "not found"})

        d = r.to_dict()
        self.assertEqual(d["passed"], 2)
        self.assertEqual(d["warned"], 1)
        self.assertEqual(d["failed"], 0)
        self.assertEqual(len(d["checks"]), 3)
        self.assertEqual(d["checks"][0]["label"], "Config")


class VerifyBedrockTests(unittest.TestCase):
    """Regression tests for :func:`_verify_bedrock` (M3).

    Before the Bedrock verifier existed, ``_check_llm_api_key`` emitted
    a generic ``pass`` with "cannot verify provider" for any Bedrock
    config. That gave operators false confidence — a revoked ABSK
    token looked healthy until a scan actually called LiteLLM. These
    tests lock in the three shape branches and the HTTP response
    matrix so a future refactor can't regress to the silent pass.
    """

    def test_sigv4_key_emits_warning(self):
        # AWS long-term credentials start with AKIA (or ASIA for STS).
        # We intentionally don't probe them — verifying SigV4 means
        # pulling in botocore just for doctor, which we avoid.
        r = _DoctorResult()
        _verify_bedrock("AKIAEXAMPLEACCESSKEY", r)
        self.assertEqual(r.warned, 1, r.checks)
        self.assertEqual(r.failed, 0)
        self.assertIn("sts get-caller-identity", r.checks[0]["detail"])

    def test_sts_session_key_emits_warning(self):
        # ASIA prefixes are STS session credentials — same SigV4 flow.
        r = _DoctorResult()
        _verify_bedrock("ASIAEXAMPLETEMPKEY", r)
        self.assertEqual(r.warned, 1, r.checks)

    def test_unrecognized_shape_passes_with_note(self):
        # If the operator is running a custom gateway that accepts
        # some other token format, we shouldn't block — just note
        # the shape isn't one we can probe.
        r = _DoctorResult()
        _verify_bedrock("custom-gateway-token-xyz", r)
        self.assertEqual(r.passed, 1, r.checks)
        self.assertIn("shape not recognized", r.checks[0]["detail"])

    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(200, "{}"))
    def test_absk_200_is_pass(self, mock_probe):
        r = _DoctorResult()
        _verify_bedrock("ABSKexamplebearertoken==", r)
        self.assertEqual(r.passed, 1, r.checks)
        # Make sure we're hitting the Bedrock endpoint with a Bearer
        # header, not SigV4.
        args, kwargs = mock_probe.call_args
        url = args[0] if args else kwargs["url"]
        self.assertIn("bedrock.", url)
        self.assertIn("amazonaws.com/foundation-models", url)
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer ABSKexamplebearertoken==")

    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(401, ""))
    def test_absk_401_is_fail(self, _mock_probe):
        r = _DoctorResult()
        _verify_bedrock("ABSKrevokedtoken==", r)
        self.assertEqual(r.failed, 1, r.checks)

    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(403, "access denied"))
    def test_absk_403_is_warn_not_fail(self, _mock_probe):
        # 403 from Bedrock = authenticated but lacks ListFoundationModels.
        # Many production IAM policies grant only InvokeModel — we must
        # not fail the doctor run in that case because scans will work.
        r = _DoctorResult()
        _verify_bedrock("ABSKvalidtokenbutscoped==", r)
        self.assertEqual(r.warned, 1, r.checks)
        self.assertEqual(r.failed, 0)
        self.assertIn("InvokeModel", r.checks[0]["detail"])

    @patch("defenseclaw.commands.cmd_doctor._http_probe", return_value=(0, "DNS failure"))
    def test_network_failure_is_warn(self, _mock_probe):
        # Offline airgapped environments shouldn't fail the whole
        # doctor check — emit a warn so the operator knows connectivity
        # is the issue, not the key.
        r = _DoctorResult()
        _verify_bedrock("ABSKoffline==", r)
        self.assertEqual(r.warned, 1, r.checks)

    def test_region_override_from_environment(self):
        # Operator pinned a GovCloud region via AWS_REGION; the probe
        # URL must honor it instead of defaulting to us-east-1.
        with patch.dict(os.environ, {"AWS_REGION": "us-gov-west-1"}, clear=False):
            self.assertEqual(_bedrock_region(), "us-gov-west-1")

    def test_region_defaults_to_us_east_1(self):
        # Strip all the AWS region env vars we might inherit from the
        # developer shell so the default kicks in deterministically.
        env_copy = {k: v for k, v in os.environ.items()
                    if not k.startswith("AWS_")}
        with patch.dict(os.environ, env_copy, clear=True):
            self.assertEqual(_bedrock_region(), "us-east-1")


class BedrockRoutingTests(unittest.TestCase):
    """Check ``_check_llm_api_key`` routes Bedrock configs to
    :func:`_verify_bedrock` (M3 hook)."""

    def _make_cfg(self, *, model: str, api_key_env: str) -> Config:
        return Config(
            data_dir="/tmp/defenseclaw",
            audit_db="/tmp/defenseclaw/audit.db",
            quarantine_dir="/tmp/defenseclaw/quarantine",
            plugin_dir="/tmp/defenseclaw/plugins",
            policy_dir="/tmp/defenseclaw/policies",
            guardrail=GuardrailConfig(
                enabled=True, model=model, port=4000, api_key_env=api_key_env,
            ),
            gateway=GatewayConfig(),
            openshell=OpenShellConfig(),
        )

    @patch.dict(os.environ, {"AWS_BEARER_TOKEN_BEDROCK": "ABSKtoken=="}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="ABSKtoken==")
    @patch("defenseclaw.commands.cmd_doctor._verify_bedrock")
    @patch("defenseclaw.commands.cmd_doctor._verify_anthropic")
    @patch("defenseclaw.commands.cmd_doctor._verify_openai")
    def test_bedrock_prefix_routes_to_bedrock_verify(
        self, mock_openai, mock_anthropic, mock_bedrock, _mock_resolve,
    ):
        cfg = self._make_cfg(
            model="bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0",
            api_key_env="AWS_BEARER_TOKEN_BEDROCK",
        )
        r = _DoctorResult()
        _check_llm_api_key(cfg, r)
        mock_bedrock.assert_called_once()
        mock_anthropic.assert_not_called()
        mock_openai.assert_not_called()

    @patch.dict(os.environ, {"AWS_BEARER_TOKEN_BEDROCK": "ABSKtoken=="}, clear=False)
    @patch("defenseclaw.commands.cmd_doctor._resolve_api_key", return_value="ABSKtoken==")
    @patch("defenseclaw.commands.cmd_doctor._verify_bedrock")
    def test_env_name_fallback_routes_when_model_empty(
        self, mock_bedrock, _mock_resolve,
    ):
        # Model empty + api_key_env=AWS_BEARER_TOKEN_BEDROCK: the
        # env-name fallback should still route to the bedrock verifier.
        cfg = self._make_cfg(model="", api_key_env="AWS_BEARER_TOKEN_BEDROCK")
        r = _DoctorResult()
        _check_llm_api_key(cfg, r)
        mock_bedrock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
