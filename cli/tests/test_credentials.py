# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the central credentials registry.

Focus: verify the *semantics* of the classification pipeline —
predicates return the right ``Requirement`` for each config shape, the
effective env-name override takes precedence over canonical names, and
``resolve`` walks the ``env → .env → unset`` ladder correctly.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw import config as config_mod
from defenseclaw import credential_provenance
from defenseclaw import credentials as C
from defenseclaw.config import (
    CiscoAIDefenseConfig,
    ClawConfig,
    Config,
    GatewayConfig,
    GuardrailConfig,
    JudgeConfig,
    LLMConfig,
    MCPScannerConfig,
    OpenShellConfig,
    OTelConfig,
    OTelDestinationConfig,
    PerConnectorGuardrailConfig,
    ScannersConfig,
    SkillScannerConfig,
    SplunkConfig,
)


def _make_cfg(data_dir: str, **overrides) -> Config:
    """Minimal, construction-only ``Config`` for predicate tests."""
    kwargs = dict(
        data_dir=data_dir,
        audit_db=os.path.join(data_dir, "audit.db"),
        quarantine_dir=os.path.join(data_dir, "quarantine"),
        plugin_dir=os.path.join(data_dir, "plugins"),
        policy_dir=os.path.join(data_dir, "policies"),
        guardrail=GuardrailConfig(),
        gateway=GatewayConfig(),
        openshell=OpenShellConfig(),
    )
    kwargs.update(overrides)
    return Config(**kwargs)


def _make_v8_cfg(data_dir: str, destinations: list[dict]) -> tuple[Config, str]:
    path = os.path.join(data_dir, "config.yaml")
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(
            {
                "config_version": 8,
                "data_dir": data_dir,
                "observability": {"destinations": destinations},
            },
            stream,
        )
    cfg = _make_cfg(data_dir)
    cfg._source_config_version = 8
    return cfg, path


class RequirementPredicateTests(unittest.TestCase):
    """Each predicate should correctly respond to whether its feature is on."""

    def test_openclaw_token_required_for_explicit_openclaw(self):
        cfg = _make_cfg("/tmp/dc-test")
        self.assertEqual(C._openclaw_gateway_token(cfg), C.Requirement.REQUIRED)

    def test_openclaw_token_not_used_for_codex_connector(self):
        cfg = _make_cfg("/tmp/dc-test", claw=ClawConfig(mode="codex"))
        self.assertEqual(C._openclaw_gateway_token(cfg), C.Requirement.NOT_USED)

    def test_openclaw_token_not_used_for_multiconnector_without_openclaw(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                connectors={
                    "codex": PerConnectorGuardrailConfig(),
                    "hermes": PerConnectorGuardrailConfig(),
                }
            ),
        )
        self.assertEqual(C._openclaw_gateway_token(cfg), C.Requirement.NOT_USED)

    def test_openclaw_token_required_for_multiconnector_with_openclaw(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                connectors={
                    "codex": PerConnectorGuardrailConfig(),
                    "openclaw": PerConnectorGuardrailConfig(),
                }
            ),
        )
        self.assertEqual(C._openclaw_gateway_token(cfg), C.Requirement.REQUIRED)

    def test_judge_key_not_used_when_guardrail_disabled(self):
        cfg = _make_cfg("/tmp/dc-test", guardrail=GuardrailConfig(enabled=False))
        self.assertEqual(C._judge_api_key(cfg), C.Requirement.NOT_USED)

    def test_judge_key_not_used_when_default_key_covers_it(self):
        """With no per-component llm.api_key_env override, JUDGE_API_KEY
        is NOT_USED because the top-level DEFENSECLAW_LLM_KEY covers it."""
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                enabled=True,
                judge=JudgeConfig(enabled=True),
            ),
        )
        self.assertEqual(C._judge_api_key(cfg), C.Requirement.NOT_USED)

    def test_judge_key_required_with_custom_override(self):
        """When judge.llm.api_key_env points at a non-default env var,
        that env var is REQUIRED."""
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                enabled=True,
                judge=JudgeConfig(
                    enabled=True,
                    llm=LLMConfig(api_key_env="MY_JUDGE_KEY"),
                ),
            ),
        )
        self.assertEqual(C._judge_api_key(cfg), C.Requirement.REQUIRED)

    def test_judge_key_not_used_for_local_provider(self):
        """Local providers (ollama/vllm) don't need a key."""
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                enabled=True,
                judge=JudgeConfig(
                    enabled=True,
                    llm=LLMConfig(model="ollama/llama3.1", api_key_env="MY_JUDGE_KEY"),
                ),
            ),
        )
        self.assertEqual(C._judge_api_key(cfg), C.Requirement.NOT_USED)

    def test_judge_key_not_used_when_guardrail_on_but_judge_off(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                enabled=True,
                judge=JudgeConfig(enabled=False),
            ),
        )
        self.assertEqual(C._judge_api_key(cfg), C.Requirement.NOT_USED)

    def test_cisco_key_required_only_for_remote_and_both(self):
        for mode, expected in (
            ("local", C.Requirement.NOT_USED),
            ("remote", C.Requirement.REQUIRED),
            ("both", C.Requirement.REQUIRED),
        ):
            with self.subTest(mode=mode):
                cfg = _make_cfg(
                    "/tmp/dc-test",
                    guardrail=GuardrailConfig(enabled=True, scanner_mode=mode),
                )
                self.assertEqual(C._cisco_ai_defense_key(cfg), expected)

    def test_virustotal_respects_use_virustotal_flag(self):
        off = _make_cfg("/tmp/dc-test")
        self.assertEqual(C._virustotal_key(off), C.Requirement.NOT_USED)
        on = _make_cfg(
            "/tmp/dc-test",
            scanners=ScannersConfig(
                skill_scanner=SkillScannerConfig(use_virustotal=True),
            ),
        )
        self.assertEqual(C._virustotal_key(on), C.Requirement.REQUIRED)

    def test_default_llm_key_required_for_auto_mcp_scan_with_cloud_model(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            llm=LLMConfig(api_key_env="DEFENSECLAW_LLM_KEY"),
            scanners=ScannersConfig(
                mcp_scanner=MCPScannerConfig(
                    analyzers="auto",
                    llm=LLMConfig(
                        provider="anthropic",
                        model="anthropic/claude-test",
                    ),
                ),
            ),
        )
        self.assertEqual(C._defenseclaw_llm_key(cfg), C.Requirement.REQUIRED)

    def test_default_llm_key_not_required_for_yara_only_mcp_scan(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            llm=LLMConfig(api_key_env="DEFENSECLAW_LLM_KEY"),
            scanners=ScannersConfig(
                mcp_scanner=MCPScannerConfig(
                    analyzers="yara",
                    llm=LLMConfig(
                        provider="anthropic",
                        model="anthropic/claude-test",
                    ),
                ),
            ),
        )
        self.assertEqual(C._defenseclaw_llm_key(cfg), C.Requirement.NOT_USED)

    def test_splunk_required_when_enabled(self):
        off = _make_cfg("/tmp/dc-test")
        self.assertEqual(C._splunk_token(off), C.Requirement.NOT_USED)
        on = _make_cfg("/tmp/dc-test", splunk=SplunkConfig(enabled=True))
        self.assertEqual(C._splunk_token(on), C.Requirement.REQUIRED)

    def test_splunk_required_for_enabled_v8_hec_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg, path = _make_v8_cfg(
                tmp,
                [
                    {
                        "name": "soc",
                        "kind": "splunk_hec",
                        "endpoint": "https://splunk.example.com/services/collector/event",
                        "token_env": "MY_SPLUNK_HEC_TOKEN",
                    }
                ],
            )
            with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": path}, clear=False):
                self.assertEqual(C._splunk_token(cfg), C.Requirement.REQUIRED)
                spec = C.lookup("SPLUNK_ACCESS_TOKEN")
                self.assertIsNotNone(spec)
                self.assertEqual(spec.resolve_env_name(cfg), "MY_SPLUNK_HEC_TOKEN")

    def test_disabled_v8_splunk_reference_is_not_used(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg, path = _make_v8_cfg(
                tmp,
                [
                    {
                        "name": "soc",
                        "kind": "splunk_hec",
                        "enabled": False,
                        "endpoint": "https://splunk.example.com/services/collector/event",
                        "token_env": "MY_SPLUNK_HEC_TOKEN",
                    }
                ],
            )
            with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": path}, clear=False):
                self.assertEqual(C._splunk_token(cfg), C.Requirement.NOT_USED)

    def test_splunk_o11y_header_reference_is_recognized(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg, path = _make_v8_cfg(
                tmp,
                [
                    {
                        "name": "splunk-o11y",
                        "kind": "otlp",
                        "protocol": "http/protobuf",
                        "endpoint": "https://ingest.us1.signalfx.com",
                        "headers": {"X-SF-Token": {"env": "SPLUNK_ACCESS_TOKEN"}},
                    }
                ],
            )
            with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": path}, clear=False):
                self.assertEqual(C._splunk_token(cfg), C.Requirement.REQUIRED)

    def test_galileo_key_required_only_for_enabled_destination(self):
        off = _make_cfg("/tmp/dc-test")
        self.assertEqual(C._galileo_key(off), C.Requirement.NOT_USED)

        disabled = _make_cfg(
            "/tmp/dc-test",
            otel=OTelConfig(
                enabled=True,
                destinations=[OTelDestinationConfig(name="galileo", preset="galileo", enabled=False)],
            ),
        )
        self.assertEqual(C._galileo_key(disabled), C.Requirement.NOT_USED)

        enabled = _make_cfg(
            "/tmp/dc-test",
            otel=OTelConfig(
                enabled=True,
                destinations=[OTelDestinationConfig(name="galileo", preset="galileo", enabled=True)],
            ),
        )
        self.assertEqual(C._galileo_key(enabled), C.Requirement.REQUIRED)

        custom_name = _make_cfg(
            "/tmp/dc-test",
            otel=OTelConfig(
                enabled=True,
                destinations=[
                    OTelDestinationConfig(
                        name="galileo-security",
                        preset="galileo",
                        enabled=True,
                    )
                ],
            ),
        )
        self.assertEqual(C._galileo_key(custom_name), C.Requirement.REQUIRED)

    def test_galileo_key_uses_enabled_v8_header_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg, path = _make_v8_cfg(
                tmp,
                [
                    {
                        "name": "galileo-production",
                        "kind": "otlp",
                        "preset": "galileo",
                        "protocol": "http/protobuf",
                        "endpoint": "https://api.galileo.ai/otel/traces",
                        "headers": {
                            "Galileo-API-Key": {"env": "MY_GALILEO_KEY"},
                            "project": "defenseclaw",
                            "logstream": "production",
                        },
                    }
                ],
            )
            with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": path}, clear=False):
                self.assertEqual(C._galileo_key(cfg), C.Requirement.REQUIRED)
                spec = C.lookup("GALILEO_API_KEY")
                self.assertIsNotNone(spec)
                self.assertEqual(spec.resolve_env_name(cfg), "MY_GALILEO_KEY")
                self.assertEqual(
                    spec.resolve_bound_endpoint(cfg),
                    "https://api.galileo.ai",
                )

    def test_v8_bound_endpoint_never_exposes_path_query_or_fragment(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg, path = _make_v8_cfg(
                tmp,
                [
                    {
                        "name": "galileo-secret-path",
                        "kind": "otlp",
                        "preset": "galileo",
                        "protocol": "http/protobuf",
                        "endpoint": (
                            "https://api.galileo.ai/tenant/path-secret-canary"
                            "?access_token=query-secret#fragment-secret"
                        ),
                        "headers": {
                            "Galileo-API-Key": {"env": "MY_GALILEO_KEY"},
                            "project": "defenseclaw",
                            "logstream": "production",
                        },
                    }
                ],
            )
            with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": path}, clear=False):
                self.assertEqual(C._galileo_key(cfg), C.Requirement.REQUIRED)
                spec = C.lookup("GALILEO_API_KEY")
                self.assertIsNotNone(spec)
                bound = spec.resolve_bound_endpoint(cfg)
                self.assertEqual(bound, "https://api.galileo.ai")
                for secret in ("path-secret-canary", "query-secret", "fragment-secret"):
                    self.assertNotIn(secret, bound)

    def test_defenseclaw_llm_key_not_used_when_nothing_uses_llm(self):
        cfg = _make_cfg("/tmp/dc-test")
        self.assertEqual(C._defenseclaw_llm_key(cfg), C.Requirement.NOT_USED)

    def test_defenseclaw_llm_key_required_when_guardrail_on(self):
        cfg = _make_cfg("/tmp/dc-test", guardrail=GuardrailConfig(enabled=True))
        self.assertEqual(C._defenseclaw_llm_key(cfg), C.Requirement.REQUIRED)

    def test_defenseclaw_llm_key_optional_for_omnigent_without_judge(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                enabled=True,
                mode="action",
                connector="omnigent",
                judge=JudgeConfig(enabled=False),
            ),
        )
        self.assertEqual(C._defenseclaw_llm_key(cfg), C.Requirement.OPTIONAL)

    def test_defenseclaw_llm_key_required_for_omnigent_judge(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                enabled=True,
                connector="omnigent",
                judge=JudgeConfig(enabled=True),
            ),
        )
        self.assertEqual(C._defenseclaw_llm_key(cfg), C.Requirement.REQUIRED)

    def test_defenseclaw_llm_key_ignores_stale_primary_when_connector_set_is_active(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            claw=ClawConfig(mode="openclaw"),
            guardrail=GuardrailConfig(
                enabled=True,
                connectors={"omnigent": PerConnectorGuardrailConfig()},
                judge=JudgeConfig(enabled=False),
            ),
        )
        self.assertEqual(C._defenseclaw_llm_key(cfg), C.Requirement.OPTIONAL)

    def test_defenseclaw_llm_key_optional_for_omnigent_connector_set_without_judge(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            claw=ClawConfig(mode="omnigent"),
            guardrail=GuardrailConfig(
                enabled=True,
                connectors={"omnigent": PerConnectorGuardrailConfig()},
                judge=JudgeConfig(enabled=False),
            ),
        )
        self.assertEqual(C._defenseclaw_llm_key(cfg), C.Requirement.OPTIONAL)

    def test_defenseclaw_llm_key_required_for_omnigent_connector_set_judge(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            claw=ClawConfig(mode="omnigent"),
            guardrail=GuardrailConfig(
                enabled=True,
                connectors={"omnigent": PerConnectorGuardrailConfig()},
                judge=JudgeConfig(enabled=True),
            ),
        )
        self.assertEqual(C._defenseclaw_llm_key(cfg), C.Requirement.REQUIRED)

    def test_defenseclaw_llm_key_optional_with_local_guardrail(self):
        """Local provider needs no key, but the knob is still surfaced."""
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                enabled=True,
                llm=LLMConfig(model="ollama/llama3.1"),
            ),
        )
        self.assertEqual(C._defenseclaw_llm_key(cfg), C.Requirement.OPTIONAL)

    def test_defenseclaw_llm_key_required_when_skill_scanner_llm_on(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            scanners=ScannersConfig(
                skill_scanner=SkillScannerConfig(use_llm=True),
            ),
        )
        self.assertEqual(C._defenseclaw_llm_key(cfg), C.Requirement.REQUIRED)


class EffectiveEnvNameTests(unittest.TestCase):
    """``effective_env_name`` must win over the canonical name when set."""

    def test_judge_env_override_applied(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            guardrail=GuardrailConfig(
                enabled=True,
                judge=JudgeConfig(
                    enabled=True,
                    llm=LLMConfig(api_key_env="MY_JUDGE"),
                ),
            ),
        )
        judge_spec = C.lookup("JUDGE_API_KEY")
        self.assertIsNotNone(judge_spec)
        self.assertEqual(judge_spec.resolve_env_name(cfg), "MY_JUDGE")

    def test_canonical_name_used_when_override_empty(self):
        cfg = _make_cfg("/tmp/dc-test")
        spec = C.lookup("SPLUNK_ACCESS_TOKEN")
        self.assertIsNotNone(spec)
        resolved = spec.resolve_env_name(cfg)
        self.assertIn(resolved, ("SPLUNK_ACCESS_TOKEN", ""))


class BoundEndpointTests(unittest.TestCase):
    """``CredentialSpec.bound_endpoint`` lets the registry attach the
    URL/host a credential is paired with (e.g. AI Defense regional
    endpoint). UX surfaces consume it via ``resolve_bound_endpoint``;
    the contract is "non-empty string or empty string", never raise.
    """

    def test_cisco_aid_returns_configured_endpoint(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            cisco_ai_defense=CiscoAIDefenseConfig(
                endpoint="https://eu.api.inspect.aidefense.security.cisco.com",
            ),
        )
        spec = C.lookup("CISCO_AI_DEFENSE_API_KEY")
        self.assertIsNotNone(spec)
        self.assertEqual(
            spec.resolve_bound_endpoint(cfg),
            "https://eu.api.inspect.aidefense.security.cisco.com",
        )

    def test_cisco_aid_default_endpoint_when_unset(self):
        """No explicit override → returns the compiled-in US default
        rather than empty. UX wants to render *something* so the
        operator sees which region they're talking to even before
        running setup."""
        cfg = _make_cfg("/tmp/dc-test")
        spec = C.lookup("CISCO_AI_DEFENSE_API_KEY")
        self.assertIsNotNone(spec)
        self.assertEqual(
            spec.resolve_bound_endpoint(cfg),
            "https://us.api.inspect.aidefense.security.cisco.com",
        )

    def test_no_bound_endpoint_returns_empty_string(self):
        """Specs without a paired endpoint (e.g. VirusTotal API key)
        must answer with ``""`` so callers can branch on truthiness
        without try/except."""
        cfg = _make_cfg("/tmp/dc-test")
        spec = C.lookup("VIRUSTOTAL_API_KEY")
        self.assertIsNotNone(spec)
        self.assertEqual(spec.resolve_bound_endpoint(cfg), "")

    def test_galileo_returns_destination_endpoint(self):
        cfg = _make_cfg(
            "/tmp/dc-test",
            otel=OTelConfig(
                enabled=True,
                destinations=[
                    OTelDestinationConfig(
                        name="galileo",
                        preset="galileo",
                        endpoint="https://api.example.test/otel/traces",
                    )
                ],
            ),
        )
        spec = C.lookup("GALILEO_API_KEY")
        self.assertIsNotNone(spec)
        self.assertEqual(
            spec.resolve_bound_endpoint(cfg),
            "https://api.example.test/otel/traces",
        )

        cfg.otel.destinations.insert(
            0,
            OTelDestinationConfig(
                name="galileo-stale",
                preset="galileo",
                enabled=False,
                endpoint="https://stale.example.test/otel/traces",
            ),
        )
        self.assertEqual(
            spec.resolve_bound_endpoint(cfg),
            "https://api.example.test/otel/traces",
        )

        cfg.otel.destinations[1].name = "galileo-security"
        self.assertEqual(
            spec.resolve_bound_endpoint(cfg),
            "https://api.example.test/otel/traces",
        )

    def test_resolve_bound_endpoint_swallows_resolver_errors(self):
        """If a future resolver raises (e.g. config refactor changes
        an attribute name), the UX must still render — the hint is
        advisory, not load-bearing."""

        def boom(_cfg):
            raise RuntimeError("synthetic")

        cfg = _make_cfg("/tmp/dc-test")
        spec = C.CredentialSpec(
            env_name="X",
            feature="x",
            description="x",
            required=lambda _c: C.Requirement.OPTIONAL,
            bound_endpoint=boom,
        )
        self.assertEqual(spec.resolve_bound_endpoint(cfg), "")


class ResolveTests(unittest.TestCase):
    """Resolution walks env → .env → unset."""

    def setUp(self):
        credential_provenance._reset_for_tests()

    def tearDown(self):
        credential_provenance._reset_for_tests()

    def _without_key(self, env_name):
        return {k: v for k, v in os.environ.items() if k != env_name}

    def test_env_beats_dotenv(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as fh:
                fh.write("EXAMPLE_KEY=from_dotenv\n")
            with patch.dict(os.environ, {"EXAMPLE_KEY": "from_env"}, clear=False):
                res = C.resolve("EXAMPLE_KEY", tmp)
                self.assertEqual(res.value, "from_env")
                self.assertEqual(res.source, "env")
                self.assertTrue(res.is_set)

    def test_dotenv_used_when_env_unset(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as fh:
                # Values may be quoted; parser must strip them.
                fh.write('EXAMPLE_KEY="from_dotenv"\n')
            env = {k: v for k, v in os.environ.items() if k != "EXAMPLE_KEY"}
            with patch.dict(os.environ, env, clear=True):
                res = C.resolve("EXAMPLE_KEY", tmp)
                self.assertEqual(res.value, "from_dotenv")
                self.assertEqual(res.source, "dotenv")

    def test_unset_when_neither_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {k: v for k, v in os.environ.items() if k != "EXAMPLE_KEY"}
            with patch.dict(os.environ, env, clear=True):
                res = C.resolve("EXAMPLE_KEY", tmp)
                self.assertFalse(res.is_set)
                self.assertEqual(res.source, "unset")

    def test_dotenv_injected_into_os_retains_dotenv_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".env")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("EXAMPLE_KEY=dotenv-only-value\n")
            with patch.dict(os.environ, self._without_key("EXAMPLE_KEY"), clear=True):
                config_mod._load_dotenv_into_os(tmp)
                res = C.resolve("EXAMPLE_KEY", tmp)
                self.assertEqual(res.value, "dotenv-only-value")
                self.assertEqual(res.source, "dotenv")

    def test_exported_environment_only_remains_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.dict(os.environ, {"EXAMPLE_KEY": "exported-value"}, clear=False):
                config_mod._load_dotenv_into_os(tmp)
                self.assertEqual(C.resolve("EXAMPLE_KEY", tmp).source, "env")

    def test_exported_environment_beats_different_dotenv_value_after_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as fh:
                fh.write("EXAMPLE_KEY=dotenv-value\n")
            with patch.dict(os.environ, {"EXAMPLE_KEY": "exported-value"}, clear=False):
                config_mod._load_dotenv_into_os(tmp)
                res = C.resolve("EXAMPLE_KEY", tmp)
                self.assertEqual(res.value, "exported-value")
                self.assertEqual(res.source, "env")

    def test_same_exported_and_dotenv_value_is_env_when_already_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as fh:
                fh.write("EXAMPLE_KEY=shared-value\n")
            with patch.dict(os.environ, {"EXAMPLE_KEY": "shared-value"}, clear=False):
                config_mod._load_dotenv_into_os(tmp)
                self.assertEqual(C.resolve("EXAMPLE_KEY", tmp).source, "env")

    def test_replacing_injected_value_invalidates_dotenv_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, ".env"), "w", encoding="utf-8") as fh:
                fh.write("EXAMPLE_KEY=dotenv-value\n")
            with patch.dict(os.environ, self._without_key("EXAMPLE_KEY"), clear=True):
                config_mod._load_dotenv_into_os(tmp)
                os.environ["EXAMPLE_KEY"] = "replacement-value"
                res = C.resolve("EXAMPLE_KEY", tmp)
                self.assertEqual(res.value, "replacement-value")
                self.assertEqual(res.source, "env")

    def test_repeated_loads_and_data_dirs_do_not_leak_provenance(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for directory in (first, second):
                with open(os.path.join(directory, ".env"), "w", encoding="utf-8") as fh:
                    fh.write("EXAMPLE_KEY=shared-value\n")
            with patch.dict(os.environ, self._without_key("EXAMPLE_KEY"), clear=True):
                config_mod._load_dotenv_into_os(first)
                config_mod._load_dotenv_into_os(first)
                self.assertEqual(C.resolve("EXAMPLE_KEY", first).source, "dotenv")

                config_mod._load_dotenv_into_os(second)
                self.assertEqual(C.resolve("EXAMPLE_KEY", second).source, "env")
                self.assertEqual(C.resolve("EXAMPLE_KEY", first).source, "env")

    def test_changed_or_removed_dotenv_invalidates_stale_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, ".env")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("EXAMPLE_KEY=first-value\n")
            with patch.dict(os.environ, self._without_key("EXAMPLE_KEY"), clear=True):
                config_mod._load_dotenv_into_os(tmp)
                self.assertEqual(C.resolve("EXAMPLE_KEY", tmp).source, "dotenv")

                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("EXAMPLE_KEY=second-value\n")
                self.assertEqual(C.resolve("EXAMPLE_KEY", tmp).source, "env")

                os.remove(path)
                config_mod._load_dotenv_into_os(tmp)
                self.assertEqual(C.resolve("EXAMPLE_KEY", tmp).source, "env")


class MaskTests(unittest.TestCase):
    def test_short_secrets_fully_masked(self):
        self.assertEqual(C.mask(""), "")
        self.assertEqual(C.mask("abc"), "****")
        self.assertEqual(C.mask("abcdefgh"), "****")

    def test_long_secrets_reveal_edges(self):
        self.assertEqual(C.mask("abcdefghij"), "abcd…ghij")


class ClassifyTests(unittest.TestCase):
    """Integration: classify() produces a CredentialStatus per entry."""

    def test_classify_returns_entry_per_spec(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _make_cfg(tmp)
            statuses = C.classify(cfg)
            self.assertEqual(len(statuses), len(C.CREDENTIALS))
            # Order is stable — registry order drives UX order.
            for i, status in enumerate(statuses):
                self.assertIs(status.spec, C.CREDENTIALS[i])

    def test_missing_required_identifies_unset_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _make_cfg(
                tmp,
                claw=ClawConfig(mode="codex"),
                guardrail=GuardrailConfig(
                    enabled=True,
                    scanner_mode="remote",  # triggers CISCO_AI_DEFENSE_API_KEY
                ),
            )
            env = {
                k: v for k, v in os.environ.items() if k not in ("OPENCLAW_GATEWAY_TOKEN", "CISCO_AI_DEFENSE_API_KEY")
            }
            with patch.dict(os.environ, env, clear=True):
                missing = {s.spec.env_name for s in C.missing_required(cfg)}
                self.assertNotIn("OPENCLAW_GATEWAY_TOKEN", missing)
                self.assertIn("CISCO_AI_DEFENSE_API_KEY", missing)

    def test_classify_includes_each_enabled_v8_destination_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg, path = _make_v8_cfg(
                tmp,
                [
                    {
                        "name": "soc-primary",
                        "kind": "splunk_hec",
                        "endpoint": "https://splunk.example.com/services/collector/event",
                        "token_env": "SPLUNK_PRIMARY_TOKEN",
                    },
                    {
                        "name": "soc-secondary",
                        "kind": "splunk_hec",
                        "endpoint": "https://splunk-secondary.example.com/services/collector/event",
                        "token_env": "SPLUNK_SECONDARY_TOKEN",
                    },
                    {
                        "name": "galileo",
                        "kind": "otlp",
                        "preset": "galileo",
                        "protocol": "http/protobuf",
                        "endpoint": "https://api.galileo.ai/otel/traces",
                        "headers": {
                            "Galileo-API-Key": {"env": "GALILEO_PRODUCTION_KEY"},
                            "project": "defenseclaw",
                            "logstream": "production",
                        },
                    },
                ],
            )
            with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": path}, clear=False):
                required_refs = {
                    status.resolution.env_name
                    for status in C.classify(cfg)
                    if status.spec.feature in {"observability.splunk", "observability.galileo"}
                    and status.requirement is C.Requirement.REQUIRED
                }
            self.assertEqual(
                required_refs,
                {
                    "SPLUNK_PRIMARY_TOKEN",
                    "SPLUNK_SECONDARY_TOKEN",
                    "GALILEO_PRODUCTION_KEY",
                },
            )

    def test_classify_loads_v8_observability_config_once(self):
        from defenseclaw.observability import v8_config

        with tempfile.TemporaryDirectory() as tmp:
            cfg, path = _make_v8_cfg(
                tmp,
                [
                    {
                        "name": "soc",
                        "kind": "splunk_hec",
                        "endpoint": "https://splunk.example.com/services/collector/event",
                        "token_env": "MY_SPLUNK_HEC_TOKEN",
                    }
                ],
            )
            with (
                patch.dict(os.environ, {"DEFENSECLAW_CONFIG": path}, clear=False),
                patch.object(
                    v8_config,
                    "load_validate_v8",
                    wraps=v8_config.load_validate_v8,
                ) as load_config,
            ):
                C.classify(cfg)
                self.assertEqual(load_config.call_count, 1)

                # Direct helper calls remain uncached after classify exits.
                C._splunk_token(cfg)
                self.assertEqual(load_config.call_count, 2)

    def test_classify_caches_empty_and_none_v8_ref_results(self):
        from defenseclaw.observability import v8_config

        with tempfile.TemporaryDirectory() as tmp:
            cfg, path = _make_v8_cfg(tmp, [])
            with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": path}, clear=False):
                with patch.object(
                    v8_config,
                    "load_validate_v8",
                    wraps=v8_config.load_validate_v8,
                ) as load_empty:
                    C.classify(cfg)
                    self.assertEqual(load_empty.call_count, 1)

                with patch.object(
                    v8_config,
                    "load_validate_v8",
                    side_effect=ValueError("synthetic invalid config"),
                ) as load_none:
                    C.classify(cfg)
                    self.assertEqual(load_none.call_count, 1)


if __name__ == "__main__":
    unittest.main()
