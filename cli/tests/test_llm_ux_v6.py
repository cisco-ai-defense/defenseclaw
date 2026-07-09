# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the connector-aware LLM setup surface.

Covers:

* :class:`LLMConfig` provider-typed sub-blocks (Bedrock / Vertex /
  Azure / TLS) round-trip through YAML.
* ``guardrail.llm_role`` round-trips and ``Config.resolve_llm`` honours
  ``instance_name`` overlays.
* The shared :mod:`defenseclaw.commands._llm_picker` helpers behave the
  same in non-interactive and interactive surfaces — every prompt has
  a matching ``--flag`` enforcement path so the TUI's batch invocations
  cannot block on stdin.
* ``defenseclaw setup llm --non-interactive`` accepts the new regional
  / instance / TLS flags and persists them into ``cfg.llm``.
* ``defenseclaw setup provider add`` accepts the extended overlay
  fields (``--base-provider-type``, ``--base-url``,
  ``--allowed-request``, ``--available-model``, ``--ca-cert-file``,
  ``--insecure-skip-verify``) and round-trips them to JSON.
* :func:`credentials.discover_custom_provider_credentials` surfaces
  overlay env keys.
* The Go-side ``configs.Provider`` struct accepts the same custom
  overlay shape produced by the CLI (smoke-tested via a JSON fixture).
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

import click
import pytest
import yaml
from click.testing import CliRunner

pytestmark = pytest.mark.supported_connector_host
from defenseclaw import config as _cfgmod
from defenseclaw import credentials as creds
from defenseclaw.commands import _llm_picker
from defenseclaw.commands.cmd_setup import setup
from defenseclaw.commands.cmd_setup_provider import OVERLAY_ENV, provider
from defenseclaw.config import (
    AzureKeyConfig,
    BedrockKeyConfig,
    Config,
    LLMConfig,
    LLMTLSConfig,
    VertexKeyConfig,
)

_PEM_DUMMY = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAdummy\n"
    "-----END CERTIFICATE-----\n"
)


def _make_cfg(data_dir: str) -> Config:
    """Initialise a fresh config rooted at ``data_dir``.

    Bypasses ``defenseclaw.config.load`` so the test doesn't have to
    mutate ``DEFENSECLAW_HOME`` for every call; we just point the
    in-memory config at ``data_dir`` and let ``cfg.save()`` write to it.
    """
    cfg_path = os.path.join(data_dir, "config.yaml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write("llm:\n  provider: anthropic\n  model: claude-sonnet-4-5\n")
    return _load_via_env(data_dir)


def _load_via_env(data_dir: str) -> Config:
    """Run :func:`defenseclaw.config.load` with ``DEFENSECLAW_HOME``
    pointed at ``data_dir`` so the test isolates from the operator's
    real ``~/.defenseclaw``.
    """
    prev = os.environ.get("DEFENSECLAW_HOME")
    os.environ["DEFENSECLAW_HOME"] = data_dir
    try:
        return _cfgmod.load()
    finally:
        if prev is None:
            os.environ.pop("DEFENSECLAW_HOME", None)
        else:
            os.environ["DEFENSECLAW_HOME"] = prev


class TestLLMConfigSchema(unittest.TestCase):
    """Provider-typed sub-blocks round-trip and apply correctly."""

    def test_bedrock_block_roundtrips(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            cfg = _make_cfg(d)
            cfg.llm.provider = "bedrock"
            cfg.llm.region = "us-east-1"
            cfg.llm.bedrock = BedrockKeyConfig(
                region="us-east-1",
                auth_mode="iam_credentials",
                access_key_env="AWS_ACCESS_KEY_ID",
                secret_key_env="AWS_SECRET_ACCESS_KEY",
                inference_profile="us.",
            )
            cfg.save()
            cfg2 = _load_via_env(d)
            self.assertEqual(cfg2.llm.region, "us-east-1")
            self.assertIsNotNone(cfg2.llm.bedrock)
            assert cfg2.llm.bedrock is not None
            self.assertEqual(cfg2.llm.bedrock.region, "us-east-1")
            self.assertEqual(cfg2.llm.bedrock.auth_mode, "iam_credentials")
            self.assertEqual(cfg2.llm.bedrock.access_key_env, "AWS_ACCESS_KEY_ID")
            self.assertEqual(cfg2.llm.bedrock.inference_profile, "us.")

    def test_vertex_and_azure_blocks_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            cfg = _make_cfg(d)
            cfg.llm.vertex = VertexKeyConfig(
                project_id="acme-prod",
                region="us-central1",
                auth_mode="service_account",
                service_account_json_env="GOOGLE_APPLICATION_CREDENTIALS",
            )
            cfg.llm.azure = AzureKeyConfig(
                endpoint="https://my.openai.azure.com",
                api_version="2024-10-21",
                auth_mode="api_key",
                deployment_aliases={"gpt-4o": "gpt4o-prod"},
            )
            cfg.save()
            cfg2 = _load_via_env(d)
            assert cfg2.llm.vertex is not None and cfg2.llm.azure is not None
            self.assertEqual(cfg2.llm.vertex.project_id, "acme-prod")
            self.assertEqual(cfg2.llm.azure.api_version, "2024-10-21")
            self.assertEqual(cfg2.llm.azure.deployment_aliases["gpt-4o"], "gpt4o-prod")

    def test_tls_block_roundtrips(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            cfg = _make_cfg(d)
            cfg.llm.tls = LLMTLSConfig(ca_cert_pem=_PEM_DUMMY)
            cfg.save()
            cfg2 = _load_via_env(d)
            assert cfg2.llm.tls is not None
            self.assertIn("BEGIN CERTIFICATE", cfg2.llm.tls.ca_cert_pem)
            self.assertFalse(cfg2.llm.tls.insecure_skip_verify)

    def test_empty_blocks_are_pruned(self) -> None:
        """A freshly-saved config without provider-typed blocks must
        not emit empty ``bedrock:`` / ``vertex:`` / ``azure:`` / ``tls:``
        keys. The YAML must stay readable for hand-edits.
        """
        with tempfile.TemporaryDirectory() as d:
            cfg = _make_cfg(d)
            cfg.llm.bedrock = BedrockKeyConfig()
            cfg.llm.vertex = VertexKeyConfig(auth_mode="service_account")
            cfg.llm.azure = AzureKeyConfig(api_version="2024-10-21")
            cfg.llm.tls = LLMTLSConfig()
            cfg.save()
            with open(os.path.join(d, "config.yaml"), encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            self.assertNotIn("bedrock", raw.get("llm", {}))
            self.assertNotIn("tls", raw.get("llm", {}))


class TestGuardrailLLMRole(unittest.TestCase):
    """``guardrail.llm_role`` is required by the connector-aware wizard."""

    def test_llm_role_roundtrips(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            cfg = _make_cfg(d)
            cfg.guardrail.enabled = True
            cfg.guardrail.llm_role = "judge_and_agent"
            cfg.save()
            cfg2 = _load_via_env(d)
            self.assertEqual(cfg2.guardrail.llm_role, "judge_and_agent")


class TestInstanceOverlay(unittest.TestCase):
    """``Config.resolve_llm`` reads ``custom-providers.json`` instances."""

    def test_instance_overlay_fills_base_url_and_tls(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            overlay = {
                "providers": [
                    {
                        "name": "acme-internal",
                        "domains": ["llm.internal"],
                        "base_provider_type": "openai",
                        "base_url": "https://llm.internal:8443",
                        "env_keys": ["ACME_KEY"],
                        "tls": {"insecure_skip_verify": True},
                    }
                ]
            }
            with open(os.path.join(d, "custom-providers.json"), "w", encoding="utf-8") as f:
                json.dump(overlay, f)
            cfg = _make_cfg(d)
            cfg.llm.instance_name = "acme-internal"
            cfg.llm.api_key_env = "ACME_KEY"
            cfg.save()
            cfg2 = _load_via_env(d)
            resolved = cfg2.resolve_llm("")
            # base_url is supplied by the overlay; api_key_env stays as
            # the operator's explicit override.
            self.assertEqual(resolved.base_url, "https://llm.internal:8443")
            self.assertEqual(resolved.api_key_env, "ACME_KEY")


class TestLLMPickerNonInteractive(unittest.TestCase):
    """Every picker enforces the non-interactive contract."""

    def test_provider_required_in_non_interactive(self) -> None:
        with self.assertRaises(click.UsageError) as ctx:
            _llm_picker.pick_provider(
                current="",
                flag_value=None,
                non_interactive=True,
            )
        self.assertIn("--provider", str(ctx.exception))

    def test_provider_falls_through_to_flag_value(self) -> None:
        out = _llm_picker.pick_provider(
            current="",
            flag_value="Bedrock",
            non_interactive=True,
        )
        self.assertEqual(out, "bedrock")

    def test_model_required_in_non_interactive(self) -> None:
        with self.assertRaises(click.UsageError):
            _llm_picker.pick_model(
                current="",
                provider="bedrock",
                instance=None,
                flag_value=None,
                non_interactive=True,
            )

    def test_region_required_in_non_interactive(self) -> None:
        with self.assertRaises(click.UsageError):
            _llm_picker.pick_region(
                provider="bedrock",
                current="",
                flag_value=None,
                non_interactive=True,
            )

    def test_key_env_validates_format(self) -> None:
        with self.assertRaises(click.BadParameter):
            _llm_picker.pick_key_env(
                provider="anthropic",
                current="",
                flag_value="not-a-valid-env",
                non_interactive=True,
            )

    def test_list_inherit_candidates_orders_top_level_first(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            cfg = _make_cfg(d)
            cfg.guardrail.enabled = True
            cfg.guardrail.judge.enabled = True
            cfg.guardrail.judge.llm.provider = "openai"
            cfg.guardrail.judge.llm.model = "gpt-4o-mini"
            candidates = _llm_picker.list_inherit_candidates(cfg)
            paths = [c["path"] for c in candidates]
            # Top-level llm is always first when populated.
            self.assertEqual(paths[0], "llm")
            self.assertIn("guardrail.judge", paths)


class TestSetupLLMNonInteractiveFlags(unittest.TestCase):
    """``setup llm --non-interactive`` plumbs every regional / TLS /
    instance flag through to ``cfg.llm``.
    """

    def setUp(self) -> None:
        from tests.helpers import cleanup_app, make_app_context

        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()
        self._cleanup = lambda: cleanup_app(self.app, self.db_path, self.tmp_dir)

    def tearDown(self) -> None:
        self._cleanup()

    def test_bedrock_flags_populate_subblock(self) -> None:
        res = self.runner.invoke(
            setup,
            [
                "llm",
                "--non-interactive",
                "--provider", "bedrock",
                "--model", "us.anthropic.claude-sonnet-4-6",
                "--bedrock-region", "us-east-1",
                "--bedrock-auth-mode", "iam_credentials",
                "--bedrock-access-key-env", "AWS_ACCESS_KEY_ID",
                "--bedrock-secret-key-env", "AWS_SECRET_ACCESS_KEY",
                "--bedrock-inference-profile", "us.",
            ],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(res.exit_code, 0, res.output)
        cfg = self.app.cfg
        assert cfg.llm.bedrock is not None
        self.assertEqual(cfg.llm.bedrock.region, "us-east-1")
        self.assertEqual(cfg.llm.bedrock.auth_mode, "iam_credentials")
        self.assertEqual(cfg.llm.bedrock.inference_profile, "us.")

    def test_instance_name_flag_persists(self) -> None:
        res = self.runner.invoke(
            setup,
            [
                "llm",
                "--non-interactive",
                "--provider", "custom",
                "--instance-name", "acme-internal",
                "--model", "us.anthropic.claude-sonnet-4-6",
            ],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(res.exit_code, 0, res.output)
        self.assertEqual(self.app.cfg.llm.instance_name, "acme-internal")

    def test_role_judge_writes_to_guardrail_judge(self) -> None:
        """``setup llm --role judge`` writes to ``cfg.guardrail.judge.llm``
        and leaves the top-level ``cfg.llm`` block untouched.
        """
        res = self.runner.invoke(
            setup,
            [
                "llm",
                "--non-interactive",
                "--role", "judge",
                "--provider", "anthropic",
                "--model", "claude-sonnet-4-5",
            ],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(res.exit_code, 0, res.output)
        cfg = self.app.cfg
        self.assertEqual(cfg.guardrail.judge.llm.provider, "anthropic")
        self.assertEqual(cfg.guardrail.judge.llm.model, "claude-sonnet-4-5")
        # The top-level llm should not have been overwritten with the judge
        # values (it was pre-populated by _make_cfg → load).
        self.assertNotEqual(cfg.llm.model, "claude-sonnet-4-5")

    def test_bedrock_deployment_alias_lands_on_subblock(self) -> None:
        res = self.runner.invoke(
            setup,
            [
                "llm",
                "--non-interactive",
                "--provider", "bedrock",
                "--model", "sonnet-4",
                "--bedrock-region", "us-east-1",
                "--bedrock-deployment", "sonnet-4=us.anthropic.claude-sonnet-4-6",
            ],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(res.exit_code, 0, res.output)
        cfg = self.app.cfg
        assert cfg.llm.bedrock is not None
        self.assertEqual(
            cfg.llm.bedrock.deployment_aliases.get("sonnet-4"),
            "us.anthropic.claude-sonnet-4-6",
        )

    def test_ping_flag_triggers_post_save_ping(self) -> None:
        """``--ping`` must trigger the post-save reachability ping. We
        patch ``_run_llm_ping`` to count invocations.
        """
        from defenseclaw.commands import cmd_setup

        with mock.patch.object(cmd_setup, "_run_llm_ping") as patched:
            res = self.runner.invoke(
                setup,
                [
                    "llm",
                    "--non-interactive",
                    "--provider", "anthropic",
                    "--model", "claude-sonnet-4-5",
                    "--ping",
                ],
                obj=self.app,
                catch_exceptions=False,
            )
            self.assertEqual(res.exit_code, 0, res.output)
            patched.assert_called_once()

    def test_legacy_test_flag_is_rejected(self) -> None:
        """The legacy ``--test`` alias for ``--ping`` was removed.
        ``click`` must surface a usage error and exit non-zero so any
        script still passing ``--test`` fails loudly instead of
        silently skipping the ping.
        """
        res = self.runner.invoke(
            setup,
            [
                "llm",
                "--non-interactive",
                "--provider", "anthropic",
                "--model", "claude-sonnet-4-5",
                "--test",
            ],
            obj=self.app,
        )
        self.assertNotEqual(res.exit_code, 0)
        self.assertIn("No such option", res.output)

    def test_auth_mode_maps_to_provider_typed_flag(self) -> None:
        res = self.runner.invoke(
            setup,
            [
                "llm",
                "--non-interactive",
                "--provider", "bedrock",
                "--model", "us.anthropic.claude-sonnet-4-6",
                "--auth-mode", "profile",
            ],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(res.exit_code, 0, res.output)
        cfg = self.app.cfg
        assert cfg.llm.bedrock is not None
        self.assertEqual(cfg.llm.bedrock.auth_mode, "profile")


class TestSetupGuardrailJudgeFlags(unittest.TestCase):
    """``setup guardrail`` exposes the full judge-side regional/TLS/auth
    flag surface so a Bedrock IAM judge can be configured without
    hand-editing YAML.
    """

    def setUp(self) -> None:
        from tests.helpers import cleanup_app, make_app_context

        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()
        self._cleanup = lambda: cleanup_app(self.app, self.db_path, self.tmp_dir)

    def tearDown(self) -> None:
        self._cleanup()

    def test_judge_bedrock_flags_persist(self) -> None:
        res = self.runner.invoke(
            setup,
            [
                "guardrail",
                "--non-interactive",
                "--connector", "openclaw",
                "--judge-provider", "bedrock",
                "--judge-model", "us.anthropic.claude-sonnet-4-6",
                "--judge-bedrock-region", "us-east-1",
                "--judge-bedrock-auth-mode", "iam_credentials",
                "--judge-bedrock-access-key-env", "AWS_ACCESS_KEY_ID",
                "--judge-bedrock-secret-key-env", "AWS_SECRET_ACCESS_KEY",
                "--judge-bedrock-inference-profile", "us.",
                "--judge-bedrock-deployment", "sonnet-4=us.anthropic.claude-sonnet-4-6",
                "--no-restart",
                "--no-verify",
            ],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(res.exit_code, 0, res.output)
        judge_llm = self.app.cfg.guardrail.judge.llm
        assert judge_llm.bedrock is not None
        self.assertEqual(judge_llm.bedrock.region, "us-east-1")
        self.assertEqual(judge_llm.bedrock.auth_mode, "iam_credentials")
        self.assertEqual(
            judge_llm.bedrock.deployment_aliases.get("sonnet-4"),
            "us.anthropic.claude-sonnet-4-6",
        )

    def test_judge_tls_skip_verify_persists(self) -> None:
        res = self.runner.invoke(
            setup,
            [
                "guardrail",
                "--non-interactive",
                "--connector", "openclaw",
                "--judge-provider", "openai",
                "--judge-model", "gpt-4o",
                "--judge-insecure-skip-verify",
                "--no-restart",
                "--no-verify",
            ],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(res.exit_code, 0, res.output)
        judge_llm = self.app.cfg.guardrail.judge.llm
        assert judge_llm.tls is not None
        self.assertTrue(judge_llm.tls.insecure_skip_verify)

    def test_judge_inherit_llm_alias_copies_unified(self) -> None:
        self.app.cfg.llm.provider = "anthropic"
        self.app.cfg.llm.model = "claude-sonnet-4-5"
        self.app.cfg.llm.api_key_env = "DEFENSECLAW_LLM_KEY"
        res = self.runner.invoke(
            setup,
            [
                "guardrail",
                "--non-interactive",
                "--connector", "openclaw",
                "--inherit-llm",
                "--no-restart",
                "--no-verify",
            ],
            obj=self.app,
            catch_exceptions=False,
        )
        self.assertEqual(res.exit_code, 0, res.output)
        judge_llm = self.app.cfg.guardrail.judge.llm
        self.assertEqual(judge_llm.provider, "anthropic")
        self.assertEqual(judge_llm.model, "claude-sonnet-4-5")


class TestConnectorLLMRole(unittest.TestCase):
    """``connector_llm_role`` classifies hook vs proxy connectors."""

    def test_codex_is_judge_only(self) -> None:
        from defenseclaw.commands.cmd_setup import connector_llm_role
        self.assertEqual(connector_llm_role("codex"), "judge_only")

    def test_openclaw_is_judge_and_agent(self) -> None:
        from defenseclaw.commands.cmd_setup import connector_llm_role
        self.assertEqual(connector_llm_role("openclaw"), "judge_and_agent")

    def test_unknown_falls_back_to_judge_only(self) -> None:
        from defenseclaw.commands.cmd_setup import connector_llm_role
        self.assertEqual(connector_llm_role("acme-fictional-connector"), "judge_only")


class TestMigrateInstanceName(unittest.TestCase):
    """``_migrate_llm_fields`` auto-derives ``instance_name`` from a
    legacy ``base_url`` that matches a custom-providers.json entry.
    """

    def test_base_url_matching_overlay_is_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            overlay = {
                "providers": [
                    {
                        "name": "acme-internal",
                        "base_url": "https://llm.internal:8443",
                        "domains": ["llm.internal"],
                    }
                ]
            }
            with open(os.path.join(d, "custom-providers.json"), "w", encoding="utf-8") as f:
                json.dump(overlay, f)
            cfg_path = os.path.join(d, "config.yaml")
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(
                    "llm:\n"
                    "  provider: custom\n"
                    "  model: claude-sonnet-4-5\n"
                    "  base_url: https://llm.internal:8443\n"
                )
            cfg = _load_via_env(d)
            self.assertEqual(cfg.llm.instance_name, "acme-internal")
            self.assertEqual(cfg.llm.base_url, "")


class TestSetupProviderExtendedSchema(unittest.TestCase):
    """``setup provider add`` accepts the custom-overlay extensions."""

    def _env(self, path: str) -> dict[str, str]:
        return {
            OVERLAY_ENV: path,
            "DEFENSECLAW_OVERLAY_ROOT": os.path.dirname(path),
        }

    def test_full_custom_provider_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            overlay = os.path.join(d, "overlay.json")
            ca_file = os.path.join(d, "root.pem")
            with open(ca_file, "w", encoding="utf-8") as f:
                f.write(_PEM_DUMMY)
            runner = CliRunner()
            env = dict(os.environ)
            env.update(self._env(overlay))
            res = runner.invoke(
                provider,
                [
                    "add",
                    "--name", "acme-internal",
                    "--base-provider-type", "openai",
                    "--base-url", "https://llm.internal:8443",
                    "--env-key", "ACME_KEY",
                    "--allowed-request", "chat",
                    "--allowed-request", "embedding",
                    "--available-model", "claude-sonnet-4-5",
                    "--request-path-override", "chat=/openai/v1/chat/completions",
                    "--ca-cert-file", ca_file,
                    "--no-reload",
                ],
                env=env,
                catch_exceptions=False,
            )
            self.assertEqual(res.exit_code, 0, res.output)
            with open(overlay, encoding="utf-8") as f:
                data = json.load(f)
            entry = next(p for p in data["providers"] if p["name"] == "acme-internal")
            self.assertEqual(entry["base_provider_type"], "openai")
            self.assertEqual(entry["base_url"], "https://llm.internal:8443")
            self.assertEqual(sorted(entry["allowed_requests"]), ["chat", "embedding"])
            self.assertEqual(entry["available_models"], ["claude-sonnet-4-5"])
            self.assertEqual(
                entry["request_path_overrides"]["chat"],
                "/openai/v1/chat/completions",
            )
            self.assertIn("BEGIN CERTIFICATE", entry["tls"]["ca_cert_pem"])

    def test_insecure_and_ca_cert_are_mutually_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            overlay = os.path.join(d, "overlay.json")
            ca_file = os.path.join(d, "root.pem")
            with open(ca_file, "w", encoding="utf-8") as f:
                f.write(_PEM_DUMMY)
            runner = CliRunner()
            env = dict(os.environ)
            env.update(self._env(overlay))
            res = runner.invoke(
                provider,
                [
                    "add",
                    "--name", "lab",
                    "--base-url", "https://llm.lab:8443",
                    "--insecure-skip-verify",
                    "--ca-cert-file", ca_file,
                    "--no-reload",
                ],
                env=env,
                catch_exceptions=False,
            )
            self.assertNotEqual(res.exit_code, 0)
            self.assertIn("mutually exclusive", res.output.lower())


class TestCustomProviderCredentialDiscovery(unittest.TestCase):
    """``credentials.classify`` surfaces overlay env keys."""

    def test_discovery_finds_overlay_env_keys(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            overlay = {
                "providers": [
                    {"name": "acme", "env_keys": ["ACME_LLM_KEY"], "domains": ["llm"]},
                ]
            }
            with open(os.path.join(d, "custom-providers.json"), "w", encoding="utf-8") as f:
                json.dump(overlay, f)
            cfg = _make_cfg(d)
            statuses = creds.classify(cfg)
            names = {s.spec.env_name for s in statuses}
            self.assertIn("ACME_LLM_KEY", names)


class TestLLMPing(unittest.TestCase):
    """:func:`defenseclaw.llm.ping` returns (ok, message) and never raises."""

    def test_ping_skips_when_model_missing(self) -> None:
        from defenseclaw import llm as llm_mod

        ok, msg = llm_mod.ping(LLMConfig())
        self.assertFalse(ok)
        self.assertIn("no model", msg)

    def test_ping_swallows_litellm_errors(self) -> None:
        """A provider failure must come back as ``(False, msg)``, not
        an exception — the wizard wraps the result in a banner.
        """
        from defenseclaw import llm as llm_mod

        cfg = LLMConfig(provider="anthropic", model="claude-sonnet-4-5")
        # Stub litellm.completion to raise so we exercise the failure path
        # without hitting the network.
        with mock.patch("litellm.completion", side_effect=RuntimeError("boom")):
            ok, msg = llm_mod.ping(cfg)
        self.assertFalse(ok)
        self.assertIn("boom", msg.lower())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
