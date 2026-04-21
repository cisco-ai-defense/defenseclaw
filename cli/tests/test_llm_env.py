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

"""Tests for ``defenseclaw.scanner._llm_env``.

This helper is shared by the skill, MCP, and plugin scanners — a bug
here (wrong env var for a provider, silent clobber, empty-key fallthrough)
surfaces as *"LLM analyzer is quiet"*, not as a hard failure, so it's
worth table-driving every branch. The parity tests at the bottom
additionally guard against the mapping drifting from the Go-side
provider table (``internal/configs/providers.json``) and the CLI's
heuristic in ``defenseclaw.guardrail.detect_api_key_env`` — those three
surfaces read the same key from the same env var, and any disagreement
manifests as silent misconfiguration.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.config import LLMConfig
from defenseclaw.guardrail import detect_api_key_env
from defenseclaw.scanner._llm_env import (
    _LOCAL_PROVIDERS,
    _PROVIDER_ENV_VARS,
    inject_llm_env,
    is_local_provider,
    litellm_completion_kwargs,
    litellm_model,
    provider_env_vars,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PROVIDERS_JSON = _REPO_ROOT / "internal" / "configs" / "providers.json"


def _clear_env(*names: str) -> dict[str, str]:
    """Remove *names* from ``os.environ`` and return the snapshot.

    Restoring via ``os.environ.update`` in ``tearDown`` keeps tests
    isolated even when the developer runs with real ``OPENAI_API_KEY``
    etc. in their shell.
    """
    removed: dict[str, str] = {}
    for name in names:
        if name in os.environ:
            removed[name] = os.environ.pop(name)
    return removed


class ProviderEnvVarsTests(unittest.TestCase):
    """Table-driven tests for :func:`provider_env_vars`."""

    # (provider, expected_primary_env_var). Second+ entries in each tuple
    # are fallbacks; we only assert on the canonical first one so adding
    # more fallbacks later stays backward compatible.
    _CASES = [
        ("openai", "OPENAI_API_KEY"),
        ("OpenAI", "OPENAI_API_KEY"),  # case-insensitive
        (" openai ", "OPENAI_API_KEY"),  # whitespace trimmed
        ("anthropic", "ANTHROPIC_API_KEY"),
        ("azure", "AZURE_OPENAI_API_KEY"),
        ("gemini", "GOOGLE_API_KEY"),
        ("bedrock", "AWS_BEARER_TOKEN_BEDROCK"),  # C2: not AWS_ACCESS_KEY_ID
        ("groq", "GROQ_API_KEY"),
        ("mistral", "MISTRAL_API_KEY"),
        ("cohere", "COHERE_API_KEY"),
    ]

    def test_known_providers(self):
        for provider, expected in self._CASES:
            with self.subTest(provider=provider):
                got = provider_env_vars(provider)
                self.assertTrue(got, f"{provider!r} returned empty tuple")
                self.assertEqual(got[0], expected)

    def test_unknown_provider_returns_empty(self):
        # Unknown providers must return () so callers know to fall
        # through to whatever LiteLLM does by default, rather than
        # silently writing the key to the wrong env var.
        self.assertEqual(provider_env_vars("madeup"), ())
        self.assertEqual(provider_env_vars(""), ())

    def test_local_providers_not_in_mapping(self):
        # Local providers deliberately have no entry — their auth path
        # is base_url, not an API key.
        for prov in _LOCAL_PROVIDERS:
            with self.subTest(provider=prov):
                self.assertEqual(provider_env_vars(prov), ())


class IsLocalProviderTests(unittest.TestCase):
    def test_matches_all_local_aliases(self):
        # Every alias in the frozenset must be recognized — scanners
        # use this to skip the API-key prompt, so a missing alias
        # means we'd demand a key for a keyless provider.
        for prov in _LOCAL_PROVIDERS:
            with self.subTest(provider=prov):
                self.assertTrue(is_local_provider(prov))

    def test_case_and_whitespace_normalization(self):
        self.assertTrue(is_local_provider("Ollama"))
        self.assertTrue(is_local_provider("  vllm  "))

    def test_cloud_providers_are_not_local(self):
        for prov in ("openai", "anthropic", "bedrock", "azure"):
            with self.subTest(provider=prov):
                self.assertFalse(is_local_provider(prov))


class InjectLLMEnvTests(unittest.TestCase):
    """Behavioral tests for :func:`inject_llm_env`.

    We mutate os.environ here, so each test tears its own changes
    down. The helper ``_clear_env`` snapshots *only* the names we
    touch; the rest of the developer's shell environment stays intact.
    """

    _TOUCHED = (
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
        "AZURE_OPENAI_API_KEY", "AZURE_API_KEY",
        "GOOGLE_API_KEY", "GEMINI_API_KEY",
        "AWS_BEARER_TOKEN_BEDROCK",
        "DEFENSECLAW_LLM_KEY",
    )

    def setUp(self):
        self._saved = _clear_env(*self._TOUCHED)

    def tearDown(self):
        # Restore the operator's real env so parallel test runs that
        # genuinely rely on e.g. ANTHROPIC_API_KEY still see it.
        for name in self._TOUCHED:
            os.environ.pop(name, None)
        os.environ.update(self._saved)

    def test_writes_provider_env_var_from_defenseclaw_llm_key(self):
        os.environ["DEFENSECLAW_LLM_KEY"] = "sk-test-key"
        llm = LLMConfig(provider="openai", model="openai/gpt-4o")
        touched = inject_llm_env(llm)
        self.assertEqual(touched, ["OPENAI_API_KEY"])
        self.assertEqual(os.environ["OPENAI_API_KEY"], "sk-test-key")

    def test_respects_existing_env_var_by_default(self):
        # overwrite=False (default) must preserve an operator-set key.
        # Regression guard: earlier revisions clobbered ANTHROPIC_API_KEY
        # with DEFENSECLAW_LLM_KEY on every scan, which broke parallel
        # pipelines sharing a shell.
        os.environ["ANTHROPIC_API_KEY"] = "operator-set"
        os.environ["DEFENSECLAW_LLM_KEY"] = "defenseclaw-fallback"
        llm = LLMConfig(provider="anthropic", model="anthropic/claude-3-5-sonnet-20241022")
        touched = inject_llm_env(llm)
        self.assertEqual(touched, ["ANTHROPIC_AUTH_TOKEN"])
        self.assertEqual(os.environ["ANTHROPIC_API_KEY"], "operator-set")
        # The secondary env var was empty, so it gets populated.
        self.assertEqual(os.environ["ANTHROPIC_AUTH_TOKEN"], "defenseclaw-fallback")

    def test_overwrite_true_forces_clobber(self):
        os.environ["ANTHROPIC_API_KEY"] = "operator-set"
        os.environ["DEFENSECLAW_LLM_KEY"] = "defenseclaw-force"
        llm = LLMConfig(provider="anthropic", model="anthropic/claude-3-5-sonnet-20241022")
        touched = inject_llm_env(llm, overwrite=True)
        self.assertEqual(set(touched), {"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"})
        self.assertEqual(os.environ["ANTHROPIC_API_KEY"], "defenseclaw-force")

    def test_empty_key_is_silent_noop(self):
        # No DEFENSECLAW_LLM_KEY, no api_key inline → must return
        # [] instead of writing the empty string into OPENAI_API_KEY
        # (which would make LiteLLM complain about an empty bearer).
        llm = LLMConfig(provider="openai", model="openai/gpt-4o")
        self.assertEqual(inject_llm_env(llm), [])
        self.assertNotIn("OPENAI_API_KEY", os.environ)

    def test_local_provider_skipped(self):
        # Ollama/vllm/lm_studio must never get an API key written —
        # these runtimes interpret a non-empty Authorization header as
        # a misconfigured request.
        os.environ["DEFENSECLAW_LLM_KEY"] = "sk-test-key"
        for prov, model in (
            ("ollama", "ollama/llama3.1"),
            ("vllm", "vllm/meta-llama"),
            ("lm_studio", "lm_studio/custom"),
        ):
            with self.subTest(provider=prov):
                llm = LLMConfig(provider=prov, model=model)
                self.assertEqual(inject_llm_env(llm), [])

    def test_unknown_provider_is_noop(self):
        # Unknown providers shouldn't touch os.environ — the caller
        # gets the telemetry signal (empty list) and LiteLLM surfaces
        # the real error.
        os.environ["DEFENSECLAW_LLM_KEY"] = "sk-test-key"
        llm = LLMConfig(provider="madeup", model="madeup/x")
        self.assertEqual(inject_llm_env(llm), [])

    def test_bedrock_writes_bearer_token_env_var(self):
        # C2 regression: LiteLLM's Bedrock path expects the bearer
        # token env var, not AWS_ACCESS_KEY_ID. Writing SigV4 keys
        # into an ABSK-shaped value would break signing.
        os.environ["DEFENSECLAW_LLM_KEY"] = (
            "ABSKQmVkcm9ja0FQSUtleS10ZXN0LWV4YW1wbGU="
        )
        llm = LLMConfig(
            provider="bedrock",
            model="bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0",
        )
        touched = inject_llm_env(llm)
        self.assertEqual(touched, ["AWS_BEARER_TOKEN_BEDROCK"])
        self.assertNotIn("AWS_ACCESS_KEY_ID", os.environ)

    def test_custom_api_key_env_is_honored(self):
        # Operators with multiple tenants override api_key_env on the
        # per-scanner LLMConfig. resolved_api_key() reads the override,
        # and inject_llm_env must fan it out into every env var the
        # *provider* expects — not the override name.
        os.environ["TENANT_A_KEY"] = "tenant-a"
        try:
            llm = LLMConfig(
                provider="openai",
                model="openai/gpt-4o",
                api_key_env="TENANT_A_KEY",
            )
            touched = inject_llm_env(llm)
            self.assertEqual(touched, ["OPENAI_API_KEY"])
            self.assertEqual(os.environ["OPENAI_API_KEY"], "tenant-a")
        finally:
            os.environ.pop("TENANT_A_KEY", None)


class LiteLLMModelTests(unittest.TestCase):
    def test_already_namespaced_model_passthrough(self):
        llm = LLMConfig(model="openai/gpt-4o", provider="openai")
        self.assertEqual(litellm_model(llm), "openai/gpt-4o")

    def test_stitches_provider_prefix(self):
        # Operators sometimes write `model: gpt-4o` + `provider: openai`
        # separately. LiteLLM needs the slash-form, so the helper
        # stitches them back together.
        llm = LLMConfig(model="gpt-4o", provider="openai")
        self.assertEqual(litellm_model(llm), "openai/gpt-4o")

    def test_empty_model_passthrough(self):
        llm = LLMConfig(model="", provider="openai")
        self.assertEqual(litellm_model(llm), "")

    def test_model_without_provider(self):
        # No provider + no slash → return as-is and let LiteLLM emit
        # its own unknown-model error. Silently prefixing anything
        # would mask real config bugs.
        llm = LLMConfig(model="gpt-4o", provider="")
        self.assertEqual(litellm_model(llm), "gpt-4o")


class LiteLLMCompletionKwargsTests(unittest.TestCase):
    def setUp(self):
        self._saved = _clear_env("OPENAI_API_KEY", "DEFENSECLAW_LLM_KEY")

    def tearDown(self):
        os.environ.pop("OPENAI_API_KEY", None)
        os.environ.pop("DEFENSECLAW_LLM_KEY", None)
        os.environ.update(self._saved)

    def test_includes_timeout_and_retries_defaults(self):
        llm = LLMConfig(model="openai/gpt-4o", provider="openai")
        kwargs = litellm_completion_kwargs(llm)
        # effective_timeout / effective_max_retries have non-zero
        # defaults — asserting `> 0` keeps this test decoupled from
        # the specific number while still proving the floor applies.
        self.assertGreater(kwargs["timeout"], 0)
        self.assertGreater(kwargs["num_retries"], 0)

    def test_passes_api_key_when_resolved(self):
        os.environ["DEFENSECLAW_LLM_KEY"] = "sk-k"
        llm = LLMConfig(model="openai/gpt-4o", provider="openai")
        kwargs = litellm_completion_kwargs(llm)
        self.assertEqual(kwargs["api_key"], "sk-k")

    def test_omits_api_key_when_unresolved(self):
        # LiteLLM accepts `api_key=None` but treats missing+empty as
        # "look at env". Passing an empty string trips some adapters
        # (notably Bedrock) into an auth error. Check we never emit
        # an empty value.
        llm = LLMConfig(model="openai/gpt-4o", provider="openai")
        kwargs = litellm_completion_kwargs(llm)
        self.assertNotIn("api_key", kwargs)

    def test_passes_base_url_when_set(self):
        llm = LLMConfig(
            model="ollama/llama3.1",
            provider="ollama",
            base_url="http://localhost:11434",
        )
        kwargs = litellm_completion_kwargs(llm)
        self.assertEqual(kwargs["api_base"], "http://localhost:11434")


class ParityTests(unittest.TestCase):
    """Guard against the three API-key surfaces drifting apart.

    1. ``cli/defenseclaw/scanner/_llm_env.py::_PROVIDER_ENV_VARS`` —
       what the Python scanners write.
    2. ``internal/configs/providers.json::env_keys`` — what OpenClaw's
       fetch interceptor picks up.
    3. ``cli/defenseclaw/guardrail.py::detect_api_key_env`` — what
       the ``setup llm`` wizard suggests.

    They don't need to be identical (providers.json only lists providers
    OpenClaw actively intercepts; the Python map covers everything
    LiteLLM supports), but the overlap *must* agree on env var names.
    """

    def test_providers_json_env_keys_are_all_known_to_python(self):
        # Every env var OpenClaw will try to strip from outbound
        # requests has to be one the Python side knows how to write
        # — otherwise the scanner writes ``FOO_API_KEY`` and OpenClaw
        # never redacts ``FOO_API_KEY`` because it's looking for a
        # different name.
        self.assertTrue(
            _PROVIDERS_JSON.is_file(),
            f"missing {_PROVIDERS_JSON} — workspace layout changed?",
        )
        data = json.loads(_PROVIDERS_JSON.read_text())
        py_env_vars = {e for envs in _PROVIDER_ENV_VARS.values() for e in envs}
        for entry in data["providers"]:
            for env_var in entry.get("env_keys", ()):
                with self.subTest(provider=entry["name"], env_var=env_var):
                    self.assertIn(
                        env_var,
                        py_env_vars,
                        f"providers.json references {env_var} but "
                        "_PROVIDER_ENV_VARS doesn't emit it",
                    )

    def test_detect_api_key_env_matches_provider_mapping(self):
        # ``setup llm`` suggests a key name via detect_api_key_env()
        # when the operator chooses a provider. That suggestion is
        # then written to ``api_key_env`` in config.yaml and read
        # back by resolved_api_key(). For the loop to be coherent,
        # the suggested env var must be one of the provider's known
        # vars — otherwise inject_llm_env() writes DEFENSECLAW_LLM_KEY
        # into (say) OPENAI_API_KEY while the operator's .env holds
        # the same value under a different name, and we get a
        # confusing "which one wins?" situation.
        cases = [
            ("openai/gpt-4o", "openai"),
            ("anthropic/claude-3-5-sonnet-20241022", "anthropic"),
            ("azure/gpt-4", "azure"),
            ("gemini/gemini-2.0", "gemini"),
            ("bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0", "bedrock"),
        ]
        for model, provider in cases:
            with self.subTest(provider=provider):
                suggestion = detect_api_key_env(model)
                expected = provider_env_vars(provider)
                self.assertIn(
                    suggestion,
                    expected,
                    f"detect_api_key_env({model!r}) -> {suggestion}, "
                    f"not in _PROVIDER_ENV_VARS[{provider!r}]={expected}",
                )


if __name__ == "__main__":
    unittest.main()
