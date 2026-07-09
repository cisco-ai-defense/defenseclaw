"""Tests for defenseclaw setup provider (custom-providers.json overlay).

The Click wizard is the operator-facing path for extending the LLM
provider registry without a release. These tests lock the behaviour
that other systems depend on:

* File I/O is atomic (temp + replace) so a crash mid-write can't
  corrupt the overlay.
* Adding a provider twice is idempotent — no duplicate domains,
  no duplicate env-keys.
* Malformed overlays fail loudly on *read*, never on *write*, so we
  never silently overwrite hand edits.
* ``_normalize_domain`` strips common operator mistakes (full URLs,
  paths, whitespace) so the saved overlay is always a clean host.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import requests
from click.testing import CliRunner
from defenseclaw.commands.cmd_setup_provider import (
    OVERLAY_ENV,
    _normalize_domain,
    _Overlay,
    _read_overlay,
    _validate_env_keys,
    _write_overlay,
    provider,
)
from defenseclaw.context import AppContext
from defenseclaw.gateway import OrchestratorClient, gateway_api_client_host


class TestNormalizeDomain(unittest.TestCase):
    def test_plain_host(self) -> None:
        self.assertEqual(_normalize_domain("api.openai.com"), "api.openai.com")

    def test_strips_scheme_and_path(self) -> None:
        self.assertEqual(
            _normalize_domain("https://api.openai.com/v1/chat/completions"),
            "api.openai.com",
        )

    def test_lowercases(self) -> None:
        self.assertEqual(_normalize_domain("API.OpenAI.COM"), "api.openai.com")

    def test_rejects_empty(self) -> None:
        import click

        with self.assertRaises(click.BadParameter):
            _normalize_domain("   ")

    def test_rejects_leading_dot(self) -> None:
        import click

        with self.assertRaises(click.BadParameter):
            _normalize_domain(".example.com")

    def test_rejects_internal_whitespace(self) -> None:
        import click

        with self.assertRaises(click.BadParameter):
            _normalize_domain("api openai.com")

    def test_strips_query_and_fragment(self) -> None:
        self.assertEqual(
            _normalize_domain("api.openai.com?foo=bar"),
            "api.openai.com",
        )
        self.assertEqual(
            _normalize_domain("api.openai.com#frag"),
            "api.openai.com",
        )

    def test_strips_userinfo(self) -> None:
        self.assertEqual(
            _normalize_domain("https://user:pass@api.openai.com/v1"),
            "api.openai.com",
        )

    def test_rejects_ip_literal_brackets(self) -> None:
        import click

        with self.assertRaises(click.BadParameter):
            _normalize_domain("[::1]:8080")

    def test_rejects_control_chars(self) -> None:
        import click

        with self.assertRaises(click.BadParameter):
            _normalize_domain("api.openai.com\x00evil")

    def test_rejects_double_dot(self) -> None:
        import click

        with self.assertRaises(click.BadParameter):
            _normalize_domain("api..openai.com")

    def test_allows_port(self) -> None:
        self.assertEqual(
            _normalize_domain("llm.internal.example.com:8443"),
            "llm.internal.example.com:8443",
        )


class TestValidateEnvKeys(unittest.TestCase):
    def test_accepts_upper_snake(self) -> None:
        self.assertEqual(
            _validate_env_keys(["OPENAI_API_KEY", "FOO_BAR"]),
            ["OPENAI_API_KEY", "FOO_BAR"],
        )

    def test_dedupes(self) -> None:
        self.assertEqual(
            _validate_env_keys(["K", "K", "K"]),
            ["K"],
        )

    def test_rejects_punctuation(self) -> None:
        import click

        with self.assertRaises(click.BadParameter):
            _validate_env_keys(["BAD-KEY!"])


class TestRoundTrip(unittest.TestCase):
    def test_read_missing_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nope.json")
            ov = _read_overlay(path)
            self.assertEqual(ov.providers, [])
            self.assertEqual(ov.ollama_ports, [])

    def test_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "custom-providers.json")
            ov = _Overlay(
                providers=[{"name": "x", "domains": ["x.test"]}],
                ollama_ports=[1, 2],
            )
            _write_overlay(path, ov)
            back = _read_overlay(path)
            self.assertEqual(back.providers, ov.providers)
            self.assertEqual(back.ollama_ports, ov.ollama_ports)

    def test_malformed_overlay_raises_on_read(self) -> None:
        import click

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "custom-providers.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write("{not json")
            with self.assertRaises(click.ClickException):
                _read_overlay(path)


class TestProviderAddCommand(unittest.TestCase):
    def _run(self, *args: str, env: dict[str, str] | None = None) -> object:
        runner = CliRunner()
        e = dict(os.environ)
        if env:
            e.update(env)
        return runner.invoke(provider, list(args), env=e, catch_exceptions=False)

    def _env_for(self, overlay_path: str) -> dict[str, str]:
        # Every test wants its overlay inside a tmpdir that is not
        # ~/.defenseclaw. The production code refuses to redirect
        # overlay writes outside the canonical data dir unless
        # DEFENSECLAW_OVERLAY_ROOT explicitly allowlists an extra
        # root. Expose that opt-in here so the path-traversal guard
        # is honored in tests instead of disabled.
        return {
            OVERLAY_ENV: overlay_path,
            "DEFENSECLAW_OVERLAY_ROOT": os.path.dirname(overlay_path),
        }

    @staticmethod
    def _app(overlay_dir: str, *, api_bind: str = "0.0.0.0", api_port: int = 29871) -> AppContext:
        app = AppContext()
        gateway = SimpleNamespace(
            api_bind=api_bind,
            api_port=api_port,
            token="configured-token",
            resolved_token=lambda: "resolved-token",
        )
        app.cfg = SimpleNamespace(
            data_dir=overlay_dir,
            gateway=gateway,
            guardrail=SimpleNamespace(connector="claude-code", port=4000),
        )
        return app

    def test_add_writes_overlay(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "overlay.json")
            res = self._run(
                "add",
                "--name",
                "Acme",
                "--domain",
                "llm.acme.test",
                "--env-key",
                "ACME_API_KEY",
                "--no-reload",
                env=self._env_for(path),
            )
            self.assertEqual(res.exit_code, 0, res.output)
            self.assertTrue(os.path.exists(path))
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            names = [p["name"] for p in data["providers"]]
            self.assertIn("Acme", names)

    def test_add_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "overlay.json")
            for _ in range(3):
                res = self._run(
                    "add",
                    "--name",
                    "Acme",
                    "--domain",
                    "https://llm.acme.test/v1/chat/completions",
                    "--env-key",
                    "ACME_API_KEY",
                    "--no-reload",
                    env=self._env_for(path),
                )
                self.assertEqual(res.exit_code, 0, res.output)
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            acme = [p for p in data["providers"] if p["name"] == "Acme"][0]
            self.assertEqual(acme["domains"], ["llm.acme.test"])
            self.assertEqual(acme["env_keys"], ["ACME_API_KEY"])

    def test_add_unions_domains(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "overlay.json")
            self._run(
                "add",
                "--name",
                "Acme",
                "--domain",
                "llm-a.test",
                "--no-reload",
                env=self._env_for(path),
            )
            self._run(
                "add",
                "--name",
                "Acme",
                "--domain",
                "llm-b.test",
                "--no-reload",
                env=self._env_for(path),
            )
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            acme = [p for p in data["providers"] if p["name"] == "Acme"][0]
            self.assertEqual(sorted(acme["domains"]), ["llm-a.test", "llm-b.test"])

    def test_remove_then_list(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "overlay.json")
            self._run(
                "add",
                "--name",
                "Gone",
                "--domain",
                "gone.test",
                "--no-reload",
                env=self._env_for(path),
            )
            res = self._run(
                "remove",
                "--name",
                "Gone",
                "--no-reload",
                env=self._env_for(path),
            )
            self.assertEqual(res.exit_code, 0, res.output)
            # Second remove must exit non-zero so scripts can tell.
            res2 = self._run(
                "remove",
                "--name",
                "Gone",
                "--no-reload",
                env=self._env_for(path),
            )
            self.assertNotEqual(res2.exit_code, 0)

    def test_refuses_path_traversal(self) -> None:
        # Default allowed roots are ~/.defenseclaw (+ DEFENSECLAW_OVERLAY_ROOT).
        # Without the explicit root opt-in, a caller pointing at /tmp
        # (or anywhere else) must be rejected — redirecting the overlay
        # at an attacker-controlled path would let them flip arbitrary
        # hosts into the LLM allowlist.
        import click
        from defenseclaw.commands.cmd_setup_provider import _overlay_path

        orig = os.environ.pop("DEFENSECLAW_OVERLAY_ROOT", None)
        os.environ[OVERLAY_ENV] = "/etc/passwd"
        try:
            with self.assertRaises(click.ClickException):
                _overlay_path(None)
        finally:
            os.environ.pop(OVERLAY_ENV, None)
            if orig is not None:
                os.environ["DEFENSECLAW_OVERLAY_ROOT"] = orig

    @mock.patch("defenseclaw.commands.cmd_setup_provider.OrchestratorClient")
    def test_add_readd_remove_reload_live_sidecar(self, client_cls: mock.Mock) -> None:
        client_cls.return_value.reload_provider_registry.return_value = {
            "status": "ok",
            "provider_count": 1,
        }
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "custom-providers.json")
            app = self._app(d)
            env = self._env_for(path)
            for args in (
                ["add", "--name", "Acme", "--domain", "one.test"],
                ["add", "--name", "Acme", "--domain", "two.test"],
                ["remove", "--name", "Acme"],
            ):
                result = CliRunner().invoke(provider, args, obj=app, env=env)
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertIn("disk and live state match", result.output)
            self.assertEqual(client_cls.call_count, 3)
            for call in client_cls.call_args_list:
                self.assertEqual(call.kwargs["host"], "127.0.0.1")
                self.assertEqual(call.kwargs["port"], 29871)
                self.assertEqual(call.kwargs["token"], "resolved-token")

    @mock.patch("defenseclaw.commands.cmd_setup_provider.OrchestratorClient")
    def test_persisted_reload_failure_is_nonzero_and_not_rolled_back(self, client_cls: mock.Mock) -> None:
        client_cls.return_value.reload_provider_registry.side_effect = requests.ConnectionError()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "custom-providers.json")
            result = CliRunner().invoke(
                provider,
                ["add", "--name", "Acme", "--domain", "one.test"],
                obj=self._app(d),
                env=self._env_for(path),
            )
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("persisted successfully on disk", result.output)
            self.assertIn("live reload failed", result.output)
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["providers"][0]["name"], "Acme")

    @mock.patch("defenseclaw.commands.cmd_setup_provider.OrchestratorClient")
    def test_no_reload_is_explicit_disk_only(self, client_cls: mock.Mock) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "custom-providers.json")
            result = CliRunner().invoke(
                provider,
                ["add", "--name", "Acme", "--domain", "one.test", "--no-reload"],
                obj=self._app(d),
                env=self._env_for(path),
            )
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("disk-only operation", result.output)
            client_cls.assert_not_called()

    @mock.patch("defenseclaw.commands.cmd_setup_provider.OrchestratorClient")
    def test_show_json_prefers_live_registry_and_never_prints_token(self, client_cls: mock.Mock) -> None:
        client_cls.return_value.provider_registry.return_value = {
            "providers": [{"name": "Live", "domains": ["live.test"]}],
            "ollama_ports": [],
        }
        with tempfile.TemporaryDirectory() as d:
            result = CliRunner().invoke(provider, ["show", "--json"], obj=self._app(d))
            self.assertEqual(result.exit_code, 0, result.output)
            payload = json.loads(result.output)
            self.assertTrue(payload["live"])
            self.assertEqual(payload["source"], "live-sidecar")
            self.assertNotIn("resolved-token", result.output)

    @mock.patch("defenseclaw.commands.cmd_setup_provider.OrchestratorClient")
    def test_list_json_labels_disk_fallback(self, client_cls: mock.Mock) -> None:
        client_cls.return_value.provider_registry.side_effect = requests.ConnectionError()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "custom-providers.json")
            _write_overlay(path, _Overlay([{"name": "Disk", "domains": ["disk.test"]}], []))
            result = CliRunner().invoke(
                provider,
                ["list", "--json"],
                obj=self._app(d),
                env=self._env_for(path),
            )
            self.assertEqual(result.exit_code, 0, result.output)
            payload = json.loads(result.output)
            self.assertFalse(payload["live"])
            self.assertEqual(payload["source"], "disk-fallback")
            self.assertIn("may not match", payload["warning"])

    @mock.patch("defenseclaw.commands.cmd_setup_provider.OrchestratorClient")
    def test_show_human_prominently_labels_disk_fallback(self, client_cls: mock.Mock) -> None:
        client_cls.return_value.provider_registry.side_effect = requests.ConnectionError()
        with tempfile.TemporaryDirectory() as d:
            result = CliRunner().invoke(provider, ["show"], obj=self._app(d))
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("DISK FALLBACK", result.output)
            self.assertIn("may not match the running sidecar", result.output)

    @mock.patch("defenseclaw.commands.cmd_setup_provider.OrchestratorClient")
    def test_auth_and_malformed_live_results_are_labeled_and_nonzero(self, client_cls: mock.Mock) -> None:
        auth_response = requests.Response()
        auth_response.status_code = 401
        cases = (
            (requests.HTTPError(response=auth_response), "authentication failed"),
            (ValueError("bad payload"), "malformed response"),
        )
        with tempfile.TemporaryDirectory() as d:
            for error, label in cases:
                with self.subTest(label=label):
                    client_cls.return_value.provider_registry.side_effect = error
                    result = CliRunner().invoke(provider, ["show", "--json"], obj=self._app(d))
                    self.assertNotEqual(result.exit_code, 0)
                    payload = json.loads(result.output)
                    self.assertFalse(payload["live"])
                    self.assertEqual(payload["source"], "disk-fallback")
                    self.assertEqual(payload["live_error"], label)


class TestProviderGatewayClient(unittest.TestCase):
    def test_wildcard_bind_normalizes_to_loopback(self) -> None:
        for bind in ("", "0.0.0.0", "::", "[::]", "*"):
            cfg = SimpleNamespace(gateway=SimpleNamespace(api_bind=bind))
            self.assertEqual(gateway_api_client_host(cfg), "127.0.0.1")

    def test_provider_client_sends_token_headers(self) -> None:
        client = OrchestratorClient(host="127.0.0.1", port=29871, token="test-token")
        self.assertEqual(client._session.headers["Authorization"], "Bearer test-token")
        self.assertEqual(client._session.headers["X-DC-Auth"], "Bearer test-token")


class TestReadOverlayMalformedShapes(unittest.TestCase):
    """A hand-edited overlay with a top-level list / null / string
    used to crash with AttributeError on ``.get``. Since the Go side
    already tolerates the same case, we should too.
    """

    def test_null_overlay_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "custom-providers.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write("null")
            ov = _read_overlay(path)
            self.assertEqual(ov.providers, [])
            self.assertEqual(ov.ollama_ports, [])

    def test_list_overlay_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "custom-providers.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write("[]")
            ov = _read_overlay(path)
            self.assertEqual(ov.providers, [])
            self.assertEqual(ov.ollama_ports, [])


class TestValidateEnvKeysStrict(unittest.TestCase):
    def test_rejects_leading_digit(self) -> None:
        import click

        with self.assertRaises(click.BadParameter):
            _validate_env_keys(["1_BAD"])

    def test_rejects_unicode(self) -> None:
        import click

        with self.assertRaises(click.BadParameter):
            _validate_env_keys(["API_KEY²"])

    def test_rejects_pure_digits(self) -> None:
        import click

        with self.assertRaises(click.BadParameter):
            _validate_env_keys(["12345"])


if __name__ == "__main__":
    unittest.main()
