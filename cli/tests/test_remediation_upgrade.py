"""Regression tests for the upgrade-integrity and LLM key-reuse remediations.

Each test corresponds to a confirmed finding and asserts the *secure*
(fail-closed) behavior plus the explicit ``--allow-unverified`` opt-out where
one exists.

Findings covered:

* F-0201 / F-0703 — abort the upgrade when no integrity metadata is available.
* F-0202        — refuse an unsigned/unverifiable checksum manifest.
* F-0704        — refuse to downgrade signed checksums to unsigned when cosign
                  is missing.
* F-0203        — fail closed when the release upgrade manifest cannot be
                  fetched.
* F-0701        — never send the gateway bearer token to a non-loopback probe
                  host.
* F-0061        — never reuse the resolved default api_key with a caller-chosen
                  endpoint.
"""

import os
import sys
import types
import unittest
from contextlib import ExitStack
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

import requests
from click.testing import CliRunner
from defenseclaw import llm
from defenseclaw.commands.cmd_upgrade import (
    _download_checksums,
    _download_upgrade_manifest,
    _is_loopback_host,
    _poll_health,
    _verify_checksums_sigstore,
    upgrade,
)
from defenseclaw.config import Config, GatewayConfig
from defenseclaw.context import AppContext
from defenseclaw.llm import _merge_defaults


class TestUpgradeFailsClosedWithoutChecksums(unittest.TestCase):
    """F-0201 / F-0703: when neither checksums.txt nor GitHub asset digests
    are available, the upgrade must abort before any artifact is installed —
    unless the operator explicitly opts in with --allow-unverified."""

    def test_upgrade_aborts_when_no_integrity_metadata(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            stack.enter_context(patch("defenseclaw.__version__", "9.9.9"))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._detect_platform",
                return_value=("darwin", "arm64"),
            ))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_checksums",
                return_value=None,
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._fetch_release_asset_digests",
                return_value=None,
            ))
            download_gateway = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._download_gateway")
            )
            install_gateway = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._install_gateway")
            )

            result = runner.invoke(upgrade, ["--yes", "--version", "9.9.9"], obj=app)

        self.assertEqual(result.exit_code, 1, msg=result.output)
        download_gateway.assert_not_called()
        install_gateway.assert_not_called()

    def test_upgrade_allow_unverified_proceeds_without_metadata(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            app.cfg.data_dir = data_dir
            app.cfg.claw.home_dir = data_dir
            stack.enter_context(patch("defenseclaw.__version__", "9.9.9"))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._detect_platform",
                return_value=("darwin", "arm64"),
            ))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_checksums",
                return_value=None,
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._fetch_release_asset_digests",
                return_value=None,
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_upgrade_manifest",
                return_value=None,
            ))
            download_gateway = stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_gateway",
                return_value=(
                    "/tmp/defenseclaw-gateway",
                    "defenseclaw_9.9.9_darwin_arm64.tar.gz",
                ),
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_wheel",
                return_value=("/tmp/defenseclaw.whl", "defenseclaw-9.9.9-py3-none-any.whl"),
            ))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_wheel_install"))
            install_gateway = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._install_gateway")
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_wheel"))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._verify_installed_gateway_version"
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._check_post_upgrade_drift"
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._create_backup",
                return_value="/tmp/backup",
            ))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._poll_health"))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=0),
            ))
            stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._run_installed_migrations", return_value=0)
            )

            result = runner.invoke(
                upgrade,
                ["--yes", "--allow-unverified", "--version", "9.9.9"],
                obj=app,
            )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        download_gateway.assert_called_once()
        install_gateway.assert_called_once()


class TestUpgradeRefusesUnsignedAssetDigests(unittest.TestCase):
    """F-0581: GitHub per-asset digests are UNSIGNED metadata from the same
    remote release service and are NOT a substitute for the Sigstore-verified
    checksums.txt. When checksums.txt is unavailable but unsigned asset digests
    ARE present, the upgrade must still refuse without --allow-unverified (this
    is the regression: it previously proceeded as if verified). With the flag
    it proceeds, but the unsigned digests are not used to fake verification."""

    @staticmethod
    def _common_patches(stack, app, data_dir):
        app.cfg.data_dir = data_dir
        app.cfg.claw.home_dir = data_dir
        stack.enter_context(patch("defenseclaw.__version__", "9.9.9"))
        stack.enter_context(patch(
            "defenseclaw.commands.cmd_upgrade._detect_platform",
            return_value=("darwin", "arm64"),
        ))
        stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_check"))
        # No Sigstore-verified checksums.txt for this release ...
        stack.enter_context(patch(
            "defenseclaw.commands.cmd_upgrade._download_checksums",
            return_value=None,
        ))
        # ... but unsigned GitHub per-asset digests ARE available.
        stack.enter_context(patch(
            "defenseclaw.commands.cmd_upgrade._fetch_release_asset_digests",
            return_value={
                "defenseclaw_9.9.9_darwin_arm64.tar.gz": "a" * 64,
                "defenseclaw-9.9.9-py3-none-any.whl": "b" * 64,
                "upgrade-manifest.json": "c" * 64,
            },
        ))

    def test_upgrade_refused_when_only_unsigned_digests_available(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            self._common_patches(stack, app, data_dir)
            # Patch everything DOWNSTREAM of the checksum gate so that, if the
            # gate fails to refuse (the pre-fix bug), the upgrade would sail
            # through to _download_gateway. This isolates the assertion to the
            # F-0581 control-flow decision rather than a later mock error.
            download_manifest = stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_upgrade_manifest",
                return_value=None,
            ))
            download_gateway = stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_gateway",
                return_value=("/tmp/gw", "defenseclaw_9.9.9_darwin_arm64.tar.gz"),
            ))
            install_gateway = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._install_gateway")
            )

            result = runner.invoke(upgrade, ["--yes", "--version", "9.9.9"], obj=app)

        self.assertEqual(result.exit_code, 1, msg=result.output)
        self.assertIn("--allow-unverified", result.output)
        # The gate must abort BEFORE any artifact is fetched or installed.
        download_manifest.assert_not_called()
        download_gateway.assert_not_called()
        install_gateway.assert_not_called()

    def test_upgrade_allowed_with_flag_but_does_not_trust_unsigned_digests(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()

        with TemporaryDirectory() as data_dir, ExitStack() as stack:
            self._common_patches(stack, app, data_dir)
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_upgrade_manifest",
                return_value=None,
            ))
            download_gateway = stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_gateway",
                return_value=(
                    "/tmp/defenseclaw-gateway",
                    "defenseclaw_9.9.9_darwin_arm64.tar.gz",
                ),
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_wheel",
                return_value=("/tmp/defenseclaw.whl", "defenseclaw-9.9.9-py3-none-any.whl"),
            ))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._preflight_wheel_install"))
            install_gateway = stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._install_gateway")
            )
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_wheel"))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._verify_installed_gateway_version"
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._check_post_upgrade_drift"
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._create_backup",
                return_value="/tmp/backup",
            ))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._run_silent"))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._poll_health"))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=0),
            ))
            stack.enter_context(
                patch("defenseclaw.commands.cmd_upgrade._run_installed_migrations", return_value=0)
            )

            result = runner.invoke(
                upgrade,
                ["--yes", "--allow-unverified", "--version", "9.9.9"],
                obj=app,
            )

        self.assertEqual(result.exit_code, 0, msg=result.output)
        download_gateway.assert_called_once()
        install_gateway.assert_called_once()
        # The unsigned digests must NOT be passed off as a verified manifest:
        # _download_gateway receives checksums=None (no integrity check), not
        # the unsigned digest map. checksums is the 5th positional arg
        # (version, os_name, arch, staging_dir, checksums).
        call = download_gateway.call_args
        checksums_arg = (
            call.kwargs["checksums"] if "checksums" in call.kwargs
            else call.args[4]
        )
        self.assertIsNone(checksums_arg)


class TestUnsignedChecksumManifestRejected(unittest.TestCase):
    """F-0202: a checksums.txt with no verifiable Sigstore signature is
    untrusted and must not authenticate artifacts by default."""

    @staticmethod
    def _write_manifest(tmp):
        path = os.path.join(tmp, "checksums.txt")
        sha = "a" * 64
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"{sha}  defenseclaw-9.9.9-py3-none-any.whl\n")
        return path, sha

    def test_unsigned_manifest_fails_closed(self):
        with TemporaryDirectory() as tmp:
            checksums_path, _sha = self._write_manifest(tmp)
            # checksums.txt present; .sig and .pem absent.
            with patch(
                "defenseclaw.commands.cmd_upgrade._download_optional_release_asset",
                side_effect=[checksums_path, None, None],
            ), self.assertRaises(SystemExit) as ctx:
                _download_checksums("9.9.9", tmp)
            self.assertEqual(ctx.exception.code, 1)

    def test_allow_unverified_accepts_unsigned_manifest(self):
        with TemporaryDirectory() as tmp:
            checksums_path, sha = self._write_manifest(tmp)
            with patch(
                "defenseclaw.commands.cmd_upgrade._download_optional_release_asset",
                side_effect=[checksums_path, None, None],
            ):
                result = _download_checksums("9.9.9", tmp, allow_unverified=True)
            self.assertEqual(result, {"defenseclaw-9.9.9-py3-none-any.whl": sha})

    def test_incomplete_signature_assets_fail_closed(self):
        """Only one of .sig/.pem present is still unverifiable."""
        with TemporaryDirectory() as tmp:
            checksums_path, _sha = self._write_manifest(tmp)
            sig = os.path.join(tmp, "checksums.txt.sig")
            with open(sig, "wb") as f:
                f.write(b"sig")
            with patch(
                "defenseclaw.commands.cmd_upgrade._download_optional_release_asset",
                side_effect=[sig, None],
            ), self.assertRaises(SystemExit) as ctx:
                _verify_checksums_sigstore("9.9.9", tmp, checksums_path)
            self.assertEqual(ctx.exception.code, 1)


class TestSigstoreCosignMissingFailsClosed(unittest.TestCase):
    """F-0704: signed checksums must not be downgraded to unsigned just
    because cosign is unavailable on the host."""

    def test_missing_cosign_with_signature_fails_closed(self):
        with TemporaryDirectory() as tmp:
            checksums = os.path.join(tmp, "checksums.txt")
            sig = os.path.join(tmp, "checksums.txt.sig")
            cert = os.path.join(tmp, "checksums.txt.pem")
            for path in (checksums, sig, cert):
                with open(path, "wb") as f:
                    f.write(b"release asset")

            with patch(
                "defenseclaw.commands.cmd_upgrade._download_optional_release_asset",
                side_effect=[sig, cert],
            ), patch(
                "defenseclaw.commands.cmd_upgrade.shutil.which",
                return_value=None,
            ), patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run"
            ) as run_mock, self.assertRaises(SystemExit) as ctx:
                _verify_checksums_sigstore("9.9.9", tmp, checksums)

        self.assertEqual(ctx.exception.code, 1)
        run_mock.assert_not_called()


class TestUpgradeManifestFailsClosed(unittest.TestCase):
    """F-0203: the release upgrade manifest carries mandatory policy; a
    fetch failure must not silently skip it."""

    def test_missing_manifest_fails_closed(self):
        with TemporaryDirectory() as tmp, patch(
            "defenseclaw.commands.cmd_upgrade.requests.get",
            return_value=Mock(status_code=404, content=b"not found"),
        ), self.assertRaises(SystemExit) as ctx:
            _download_upgrade_manifest("9.9.9", tmp, None)
        self.assertEqual(ctx.exception.code, 1)

    def test_unreachable_manifest_fails_closed(self):
        with TemporaryDirectory() as tmp, patch(
            "defenseclaw.commands.cmd_upgrade.requests.get",
            side_effect=requests.ConnectionError("boom"),
        ), self.assertRaises(SystemExit) as ctx:
            _download_upgrade_manifest("9.9.9", tmp, None)
        self.assertEqual(ctx.exception.code, 1)

    def test_allow_unverified_skips_missing_manifest(self):
        with TemporaryDirectory() as tmp, patch(
            "defenseclaw.commands.cmd_upgrade.requests.get",
            return_value=Mock(status_code=404, content=b"not found"),
        ):
            self.assertIsNone(
                _download_upgrade_manifest("9.9.9", tmp, None, allow_unverified=True)
            )


class TestHealthProbeTokenScoping(unittest.TestCase):
    """F-0701: the gateway bearer token must only be attached when the probe
    host is loopback. A tampered api_bind must not receive the token."""

    class _FakeClient:
        captured: dict = {}

        def __init__(self, host="127.0.0.1", port=18970, token=""):
            type(self).captured = {"host": host, "port": port, "token": token}

        def health(self):
            return {"gateway": {"state": "running"}}

    def test_is_loopback_host_classification(self):
        for host in ("", "localhost", "127.0.0.1", "127.0.0.5", "::1", "[::1]"):
            self.assertTrue(_is_loopback_host(host), msg=host)
        for host in ("attacker.invalid", "10.0.0.8", "0.0.0.0", "192.168.65.2"):
            self.assertFalse(_is_loopback_host(host), msg=host)

    def test_token_omitted_for_non_loopback_bind(self):
        cfg = Config(gateway=GatewayConfig(
            api_bind="attacker.invalid", api_port=31337, token="gw-token",
        ))
        with patch.dict(os.environ, {
            "DEFENSECLAW_GATEWAY_TOKEN": "", "OPENCLAW_GATEWAY_TOKEN": "",
        }), patch("defenseclaw.gateway.OrchestratorClient", self._FakeClient):
            _poll_health(cfg, timeout_seconds=1)

        self.assertEqual(self._FakeClient.captured["host"], "attacker.invalid")
        self.assertEqual(self._FakeClient.captured["token"], "")

    def test_token_sent_for_loopback_bind(self):
        cfg = Config(gateway=GatewayConfig(
            api_bind="127.0.0.1", api_port=18970, token="gw-token",
        ))
        with patch.dict(os.environ, {
            "DEFENSECLAW_GATEWAY_TOKEN": "", "OPENCLAW_GATEWAY_TOKEN": "",
        }), patch("defenseclaw.gateway.OrchestratorClient", self._FakeClient):
            _poll_health(cfg, timeout_seconds=1)

        self.assertEqual(self._FakeClient.captured["host"], "127.0.0.1")
        self.assertEqual(self._FakeClient.captured["token"], "gw-token")


class TestLLMKeyReuse(unittest.TestCase):
    """F-0061: the resolved default api_key must never be reused with a
    caller-chosen endpoint that the request redirected to."""

    DEFAULTS = {
        "model": "openai/gpt-4o",
        "api_key": "SECRET_DEFAULT_KEY",
        "api_base": "https://legit.example/v1",
    }

    def test_api_base_redirect_drops_default_key(self):
        merged = _merge_defaults(
            {"api_base": "https://attacker.example/v1"}, dict(self.DEFAULTS),
        )
        self.assertNotIn("api_key", merged)
        self.assertEqual(merged["api_base"], "https://attacker.example/v1")

    def test_model_redirect_drops_default_key(self):
        merged = _merge_defaults(
            {"model": "anthropic/claude-3-5-sonnet"}, dict(self.DEFAULTS),
        )
        self.assertNotIn("api_key", merged)

    def test_unchanged_routing_keeps_default_key(self):
        merged = _merge_defaults(
            {"messages": [{"role": "user", "content": "ping"}]}, dict(self.DEFAULTS),
        )
        self.assertEqual(merged["api_key"], "SECRET_DEFAULT_KEY")

    def test_matching_provider_model_keeps_default_key(self):
        # provider + bare model that re-states the default routing must not
        # be treated as a redirect.
        merged = _merge_defaults(
            {"provider": "openai", "model": "gpt-4o"}, dict(self.DEFAULTS),
        )
        self.assertEqual(merged["api_key"], "SECRET_DEFAULT_KEY")

    def test_caller_supplied_key_is_preserved(self):
        merged = _merge_defaults(
            {"api_base": "https://attacker.example/v1", "api_key": "CALLER_KEY"},
            dict(self.DEFAULTS),
        )
        self.assertEqual(merged["api_key"], "CALLER_KEY")

    def test_call_llm_does_not_leak_default_key_to_foreign_endpoint(self):
        captured: dict = {}

        def completion(**kwargs):
            captured.update(kwargs)
            return types.SimpleNamespace(
                choices=[types.SimpleNamespace(
                    message=types.SimpleNamespace(content="ok"),
                )],
                usage=types.SimpleNamespace(
                    prompt_tokens=1, completion_tokens=1, total_tokens=2,
                ),
                model="fake",
            )

        fake_litellm = types.SimpleNamespace(completion=completion)
        with patch.dict(sys.modules, {"litellm": fake_litellm}), patch.object(
            llm, "_load_plugin_llm_config", return_value=dict(self.DEFAULTS),
        ):
            result = llm.call_llm({
                "messages": [{"role": "user", "content": "ping"}],
                "api_base": "https://attacker.example/v1",
            })

        self.assertIsNone(result["error"])
        self.assertEqual(captured.get("api_base"), "https://attacker.example/v1")
        self.assertNotIn("api_key", captured)


if __name__ == "__main__":
    unittest.main()
