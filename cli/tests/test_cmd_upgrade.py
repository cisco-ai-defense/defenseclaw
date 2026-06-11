import hashlib
import io
import json
import os
import tarfile
import unittest
import zipfile
from contextlib import ExitStack
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from click.testing import CliRunner
from defenseclaw.commands.cmd_upgrade import (
    _api_bind_host,
    _assert_required_cli_migrations,
    _check_post_upgrade_drift,
    _create_backup,
    _detect_platform,
    _download_checksums,
    _download_file,
    _download_gateway,
    _download_upgrade_manifest,
    _fetch_release_asset_digests,
    _fill_missing_checksums_from_release_assets,
    _gateway_archive_name,
    _install_gateway,
    _install_wheel,
    _normalize_target_version,
    _print_migration_cursor_summary,
    _run_silent,
    _validate_upgrade_manifest,
    _verify_checksums_sigstore,
    _verify_installed_gateway_version,
    _verify_sha256,
    upgrade,
)
from defenseclaw.config import Config, GatewayConfig, GuardrailConfig, OpenShellConfig
from defenseclaw.context import AppContext


class TestUpgradeVersionValidation(unittest.TestCase):
    def test_accepts_plain_or_v_prefixed_semver(self):
        self.assertEqual(_normalize_target_version("9.9.9"), "9.9.9")
        self.assertEqual(_normalize_target_version("v9.9.9"), "9.9.9")

    def test_rejects_versions_that_would_be_unsafe_in_paths_or_urls(self):
        with self.assertRaises(SystemExit) as ctx:
            _normalize_target_version("../9.9.9")
        self.assertEqual(ctx.exception.code, 1)


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


class TestUpgradeBackup(unittest.TestCase):
    def test_create_backup_includes_managed_connector_backups(self):
        cfg = Config()
        with TemporaryDirectory() as data_dir:
            cfg.data_dir = data_dir
            managed = os.path.join(
                data_dir,
                "connector_backups",
                "codex",
                "config.toml.json",
            )
            os.makedirs(os.path.dirname(managed), exist_ok=True)
            with open(managed, "w") as f:
                f.write("{}")

            backup_dir = _create_backup(cfg)

            copied = os.path.join(
                backup_dir,
                "connector_backups",
                "codex",
                "config.toml.json",
            )
            self.assertTrue(os.path.isfile(copied))


class TestUpgradeWheelInstall(unittest.TestCase):
    def test_install_wheel_uses_managed_venv_python_after_creating_venv(self):
        with TemporaryDirectory() as home, patch.dict(os.environ, {"HOME": home}), \
             patch("shutil.which", return_value="/usr/bin/uv"), \
             patch("subprocess.run") as run_mock:
            venv_python = os.path.join(home, ".defenseclaw", ".venv", "bin", "python")

            def side_effect(args, **_kwargs):
                if args[:2] == ["/usr/bin/uv", "venv"]:
                    os.makedirs(os.path.dirname(venv_python), exist_ok=True)
                    with open(venv_python, "w") as f:
                        f.write("# python")
                return Mock(returncode=0)

            run_mock.side_effect = side_effect

            _install_wheel("/tmp/defenseclaw.whl")

        pip_call = run_mock.call_args_list[-1].args[0]
        self.assertEqual(pip_call[:4], ["/usr/bin/uv", "pip", "install", "--python"])
        self.assertEqual(pip_call[4], venv_python)


class TestUpgradeSameVersionRepair(unittest.TestCase):
    def test_same_version_reapplies_migrations(self):
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
                return_value={
                    "defenseclaw_9.9.9_darwin_arm64.tar.gz": "0" * 64,
                    "defenseclaw-9.9.9-py3-none-any.whl": "0" * 64,
                    "upgrade-manifest.json": "0" * 64,
                },
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_upgrade_manifest",
                return_value=None,
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_gateway",
                return_value=("/tmp/defenseclaw-gateway", "defenseclaw_9.9.9_darwin_arm64.tar.gz"),
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_wheel",
                return_value=("/tmp/defenseclaw.whl", "defenseclaw-9.9.9-py3-none-any.whl"),
            ))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_gateway"))
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
            run_migrations = stack.enter_context(
                patch("defenseclaw.migrations.run_migrations", return_value=1)
            )
            result = runner.invoke(upgrade, ["--yes", "--version", "9.9.9"], obj=app)

        self.assertEqual(result.exit_code, 0, msg=result.output)
        run_migrations.assert_called_once()


class TestUpgradeWithoutOpenClawCli(unittest.TestCase):
    """Regression: when the `openclaw` CLI is not installed, the post-restart
    hook used to crash with FileNotFoundError because subprocess.run() raises
    before check=False can take effect. The upgrade must instead degrade
    gracefully and exit 0."""

    def test_upgrade_succeeds_when_openclaw_cli_missing(self):
        runner = CliRunner()
        app = AppContext()
        app.cfg = Config()

        def fake_run(args, **_kwargs):
            if args and args[0] == "openclaw":
                raise FileNotFoundError(2, "No such file or directory", "openclaw")
            return Mock(returncode=0)

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
                return_value={
                    "defenseclaw_9.9.9_darwin_arm64.tar.gz": "0" * 64,
                    "defenseclaw-9.9.9-py3-none-any.whl": "0" * 64,
                    "upgrade-manifest.json": "0" * 64,
                },
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_upgrade_manifest",
                return_value=None,
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_gateway",
                return_value=("/tmp/defenseclaw-gateway", "defenseclaw_9.9.9_darwin_arm64.tar.gz"),
            ))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade._download_wheel",
                return_value=("/tmp/defenseclaw.whl", "defenseclaw-9.9.9-py3-none-any.whl"),
            ))
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._install_gateway"))
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
            stack.enter_context(patch("defenseclaw.commands.cmd_upgrade._poll_health"))
            stack.enter_context(patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                side_effect=fake_run,
            ))
            stack.enter_context(
                patch("defenseclaw.migrations.run_migrations", return_value=0)
            )
            result = runner.invoke(upgrade, ["--yes", "--version", "9.9.9"], obj=app)

        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Could not restart OpenClaw gateway automatically", result.output)
        self.assertIn("Run manually: openclaw gateway restart", result.output)


class TestChecksumVerification(unittest.TestCase):
    """Supply-chain: every artifact must match a published checksum or be
    refused. A successful checksum is silent; a mismatch aborts; an
    unknown filename in the manifest aborts. ``_download_checksums`` is
    network-bound so we patch ``requests.get`` directly."""

    def test_verify_sha256_passes_on_match(self):
        with TemporaryDirectory() as tmp:
            artifact = os.path.join(tmp, "release.tar.gz")
            payload = b"binary contents"
            with open(artifact, "wb") as f:
                f.write(payload)
            digest = hashlib.sha256(payload).hexdigest()
            checksums = {"release.tar.gz": digest}

            _verify_sha256(artifact, "release.tar.gz", checksums)

    def test_verify_sha256_aborts_on_mismatch(self):
        with TemporaryDirectory() as tmp:
            artifact = os.path.join(tmp, "release.tar.gz")
            with open(artifact, "wb") as f:
                f.write(b"tampered contents")
            checksums = {
                "release.tar.gz": hashlib.sha256(b"original contents").hexdigest(),
            }

            with self.assertRaises(SystemExit) as ctx:
                _verify_sha256(artifact, "release.tar.gz", checksums)
            self.assertEqual(ctx.exception.code, 1)

    def test_verify_sha256_aborts_when_filename_missing_from_manifest(self):
        """A novel filename never present in the manifest must NOT be
        treated as 'no checksum entry → trust' — that would let an
        attacker drop a new artifact next to legitimate ones."""
        with TemporaryDirectory() as tmp:
            artifact = os.path.join(tmp, "evil.tar.gz")
            with open(artifact, "wb") as f:
                f.write(b"surprise")

            with self.assertRaises(SystemExit) as ctx:
                _verify_sha256(artifact, "evil.tar.gz", {"other.tar.gz": "0" * 64})
            self.assertEqual(ctx.exception.code, 1)

    def test_download_checksums_parses_goreleaser_format(self):
        """goreleaser writes ``<sha256>  <filename>`` (two-space separator)."""
        with TemporaryDirectory() as tmp, patch(
            "defenseclaw.commands.cmd_upgrade.requests.get"
        ) as get_mock, patch(
            "defenseclaw.commands.cmd_upgrade._verify_checksums_sigstore"
        ) as verify_sigstore:
            sha = "a" * 64
            body = f"{sha}  defenseclaw_9.9.9_darwin_arm64.tar.gz\n"
            get_mock.return_value = Mock(status_code=200, content=body.encode())

            result = _download_checksums("9.9.9", tmp)

            verify_sigstore.assert_called_once()
            self.assertEqual(
                result, {"defenseclaw_9.9.9_darwin_arm64.tar.gz": sha},
            )

    def test_download_checksums_normalizes_find_dot_prefix(self):
        """The Makefile-generated checksum manifest strips this now, but
        older local builds may contain ``./filename`` from ``find .``."""
        with TemporaryDirectory() as tmp, patch(
            "defenseclaw.commands.cmd_upgrade.requests.get"
        ) as get_mock, patch(
            "defenseclaw.commands.cmd_upgrade._verify_checksums_sigstore"
        ):
            sha = "c" * 64
            body = f"{sha}  ./upgrade-manifest.json\n"
            get_mock.return_value = Mock(status_code=200, content=body.encode())

            result = _download_checksums("9.9.9", tmp)

            self.assertEqual(result, {"upgrade-manifest.json": sha})

    def test_download_checksums_returns_none_on_404(self):
        """Old releases predate goreleaser checksum publication. Caller
        proceeds with a warning; callable must NOT raise."""
        with TemporaryDirectory() as tmp, patch(
            "defenseclaw.commands.cmd_upgrade.requests.get",
            return_value=Mock(status_code=404, content=b""),
        ):
            self.assertIsNone(_download_checksums("9.9.9", tmp))

    def test_download_checksums_rejects_malformed_lines(self):
        """A 200 with garbage body must NOT parse as 'verified empty
        manifest' — the caller would silently skip checks."""
        with TemporaryDirectory() as tmp, patch(
            "defenseclaw.commands.cmd_upgrade.requests.get"
        ) as get_mock, patch(
            "defenseclaw.commands.cmd_upgrade._verify_checksums_sigstore"
        ):
            body = "not-a-checksum\nzzz  bad-hex\n"
            get_mock.return_value = Mock(status_code=200, content=body.encode())

            with self.assertRaises(SystemExit) as ctx:
                _download_checksums("9.9.9", tmp)
            self.assertEqual(ctx.exception.code, 1)

    def test_checksums_sigstore_verifies_signed_manifest(self):
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
                return_value="/usr/bin/cosign",
            ), patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=0, stdout="", stderr=""),
            ) as run_mock:
                _verify_checksums_sigstore("9.9.9", tmp, checksums)

        cmd = run_mock.call_args.args[0]
        self.assertEqual(cmd[0:2], ["/usr/bin/cosign", "verify-blob"])
        self.assertEqual(
            cmd[cmd.index("--certificate-identity-regexp") + 1],
            "^https://github.com/cisco-ai-defense/defenseclaw/.+",
        )
        self.assertEqual(
            cmd[cmd.index("--certificate-oidc-issuer") + 1],
            "https://token.actions.githubusercontent.com",
        )
        self.assertEqual(cmd[-1], checksums)

    def test_checksums_sigstore_hard_fails_when_cosign_rejects_signature(self):
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
                return_value="/usr/bin/cosign",
            ), patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(returncode=1, stdout="", stderr="bad signature"),
            ), self.assertRaises(SystemExit) as ctx:
                _verify_checksums_sigstore("9.9.9", tmp, checksums)

        self.assertEqual(ctx.exception.code, 1)

    def test_checksums_sigstore_fails_closed_without_cosign(self):
        """F-0704: a release that ships Sigstore assets must NOT be downgraded
        to unsigned verification just because cosign is missing. The default
        (no --allow-unverified) now fails closed."""
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

    def test_checksums_sigstore_allow_unverified_skips_cosign(self):
        """With the explicit operator opt-in, a missing cosign degrades to a
        warning instead of aborting (F-0704 escape hatch)."""
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
            ), patch("defenseclaw.commands.cmd_upgrade.subprocess.run") as run_mock:
                _verify_checksums_sigstore(
                    "9.9.9", tmp, checksums, allow_unverified=True,
                )

        run_mock.assert_not_called()

    def test_download_file_retries_transient_server_errors(self):
        ok_response = Mock(status_code=200)
        ok_response.iter_content = Mock(return_value=[b"downloaded"])
        with TemporaryDirectory() as tmp, patch(
            "defenseclaw.commands.cmd_upgrade.requests.get",
            side_effect=[Mock(status_code=503), ok_response],
        ) as get_mock, patch("defenseclaw.commands.cmd_upgrade.time.sleep") as sleep_mock:
            dest = os.path.join(tmp, "artifact.bin")

            _download_file("https://example.invalid/artifact.bin", dest)

            with open(dest, "rb") as f:
                self.assertEqual(f.read(), b"downloaded")
            self.assertEqual(get_mock.call_count, 2)
            sleep_mock.assert_called_once_with(1)

    def test_fetch_release_asset_digests_parses_github_digest_field(self):
        with patch("defenseclaw.commands.cmd_upgrade.requests.get") as get_mock:
            sha = "b" * 64
            get_mock.return_value = Mock(
                json=Mock(return_value={
                    "assets": [
                        {
                            "name": "defenseclaw-9.9.9-py3-none-any.whl",
                            "digest": f"sha256:{sha}",
                        },
                        {
                            "name": "checksums.txt",
                            "digest": "sha1:not-used",
                        },
                    ],
                }),
                raise_for_status=Mock(),
            )

            result = _fetch_release_asset_digests("9.9.9")

        self.assertEqual(result, {"defenseclaw-9.9.9-py3-none-any.whl": sha})

    def test_missing_manifest_entries_are_filled_from_release_asset_digests(self):
        checksums = {"defenseclaw_9.9.9_darwin_arm64.tar.gz": "a" * 64}
        with patch(
            "defenseclaw.commands.cmd_upgrade._fetch_release_asset_digests",
            return_value={"defenseclaw-9.9.9-py3-none-any.whl": "b" * 64},
        ):
            _fill_missing_checksums_from_release_assets(
                "9.9.9",
                checksums,
                [
                    "defenseclaw_9.9.9_darwin_arm64.tar.gz",
                    "defenseclaw-9.9.9-py3-none-any.whl",
                ],
            )

        self.assertEqual(checksums["defenseclaw-9.9.9-py3-none-any.whl"], "b" * 64)


class TestUpgradeManifest(unittest.TestCase):
    """Release-owned upgrade manifests let future versions declare upgrade
    policy even when the local upgrade script is older than the release."""

    def test_validate_rejects_newer_upgrade_protocol(self):
        payload = {
            "schema_version": 1,
            "release_version": "9.9.9",
            "min_upgrade_protocol": 999,
            "migration_failure_policy": "fail",
            "required_cli_migrations": ["9.9.9"],
        }

        with self.assertRaises(SystemExit) as ctx:
            _validate_upgrade_manifest(payload, "9.9.9")

        self.assertEqual(ctx.exception.code, 1)

    def test_validate_rejects_newer_manifest_schema(self):
        payload = {
            "schema_version": 2,
            "release_version": "9.9.9",
            "min_upgrade_protocol": 1,
            "migration_failure_policy": "warn",
            "required_cli_migrations": [],
        }

        with self.assertRaises(SystemExit) as ctx:
            _validate_upgrade_manifest(payload, "9.9.9")

        self.assertEqual(ctx.exception.code, 1)

    def test_download_manifest_verifies_checksum_and_parses_policy(self):
        payload = {
            "schema_version": 1,
            "release_version": "9.9.9",
            "min_upgrade_protocol": 1,
            "migration_failure_policy": "fail",
            "required_cli_migrations": ["9.9.9"],
        }
        body = json.dumps(payload).encode()
        digest = hashlib.sha256(body).hexdigest()
        with TemporaryDirectory() as tmp, patch(
            "defenseclaw.commands.cmd_upgrade.requests.get",
            return_value=Mock(status_code=200, content=body),
        ):
            manifest = _download_upgrade_manifest(
                "9.9.9",
                tmp,
                {"upgrade-manifest.json": digest},
            )

        self.assertEqual(manifest["migration_failure_policy"], "fail")
        self.assertEqual(manifest["required_cli_migrations"], ["9.9.9"])

    def test_required_migration_check_fails_when_cursor_missing_entry(self):
        manifest = {
            "migration_failure_policy": "fail",
            "required_cli_migrations": ["9.9.9"],
        }

        with TemporaryDirectory() as data_dir, self.assertRaises(SystemExit) as ctx:
            _assert_required_cli_migrations(manifest, data_dir)

        self.assertEqual(ctx.exception.code, 1)

    def test_required_migration_check_warn_policy_does_not_fail(self):
        manifest = {
            "migration_failure_policy": "warn",
            "required_cli_migrations": ["9.9.9"],
        }

        with TemporaryDirectory() as data_dir:
            _assert_required_cli_migrations(manifest, data_dir)

    def test_required_migration_check_passes_when_cursor_records_entry(self):
        from defenseclaw import migration_state

        manifest = {
            "required_cli_migrations": ["9.9.9"],
        }
        with TemporaryDirectory() as data_dir:
            state = migration_state.MigrationState(
                package_version="9.9.9",
                applied=["9.9.9"],
                applied_at={"9.9.9": "2026-05-19T00:00:00Z"},
            )
            migration_state.save(data_dir, state)

            _assert_required_cli_migrations(manifest, data_dir)


class TestGatewayTarballExtraction(unittest.TestCase):
    """Gateway release tarballs are verified before extraction, but the
    extractor still refuses unsafe or malformed archive contents."""

    @staticmethod
    def _write_tarball(path, entries):
        with tarfile.open(path, "w:gz") as tar:
            for name, payload in entries.items():
                data = payload.encode()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o755
                tar.addfile(info, io.BytesIO(data))

    def test_download_gateway_extracts_expected_binary(self):
        with TemporaryDirectory() as tmp:

            def fake_download(_url, dest):
                self._write_tarball(dest, {"defenseclaw": "#!/bin/sh\n"})

            with patch("defenseclaw.commands.cmd_upgrade._download_file", side_effect=fake_download):
                binary, tarball_name = _download_gateway("9.9.9", "darwin", "arm64", tmp)

            self.assertEqual(tarball_name, "defenseclaw_9.9.9_darwin_arm64.tar.gz")
            self.assertTrue(os.path.isfile(binary))

    def test_download_gateway_rejects_path_traversal_tarball(self):
        with TemporaryDirectory() as tmp:

            def fake_download(_url, dest):
                self._write_tarball(dest, {"../evil": "nope"})

            with patch("defenseclaw.commands.cmd_upgrade._download_file", side_effect=fake_download):
                with self.assertRaises(SystemExit) as ctx:
                    _download_gateway("9.9.9", "darwin", "arm64", tmp)
            self.assertEqual(ctx.exception.code, 1)

    def test_download_gateway_rejects_tarball_without_binary(self):
        with TemporaryDirectory() as tmp:

            def fake_download(_url, dest):
                self._write_tarball(dest, {"README.md": "missing binary"})

            with patch("defenseclaw.commands.cmd_upgrade._download_file", side_effect=fake_download):
                with self.assertRaises(SystemExit) as ctx:
                    _download_gateway("9.9.9", "darwin", "arm64", tmp)
            self.assertEqual(ctx.exception.code, 1)


class TestGatewayWindowsArchive(unittest.TestCase):
    """Windows ships a .zip containing defenseclaw.exe; the upgrade path must
    download, validate, and extract it the same way it does the .tar.gz."""

    @staticmethod
    def _write_zip(path, entries):
        with zipfile.ZipFile(path, "w") as zf:
            for name, payload in entries.items():
                zf.writestr(name, payload)

    def test_archive_name_is_zip_on_windows_tarball_elsewhere(self):
        self.assertEqual(
            _gateway_archive_name("9.9.9", "windows", "amd64"),
            "defenseclaw_9.9.9_windows_amd64.zip",
        )
        self.assertEqual(
            _gateway_archive_name("9.9.9", "linux", "arm64"),
            "defenseclaw_9.9.9_linux_arm64.tar.gz",
        )

    def test_detect_platform_allows_windows(self):
        with patch("platform.system", return_value="Windows"), \
             patch("platform.machine", return_value="AMD64"):
            self.assertEqual(_detect_platform(), ("windows", "amd64"))

    def test_download_gateway_extracts_exe_from_zip(self):
        with TemporaryDirectory() as tmp:

            def fake_download(_url, dest):
                self._write_zip(dest, {"defenseclaw.exe": "MZ\x00binary"})

            with patch("defenseclaw.commands.cmd_upgrade._download_file", side_effect=fake_download):
                binary, archive_name = _download_gateway("9.9.9", "windows", "amd64", tmp)

            self.assertEqual(archive_name, "defenseclaw_9.9.9_windows_amd64.zip")
            self.assertTrue(binary.endswith("defenseclaw.exe"))
            self.assertTrue(os.path.isfile(binary))

    def test_download_gateway_rejects_zip_without_exe(self):
        with TemporaryDirectory() as tmp:

            def fake_download(_url, dest):
                self._write_zip(dest, {"README.md": "missing binary"})

            with patch("defenseclaw.commands.cmd_upgrade._download_file", side_effect=fake_download):
                with self.assertRaises(SystemExit) as ctx:
                    _download_gateway("9.9.9", "windows", "amd64", tmp)
            self.assertEqual(ctx.exception.code, 1)

    def test_download_gateway_rejects_zip_path_traversal(self):
        with TemporaryDirectory() as tmp:

            def fake_download(_url, dest):
                self._write_zip(dest, {"../evil.exe": "nope"})

            with patch("defenseclaw.commands.cmd_upgrade._download_file", side_effect=fake_download):
                with self.assertRaises(SystemExit) as ctx:
                    _download_gateway("9.9.9", "windows", "amd64", tmp)
            self.assertEqual(ctx.exception.code, 1)


class TestInstallGatewaySnapshotsPrevious(unittest.TestCase):
    """Robustness: installing the new gateway must snapshot the old one
    so a failed health check has a documented rollback path."""

    def test_snapshot_created_when_previous_binary_exists(self):
        with TemporaryDirectory() as fake_home, TemporaryDirectory() as backup_dir, \
             patch.dict(os.environ, {"HOME": fake_home}):
            install_dir = os.path.join(fake_home, ".local", "bin")
            os.makedirs(install_dir)
            previous = os.path.join(install_dir, "defenseclaw-gateway")
            with open(previous, "wb") as f:
                f.write(b"#!/bin/sh\necho old\n")
            os.chmod(previous, 0o755)

            new_binary = os.path.join(fake_home, "defenseclaw")
            with open(new_binary, "wb") as f:
                f.write(b"#!/bin/sh\necho new\n")
            os.chmod(new_binary, 0o755)

            _install_gateway(new_binary, "linux", backup_dir=backup_dir)

            snapshot = os.path.join(backup_dir, "defenseclaw-gateway.previous")
            self.assertTrue(
                os.path.isfile(snapshot),
                msg="previous gateway should have been copied into backup_dir",
            )
            with open(snapshot, "rb") as f:
                self.assertEqual(f.read(), b"#!/bin/sh\necho old\n")
            with open(previous, "rb") as f:
                self.assertEqual(f.read(), b"#!/bin/sh\necho new\n")

    def test_no_snapshot_when_no_previous_binary(self):
        """A fresh install (no prior gateway) must not fail just because
        there's nothing to snapshot."""
        with TemporaryDirectory() as fake_home, TemporaryDirectory() as backup_dir, \
             patch.dict(os.environ, {"HOME": fake_home}):
            new_binary = os.path.join(fake_home, "defenseclaw")
            with open(new_binary, "wb") as f:
                f.write(b"#!/bin/sh\n")
            os.chmod(new_binary, 0o755)

            _install_gateway(new_binary, "linux", backup_dir=backup_dir)

            self.assertFalse(
                os.path.isfile(os.path.join(backup_dir, "defenseclaw-gateway.previous")),
            )


class TestPostInstallVersionVerification(unittest.TestCase):
    """The freshly-installed gateway must report the expected version, or
    the upgrade output must surface the discrepancy."""

    def test_warns_when_version_mismatches(self):
        """An unexpected version string warns but does not abort."""
        runner = CliRunner()
        with TemporaryDirectory() as tmp:
            gateway = os.path.join(tmp, "defenseclaw-gateway")
            with open(gateway, "w") as f:
                f.write("#!/bin/sh\n")
            with patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(
                    stdout="defenseclaw-gateway version 0.5.0 (commit=..., built=...)",
                    stderr="",
                ),
            ):
                with runner.isolation() as (out, _err, _):
                    _verify_installed_gateway_version(gateway, "9.9.9")
                    output = out.getvalue().decode()

        self.assertIn("Gateway version verification failed", output)
        self.assertIn("expected 9.9.9", output)

    def test_silent_success_when_version_matches(self):
        runner = CliRunner()
        with TemporaryDirectory() as tmp:
            gateway = os.path.join(tmp, "defenseclaw-gateway")
            with open(gateway, "w") as f:
                f.write("#!/bin/sh\n")
            with patch(
                "defenseclaw.commands.cmd_upgrade.subprocess.run",
                return_value=Mock(
                    stdout="defenseclaw-gateway version 9.9.9 (commit=abc, built=2026-05-19)",
                    stderr="",
                ),
            ) as run_mock:
                with runner.isolation() as (out, _err, _):
                    _verify_installed_gateway_version(gateway, "9.9.9")
                    output = out.getvalue().decode()

        self.assertIn("Gateway binary verified", output)
        self.assertNotIn("verification failed", output)
        self.assertEqual(run_mock.call_args.args[0][0], gateway)

    def test_handles_missing_binary_gracefully(self):
        """Missing installed path warns and returns cleanly."""
        runner = CliRunner()
        with runner.isolation() as (out, _err, _):
            _verify_installed_gateway_version("/no/such/defenseclaw-gateway", "9.9.9")
            output = out.getvalue().decode()

        self.assertIn("Installed gateway binary is missing", output)


class TestRunSilentSurfaceErrors(unittest.TestCase):
    """When a command fails, the operator should see WHY without needing
    to re-run with --verbose. ``_run_silent`` is the workhorse for
    gateway start/stop/restart calls."""

    def test_success_path_silent(self):
        runner = CliRunner()
        with patch(
            "defenseclaw.commands.cmd_upgrade.subprocess.run",
            return_value=Mock(returncode=0, stderr="", stdout=""),
        ):
            with runner.isolation() as (out, _err, _):
                ok = _run_silent(["true"], "Started", "Did not start")
                output = out.getvalue().decode()

        self.assertTrue(ok)
        self.assertIn("Started", output)
        self.assertNotIn("Did not start", output)

    def test_non_zero_exit_surfaces_stderr(self):
        runner = CliRunner()
        with patch(
            "defenseclaw.commands.cmd_upgrade.subprocess.run",
            return_value=Mock(
                returncode=1,
                stderr="Error: port 18970 already in use\nrun: lsof -i :18970",
                stdout="",
            ),
        ):
            with runner.isolation() as (out, _err, _):
                ok = _run_silent(["start"], "Started", "Did not start")
                output = out.getvalue().decode()

        self.assertFalse(ok)
        self.assertIn("Did not start", output)
        self.assertIn("port 18970 already in use", output)

    def test_file_not_found_surfaces_exception_message(self):
        runner = CliRunner()
        with patch(
            "defenseclaw.commands.cmd_upgrade.subprocess.run",
            side_effect=FileNotFoundError(2, "No such file", "missing-bin"),
        ):
            with runner.isolation() as (out, _err, _):
                ok = _run_silent(["missing-bin"], "Started", "Did not start")
                output = out.getvalue().decode()

        self.assertFalse(ok)
        self.assertIn("Did not start", output)


class TestPostUpgradeDriftCheck(unittest.TestCase):
    """Drift check must surface mismatched component versions but never
    block the upgrade — it's an advisory at the end of the flow."""

    def test_drift_warns_with_actionable_message(self):
        runner = CliRunner()
        from defenseclaw.commands.cmd_version import Component

        with patch(
            "defenseclaw.commands.cmd_version._cli_component",
            return_value=Component(
                name="cli", version="9.9.9", origin="defenseclaw (python)",
            ),
        ), patch(
            "defenseclaw.commands.cmd_version._gateway_component",
            return_value=Component(
                name="gateway", version="9.9.9", origin="/usr/local/bin",
            ),
        ), patch(
            "defenseclaw.commands.cmd_version._plugin_component",
            return_value=Component(
                name="plugin", version="0.5.0", origin="~/.openclaw/...",
            ),
        ):
            with runner.isolation() as (out, _err, _):
                _check_post_upgrade_drift("9.9.9")
                output = out.getvalue().decode()

        self.assertIn("Component drift detected", output)
        self.assertIn("plugin", output)
        self.assertIn("9.9.9", output)

    def test_no_drift_means_no_output(self):
        runner = CliRunner()
        from defenseclaw.commands.cmd_version import Component

        with patch(
            "defenseclaw.commands.cmd_version._cli_component",
            return_value=Component(
                name="cli", version="9.9.9", origin="defenseclaw (python)",
            ),
        ), patch(
            "defenseclaw.commands.cmd_version._gateway_component",
            return_value=Component(
                name="gateway", version="9.9.9", origin="/usr/local/bin",
            ),
        ), patch(
            "defenseclaw.commands.cmd_version._plugin_component",
            return_value=Component(
                name="plugin", version="9.9.9", origin="~/.openclaw/...",
            ),
        ):
            with runner.isolation() as (out, _err, _):
                _check_post_upgrade_drift("9.9.9")
                output = out.getvalue().decode()

        self.assertNotIn("drift", output.lower())


class TestMigrationCursorSummary(unittest.TestCase):
    """The migration cursor is the source of truth for 'which migrations
    have observably executed.' Surface it in upgrade output so a partial-
    failure host is debuggable from a single log."""

    def test_summary_includes_applied_versions(self):
        runner = CliRunner()
        from defenseclaw import migration_state

        with TemporaryDirectory() as data_dir:
            state = migration_state.MigrationState(
                package_version="9.9.9",
                applied=["0.3.0", "0.4.0", "0.5.0"],
                applied_at={
                    "0.3.0": "2026-01-01T00:00:00Z",
                    "0.4.0": "2026-02-01T00:00:00Z",
                    "0.5.0": "2026-03-01T00:00:00Z",
                },
            )
            migration_state.save(data_dir, state)

            with runner.isolation() as (out, _err, _):
                _print_migration_cursor_summary(data_dir)
                output = out.getvalue().decode()

        self.assertIn("cursor:", output)
        self.assertIn("0.3.0", output)
        self.assertIn("0.4.0", output)
        self.assertIn("0.5.0", output)

    def test_summary_silent_when_cursor_absent(self):
        """Missing cursor file → silent. The caller already prints
        'No migrations needed' which is enough context."""
        runner = CliRunner()
        with TemporaryDirectory() as data_dir:
            with runner.isolation() as (out, _err, _):
                _print_migration_cursor_summary(data_dir)
                output = out.getvalue().decode()

        self.assertEqual(output.strip(), "")
