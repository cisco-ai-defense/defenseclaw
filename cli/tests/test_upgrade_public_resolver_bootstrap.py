# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
import sys
from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

import defenseclaw.commands.cmd_upgrade as upgrade_module
import defenseclaw.main as main_module
import pytest
from click.testing import CliRunner
from defenseclaw.release_channel import build_channel, render_channel
from defenseclaw.resolver_hint import RESOLVER_COMPLETENESS_MARKER

_POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix",
    reason="release-resolver authentication uses POSIX file custody",
)
_VERSION = "9.9.9"
_CHANNEL_COMMIT = "c" * 40


def _resolver_payload() -> bytes:
    return (f"#!/usr/bin/env bash\nprintf 'resolver\\n'\n{RESOLVER_COMPLETENESS_MARKER}\n").encode()


def _channel_payload(
    resolver: bytes,
    *,
    repository: str = upgrade_module.GITHUB_REPO,
    digest: str | None = None,
) -> bytes:
    return render_channel(
        build_channel(
            repository=repository,
            version=_VERSION,
            commit="a" * 40,
            resolver_sha256=digest or hashlib.sha256(resolver).hexdigest(),
            posix_installer_sha256="b" * 64,
            windows_installer_sha256="c" * 64,
        )
    )


def _channel_downloaders(
    resolver: bytes,
    *,
    channel: bytes | None = None,
):
    channel_payload = channel or _channel_payload(resolver)
    channel_payloads = {
        "stable.txt": channel_payload,
        "stable.txt.bundle": b"signed bundle\n",
    }

    def download_ref(
        destination: str,
        _maximum: int,
    ) -> None:
        Path(destination).write_text(
            json.dumps(
                {
                    "ref": "refs/heads/release-channel",
                    "object": {
                        "type": "commit",
                        "sha": _CHANNEL_COMMIT,
                    },
                }
            ),
            encoding="utf-8",
        )
        os.chmod(destination, 0o600)

    def download_channel(
        name: str,
        destination: str,
        maximum: int,
        *,
        commit: str,
    ) -> None:
        assert commit == _CHANNEL_COMMIT
        assert (
            maximum
            == {
                "stable.txt": upgrade_module.MAX_CHANNEL_BYTES,
                "stable.txt.bundle": upgrade_module._RELEASE_CHANNEL_BUNDLE_MAX_BYTES,
            }[name]
        )
        Path(destination).write_bytes(channel_payloads[name])
        os.chmod(destination, 0o600)

    def download_resolver(
        _url: str,
        destination: str,
        _maximum: int,
    ) -> None:
        Path(destination).write_bytes(resolver)
        os.chmod(destination, 0o600)

    return download_ref, download_channel, download_resolver


def _poisoned_environment() -> dict[str, str]:
    return {
        "VERSION": "poisoned",
        "PYTHONHOME": "/poisoned/home",
        "PYTHONPATH": "/poisoned/path",
        "BASH_ENV": "/poisoned/bash-env",
        "ENV": "/poisoned/env",
        "SHELLOPTS": "xtrace",
        "BASHOPTS": "extdebug",
        "BASH_XTRACEFD": "9",
        "IFS": "poisoned",
        "LD_PRELOAD": "/poisoned/preload",
        "LD_AUDIT": "/poisoned/audit",
        "LD_LIBRARY_PATH": "/poisoned/library",
        "DYLD_INSERT_LIBRARIES": "/poisoned/insert",
        "DYLD_LIBRARY_PATH": "/poisoned/dyld-library",
        "SSL_CERT_FILE": "/poisoned/ssl-cert.pem",
        "SSL_CERT_DIR": "/poisoned/ssl-certs",
        "REQUESTS_CA_BUNDLE": "/poisoned/requests-ca.pem",
        "CURL_CA_BUNDLE": "/poisoned/curl-ca.pem",
        "SIGSTORE_ROOT_FILE": "/poisoned/sigstore-root",
        "SIGSTORE_REKOR_PUBLIC_KEY": "/poisoned/rekor",
        "SIGSTORE_CT_LOG_PUBLIC_KEY_FILE": "/poisoned/ct-log",
        "SIGSTORE_TSA_CERTIFICATE_FILE": "/poisoned/tsa",
        "SIGSTORE_FUTURE_TRUST_OVERRIDE": "/poisoned/future-sigstore",
        "TUF_ROOT": "/poisoned/tuf-root",
        "TUF_MIRROR": "https://attacker.invalid",
        "TUF_ROOT_JSON": "/poisoned/tuf-root.json",
        "TUF_FUTURE_TRUST_OVERRIDE": "/poisoned/future-tuf",
        "COSIGN_REKOR_URL": "https://attacker.invalid",
        "BASH_FUNC_poisoned%%": "() { printf poisoned; }",
        "HTTPS_PROXY": "http://corporate-proxy.invalid:8080",
        "PRESERVED_OPERATOR_VALUE": "yes",
    }


def _assert_environment_sanitized(environment: dict[str, str]) -> None:
    assert environment["PRESERVED_OPERATOR_VALUE"] == "yes"
    assert environment["HTTPS_PROXY"] == "http://corporate-proxy.invalid:8080"
    assert set(upgrade_module._AUTHENTICATED_CHILD_ENV_REMOVALS).isdisjoint(environment)
    assert {
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
    }.isdisjoint(environment)
    assert not any(name.startswith(upgrade_module._AUTHENTICATED_CHILD_ENV_PREFIX_REMOVALS) for name in environment)


def test_authenticated_environment_clears_complete_shell_interpreter_loader_policy() -> None:
    poisoned = {name: "poisoned" for name in upgrade_module._AUTHENTICATED_CHILD_ENV_REMOVALS}
    poisoned.update(
        {
            "BASH_FUNC_poisoned%%": "() { :; }",
            "COSIGN_FUTURE_OVERRIDE": "poisoned",
            "DYLD_FUTURE_LOADER_OVERRIDE": "poisoned",
            "LD_FUTURE_LOADER_OVERRIDE": "poisoned",
            "SIGSTORE_FUTURE_OVERRIDE": "poisoned",
            "TUF_FUTURE_OVERRIDE": "poisoned",
            "HTTPS_PROXY": "http://corporate-proxy.invalid:8080",
        }
    )

    sanitized = upgrade_module._sanitize_authenticated_environment(poisoned)

    assert sanitized == {
        "HTTPS_PROXY": "http://corporate-proxy.invalid:8080",
    }


def test_main_delegates_before_click_config_or_cursor_gates() -> None:
    with (
        patch.object(main_module.ux, "_configured_unicode_output", None),
        patch.object(sys, "argv", ["defenseclaw", "upgrade", "--yes"]),
        patch.object(
            main_module,
            "_maybe_delegate_public_upgrade",
            side_effect=SystemExit(23),
        ) as delegate,
        patch.object(main_module, "_try_launch_tui") as tui,
        patch.object(main_module, "cli") as cli,
        patch("defenseclaw.config.load") as config_load,
        pytest.raises(SystemExit) as raised,
    ):
        main_module.main()

    assert raised.value.code == 23
    delegate.assert_called_once_with(["upgrade", "--yes"])
    tui.assert_not_called()
    cli.assert_not_called()
    config_load.assert_not_called()


def test_public_delegation_forwards_exact_intent_and_sanitizes_every_child(
    capsys: pytest.CaptureFixture[str],
) -> None:
    bash = SimpleNamespace(path="/bin/bash", assert_stable=Mock())
    with (
        patch.dict(os.environ, _poisoned_environment(), clear=True),
        patch.object(upgrade_module.platform, "system", return_value="Linux"),
        patch.object(upgrade_module.os, "name", "posix"),
        patch.object(
            upgrade_module,
            "_authenticated_release_resolver",
            return_value=nullcontext((bash, "/private/resolver", _VERSION)),
        ) as authenticate,
        patch.object(
            upgrade_module.subprocess,
            "run",
            return_value=Mock(returncode=17),
        ) as run,
        pytest.raises(SystemExit) as raised,
    ):
        upgrade_module._maybe_delegate_public_upgrade(
            [
                "upgrade",
                "--yes",
                "--recover-corrupt-audit",
                "--version=v8.7.6",
            ],
        )

    assert raised.value.code == 17
    assert run.call_args.args[0] == [
        "/bin/bash",
        "/private/resolver",
        "--yes",
        "--recover-corrupt-audit",
        "--version",
        "8.7.6",
    ]
    authenticated_env = authenticate.call_args.kwargs["environment"]
    _assert_environment_sanitized(authenticated_env)
    child_env = run.call_args.kwargs["env"]
    _assert_environment_sanitized(child_env)
    assert child_env["DEFENSECLAW_UPGRADE_FRESH_PROCESS"] == "1"
    assert run.call_args.kwargs["check"] is False
    assert "shell" not in run.call_args.kwargs
    bash.assert_stable.assert_called_once_with()
    output = capsys.readouterr().out
    for name in upgrade_module._AUTHENTICATED_CA_OVERRIDE_ENV:
        assert name in output
        assert _poisoned_environment()[name] not in output
    assert "Authenticated resolver and verifier child processes" in output
    assert "HTTPS proxy variables remain enabled for their network requests" in output


def test_latest_mode_uses_authenticated_channel_target_explicitly() -> None:
    bash = SimpleNamespace(path="/bin/bash", assert_stable=Mock())
    with (
        patch.dict(os.environ, {}, clear=True),
        patch.object(upgrade_module.platform, "system", return_value="Linux"),
        patch.object(upgrade_module.os, "name", "posix"),
        patch.object(
            upgrade_module,
            "_authenticated_release_resolver",
            return_value=nullcontext((bash, "/private/resolver", _VERSION)),
        ),
        patch.object(upgrade_module, "_fetch_latest_version") as unsigned_latest,
        patch.object(
            upgrade_module.subprocess,
            "run",
            return_value=Mock(returncode=0),
        ) as run,
        pytest.raises(SystemExit) as raised,
    ):
        upgrade_module._maybe_delegate_public_upgrade(
            ["upgrade", "-y", "--health-timeout=60"],
        )

    assert raised.value.code == 0
    assert run.call_args.args[0] == [
        "/bin/bash",
        "/private/resolver",
        "--yes",
        "--version",
        _VERSION,
    ]
    unsigned_latest.assert_not_called()


@pytest.mark.parametrize(
    "handoff",
    (
        {"DEFENSECLAW_UPGRADE_FRESH_PROCESS": "1"},
        {"DEFENSECLAW_STAGED_UPGRADE": "1"},
    ),
)
def test_internal_handoff_bypasses_launcher_without_parsing_future_flags(
    handoff: dict[str, str],
) -> None:
    with (
        patch.dict(os.environ, handoff, clear=True),
        patch.object(upgrade_module, "_authenticated_release_resolver") as authenticate,
    ):
        upgrade_module._maybe_delegate_public_upgrade(
            ["upgrade", "--future-resolver-controller-flag"],
        )

    authenticate.assert_not_called()


def test_upgrade_help_bypasses_launcher() -> None:
    with (
        patch.dict(os.environ, {}, clear=True),
        patch.object(upgrade_module, "_authenticated_release_resolver") as authenticate,
    ):
        upgrade_module._maybe_delegate_public_upgrade(["upgrade", "--help"])
    authenticate.assert_not_called()


@_POSIX_ONLY
def test_authentication_uses_signed_channel_digest_marker_and_sanitized_syntax() -> None:
    resolver = _resolver_payload()
    download_ref, download_channel, download_resolver = _channel_downloaders(resolver)
    bash = SimpleNamespace(path="/bin/bash", assert_stable=Mock())
    trusted_environment = _poisoned_environment()

    def run_command(argv: list[str], **_kwargs):
        if argv[1] == "verify-blob":
            return Mock(returncode=0)
        assert argv[1] == "-n"
        return Mock(returncode=0)

    with (
        patch.object(
            upgrade_module,
            "_trusted_system_bash",
            return_value=nullcontext(bash),
        ),
        patch.object(
            upgrade_module,
            "_download_private_release_channel_ref",
            side_effect=download_ref,
        ),
        patch.object(
            upgrade_module,
            "_download_private_channel_asset",
            side_effect=download_channel,
        ),
        patch.object(
            upgrade_module,
            "_download_private_channel_resolver",
            side_effect=download_resolver,
        ) as resolver_download,
        patch.object(
            upgrade_module,
            "_cosign_verifier",
            return_value=nullcontext("/private/cosign"),
        ),
        patch.object(
            upgrade_module.subprocess,
            "run",
            side_effect=run_command,
        ) as run,
        upgrade_module._authenticated_release_resolver(
            environment=trusted_environment,
        ) as (trusted_bash, path, resolver_version),
    ):
        assert trusted_bash is bash
        assert resolver_version == _VERSION
        assert Path(path).read_bytes() == resolver

    verify_argv = run.call_args_list[0].args[0]
    assert verify_argv[:2] == ["/private/cosign", "verify-blob"]
    assert "--bundle" in verify_argv
    identity_index = verify_argv.index("--certificate-identity")
    assert verify_argv[identity_index + 1] == (
        "https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main"
    )
    assert resolver_download.call_args.args[0] == (
        f"https://github.com/{upgrade_module.GITHUB_REPO}/releases/download/{_VERSION}/defenseclaw-upgrade.sh"
    )
    assert run.call_args_list[1].args[0][0:2] == ["/bin/bash", "-n"]
    for call in run.call_args_list:
        _assert_environment_sanitized(call.kwargs["env"])
        assert call.kwargs.get("shell") is not True
    verification_environment = run.call_args_list[0].kwargs["env"]
    assert "defenseclaw-sigstore-home-" in verification_environment["HOME"]
    for name in (
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
    ):
        assert "defenseclaw-sigstore-home-" in verification_environment[name]
    bash.assert_stable.assert_called_once_with()


@_POSIX_ONLY
def test_channel_rotation_retries_only_commit_pinned_authenticated_pairs() -> None:
    resolver = _resolver_payload()
    channel_payload = _channel_payload(resolver)
    commits = iter(("d" * 40, "e" * 40))
    channel_downloads: list[tuple[str, str]] = []
    bash = SimpleNamespace(path="/bin/bash", assert_stable=Mock())

    def download_ref(destination: str, _maximum: int) -> None:
        Path(destination).write_text(
            json.dumps(
                {
                    "ref": "refs/heads/release-channel",
                    "object": {"type": "commit", "sha": next(commits)},
                }
            ),
            encoding="utf-8",
        )
        os.chmod(destination, 0o600)

    def download_channel(
        name: str,
        destination: str,
        _maximum: int,
        *,
        commit: str,
    ) -> None:
        channel_downloads.append((name, commit))
        payload = channel_payload if name == "stable.txt" else f"bundle for {commit}\n".encode()
        Path(destination).write_bytes(payload)
        os.chmod(destination, 0o600)

    def download_resolver(
        _url: str,
        destination: str,
        _maximum: int,
    ) -> None:
        Path(destination).write_bytes(resolver)
        os.chmod(destination, 0o600)

    verification_attempt = 0

    def run_command(argv: list[str], **_kwargs):
        nonlocal verification_attempt
        if argv[1] == "verify-blob":
            verification_attempt += 1
            return Mock(returncode=1 if verification_attempt == 1 else 0)
        assert argv[1] == "-n"
        return Mock(returncode=0)

    with (
        patch.object(
            upgrade_module,
            "_trusted_system_bash",
            return_value=nullcontext(bash),
        ),
        patch.object(
            upgrade_module,
            "_download_private_release_channel_ref",
            side_effect=download_ref,
        ),
        patch.object(
            upgrade_module,
            "_download_private_channel_asset",
            side_effect=download_channel,
        ),
        patch.object(
            upgrade_module,
            "_download_private_channel_resolver",
            side_effect=download_resolver,
        ),
        patch.object(
            upgrade_module,
            "_cosign_verifier",
            return_value=nullcontext("/private/cosign"),
        ),
        patch.object(upgrade_module.time, "sleep") as retry_wait,
        patch.object(
            upgrade_module.subprocess,
            "run",
            side_effect=run_command,
        ),
        upgrade_module._authenticated_release_resolver() as (
            _trusted_bash,
            _resolver_path,
            resolver_version,
        ),
    ):
        assert resolver_version == _VERSION

    assert channel_downloads == [
        ("stable.txt", "d" * 40),
        ("stable.txt.bundle", "d" * 40),
        ("stable.txt.bundle", "e" * 40),
        ("stable.txt", "e" * 40),
    ]
    retry_wait.assert_called_once_with(upgrade_module._RELEASE_CHANNEL_RETRY_DELAYS[0])


def test_channel_retry_schedule_is_finite_monotonic_and_bound_to_attempts() -> None:
    delays = upgrade_module._RELEASE_CHANNEL_RETRY_DELAYS

    assert len(delays) == max(upgrade_module._RELEASE_CHANNEL_AUTH_ATTEMPTS - 1, 0)
    assert all(math.isfinite(delay) and delay > 0 for delay in delays)
    assert all(previous < current for previous, current in zip(delays, delays[1:], strict=False))


@_POSIX_ONLY
def test_channel_authentication_retries_transient_ref_download_failure() -> None:
    resolver = _resolver_payload()
    download_ref, download_channel, download_resolver = _channel_downloaders(resolver)
    bash = SimpleNamespace(path="/bin/bash", assert_stable=Mock())
    ref_attempts = 0

    def transient_ref_download(destination: str, maximum: int) -> None:
        nonlocal ref_attempts
        ref_attempts += 1
        if ref_attempts == 1:
            raise OSError("transient release-channel ref failure")
        download_ref(destination, maximum)

    def run_command(argv: list[str], **_kwargs):
        if argv[1] == "verify-blob":
            return Mock(returncode=0)
        assert argv[1] == "-n"
        return Mock(returncode=0)

    with (
        patch.object(
            upgrade_module,
            "_trusted_system_bash",
            return_value=nullcontext(bash),
        ),
        patch.object(
            upgrade_module,
            "_download_private_release_channel_ref",
            side_effect=transient_ref_download,
        ),
        patch.object(
            upgrade_module,
            "_download_private_channel_asset",
            side_effect=download_channel,
        ),
        patch.object(
            upgrade_module,
            "_download_private_channel_resolver",
            side_effect=download_resolver,
        ),
        patch.object(
            upgrade_module,
            "_cosign_verifier",
            return_value=nullcontext("/private/cosign"),
        ),
        patch.object(upgrade_module.time, "sleep") as retry_wait,
        patch.object(
            upgrade_module.subprocess,
            "run",
            side_effect=run_command,
        ),
        upgrade_module._authenticated_release_resolver() as (
            _trusted_bash,
            _resolver_path,
            resolver_version,
        ),
    ):
        assert resolver_version == _VERSION

    assert ref_attempts == 2
    retry_wait.assert_called_once_with(upgrade_module._RELEASE_CHANNEL_RETRY_DELAYS[0])


@_POSIX_ONLY
def test_channel_retry_cleanup_never_masks_the_download_failure(tmp_path: Path) -> None:
    download_error = OSError("transient release-channel ref failure")

    with (
        patch.object(
            upgrade_module,
            "_download_private_release_channel_ref",
            side_effect=download_error,
        ),
        patch.object(upgrade_module.shutil, "rmtree") as cleanup,
        patch.object(upgrade_module.time, "sleep"),
        pytest.raises(
            OSError,
            match="stable channel download failed after .* bounded attempts: transient release-channel ref failure",
        ),
    ):
        upgrade_module._download_authenticated_channel_pair(
            directory=str(tmp_path),
            cosign="/private/cosign",
            cosign_environment={},
        )

    assert cleanup.call_count == upgrade_module._RELEASE_CHANNEL_AUTH_ATTEMPTS
    assert all(call.kwargs == {"ignore_errors": True} for call in cleanup.call_args_list)


@pytest.mark.parametrize(
    "payload",
    (
        (
            '{"ref":"refs/heads/release-channel","object":'
            '{"type":"commit","sha":"' + "a" * 40 + '","sha":"' + "b" * 40 + '"}}'
        ),
        (
            '{"ref":"refs/heads/release-channel","shadow":{"sha":"'
            + "a" * 40
            + '"},"object":{"type":"commit","sha":"'
            + "b" * 40
            + '"}}'
        ),
    ),
)
def test_channel_ref_rejects_duplicate_or_ambiguous_commit_ids(
    tmp_path: Path,
    payload: str,
) -> None:
    path = tmp_path / "ref.json"
    path.write_text(payload, encoding="ascii")

    with pytest.raises(OSError, match="exactly one canonical commit ID"):
        upgrade_module._release_channel_commit_from_ref(str(path))


def test_channel_ref_rejects_duplicate_non_sha_json_fields(tmp_path: Path) -> None:
    path = tmp_path / "ref.json"
    path.write_text(
        (
            '{"ref":"refs/heads/release-channel",'
            '"ref":"refs/heads/attacker",'
            '"object":{"type":"commit","sha":"' + "a" * 40 + '"}}'
        ),
        encoding="ascii",
    )

    with pytest.raises(OSError, match="invalid JSON"):
        upgrade_module._release_channel_commit_from_ref(str(path))


@_POSIX_ONLY
def test_bad_channel_signature_fails_before_resolver_download() -> None:
    resolver = _resolver_payload()
    download_ref, download_channel, _download_resolver = _channel_downloaders(resolver)
    bash = SimpleNamespace(path="/bin/bash", assert_stable=Mock())
    with (
        patch.object(
            upgrade_module,
            "_trusted_system_bash",
            return_value=nullcontext(bash),
        ),
        patch.object(
            upgrade_module,
            "_download_private_release_channel_ref",
            side_effect=download_ref,
        ),
        patch.object(
            upgrade_module,
            "_download_private_channel_asset",
            side_effect=download_channel,
        ),
        patch.object(
            upgrade_module,
            "_download_private_channel_resolver",
        ) as resolver_download,
        patch.object(
            upgrade_module,
            "_cosign_verifier",
            return_value=nullcontext("/private/cosign"),
        ),
        patch.object(upgrade_module.time, "sleep"),
        patch.object(
            upgrade_module.subprocess,
            "run",
            return_value=Mock(returncode=1),
        ),
        pytest.raises(OSError, match="stable channel signature"),
    ):
        with upgrade_module._authenticated_release_resolver():
            pass

    resolver_download.assert_not_called()


@_POSIX_ONLY
def test_bad_channel_signature_retains_most_recent_download_failure(
    tmp_path: Path,
) -> None:
    resolver = _resolver_payload()
    download_ref, download_channel, _download_resolver = _channel_downloaders(resolver)
    ref_attempt = 0

    def transient_ref_failure(destination: str, maximum: int) -> None:
        nonlocal ref_attempt
        ref_attempt += 1
        if ref_attempt == 1:
            raise OSError("transient channel locator failure")
        download_ref(destination, maximum)

    with (
        patch.object(
            upgrade_module,
            "_download_private_release_channel_ref",
            side_effect=transient_ref_failure,
        ),
        patch.object(
            upgrade_module,
            "_download_private_channel_asset",
            side_effect=download_channel,
        ),
        patch.object(upgrade_module.time, "sleep"),
        patch.object(
            upgrade_module.subprocess,
            "run",
            return_value=Mock(returncode=1),
        ),
        pytest.raises(
            OSError,
            match=("stable channel signature.*most recent channel download failure: transient channel locator failure"),
        ),
    ):
        upgrade_module._download_authenticated_channel_pair(
            directory=str(tmp_path),
            cosign="/private/cosign",
            cosign_environment={},
        )


@_POSIX_ONLY
@pytest.mark.parametrize(
    "mode",
    ("tampered", "truncated", "malformed-channel", "wrong-repository"),
)
def test_unbound_or_incomplete_resolver_never_reaches_execution(mode: str) -> None:
    signed = _resolver_payload()
    resolver = signed + b"# tampered\n" if mode == "tampered" else signed
    if mode == "truncated":
        resolver = b"#!/usr/bin/env bash\nprintf 'resolver\\n'\n"
    channel = _channel_payload(signed)
    if mode == "malformed-channel":
        channel = channel.replace(b"channel=stable\n", b"channel=other\n")
    elif mode == "wrong-repository":
        channel = _channel_payload(signed, repository="attacker/defenseclaw")
    download_ref, download_channel, download_resolver = _channel_downloaders(
        resolver,
        channel=channel,
    )
    bash = SimpleNamespace(path="/private/bash", assert_stable=Mock())

    with (
        patch.object(
            upgrade_module,
            "_trusted_system_bash",
            return_value=nullcontext(bash),
        ),
        patch.object(
            upgrade_module,
            "_download_private_release_channel_ref",
            side_effect=download_ref,
        ),
        patch.object(
            upgrade_module,
            "_download_private_channel_asset",
            side_effect=download_channel,
        ),
        patch.object(
            upgrade_module,
            "_download_private_channel_resolver",
            side_effect=download_resolver,
        ),
        patch.object(
            upgrade_module,
            "_cosign_verifier",
            return_value=nullcontext("/private/cosign"),
        ),
        patch.object(
            upgrade_module.subprocess,
            "run",
            return_value=Mock(returncode=0),
        ) as run,
        pytest.raises(OSError),
    ):
        with upgrade_module._authenticated_release_resolver():
            pass

    assert len(run.call_args_list) == 1
    assert run.call_args.args[0][1] == "verify-blob"


@pytest.mark.parametrize(
    "arguments",
    (
        ["upgrade", "--allow-unverified"],
        ["upgrade", "--health-timeout", "61"],
    ),
)
def test_unsupported_public_intent_fails_before_channel_authentication(
    arguments: list[str],
) -> None:
    with (
        patch.dict(os.environ, {}, clear=True),
        patch.object(upgrade_module.platform, "system", return_value="Linux"),
        patch.object(upgrade_module.os, "name", "posix"),
        patch.object(upgrade_module, "_authenticated_release_resolver") as authenticate,
        pytest.raises(SystemExit) as raised,
    ):
        upgrade_module._maybe_delegate_public_upgrade(arguments)

    assert raised.value.code == 2
    authenticate.assert_not_called()


def test_windows_bypasses_shim_and_rejects_corrupt_audit_recovery() -> None:
    with (
        patch.dict(os.environ, {}, clear=True),
        patch.object(upgrade_module.platform, "system", return_value="Windows"),
        patch.object(upgrade_module.upgrade, "make_context") as parse_intent,
    ):
        upgrade_module._maybe_delegate_public_upgrade(["upgrade", "--yes"])

    parse_intent.assert_not_called()

    runner = CliRunner()
    with patch.object(upgrade_module.platform, "system", return_value="Windows"):
        result = runner.invoke(
            upgrade_module.upgrade,
            ["--recover-corrupt-audit", "--version", _VERSION],
            obj=SimpleNamespace(cfg=None),
        )
    assert result.exit_code == 2
    assert "not supported by the native Windows upgrader" in result.output


@_POSIX_ONLY
def test_system_bash_is_root_owned_bounded_and_stable_while_open() -> None:
    with upgrade_module._trusted_system_bash() as bash:
        named = os.lstat(bash.path)
        assert named.st_uid == 0
        assert named.st_mode & 0o022 == 0
        assert 0 < named.st_size <= upgrade_module._MAX_SYSTEM_BASH_BYTES
        bash.assert_stable()

        changed = SimpleNamespace(
            st_dev=named.st_dev,
            st_ino=named.st_ino + 1,
            st_mode=named.st_mode,
            st_uid=named.st_uid,
            st_gid=named.st_gid,
            st_size=named.st_size,
        )
        with (
            patch.object(upgrade_module.os, "lstat", return_value=changed),
            pytest.raises(OSError, match="identity changed"),
        ):
            bash.assert_stable()


@_POSIX_ONLY
def test_strict_cosign_never_executes_unpinned_path_binary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ambient = tmp_path / "cosign"
    ambient.write_bytes(b"#!/bin/sh\nprintf compromised\n")
    ambient.chmod(0o755)
    authenticated = tmp_path / "authenticated-cosign"
    authenticated.write_bytes(b"pinned verifier")
    authenticated.chmod(0o700)

    with (
        patch.object(upgrade_module.shutil, "which", return_value=str(ambient)),
        patch.object(
            upgrade_module,
            "_copy_authenticated_cosign",
            side_effect=OSError("digest mismatch"),
        ) as copy_cosign,
        patch.object(
            upgrade_module,
            "_download_bootstrap_cosign",
            return_value=str(authenticated),
        ) as download_cosign,
        upgrade_module._cosign_verifier(strict=True) as verifier,
    ):
        assert verifier == str(authenticated)

    copy_cosign.assert_called_once()
    download_cosign.assert_called_once()
    output = capsys.readouterr().out
    assert "Ambient Cosign was rejected by pinned digest or custody checks" in output
    assert str(ambient) not in output
    assert "digest mismatch" not in output


@_POSIX_ONLY
def test_matching_path_cosign_is_copied_into_private_digest_bound_custody(
    tmp_path: Path,
) -> None:
    payload = b"pinned cosign fixture"
    ambient = tmp_path / "cosign"
    ambient.write_bytes(payload)
    ambient.chmod(0o755)
    digest = hashlib.sha256(payload).hexdigest()
    os_name, arch = upgrade_module._detect_platform()

    with (
        patch.dict(
            upgrade_module.COSIGN_BOOTSTRAP_SHA256,
            {(os_name, arch): digest},
            clear=False,
        ),
        TemporaryDirectory() as directory,
    ):
        os.chmod(directory, 0o700)
        copied = upgrade_module._copy_authenticated_cosign(str(ambient), directory)
        assert copied != str(ambient)
        assert Path(copied).read_bytes() == payload
        assert stat.S_IMODE(os.lstat(copied).st_mode) == 0o700


@_POSIX_ONLY
def test_matching_symlinked_path_cosign_is_copied_from_open_descriptor(
    tmp_path: Path,
) -> None:
    payload = b"pinned symlinked cosign fixture"
    target = tmp_path / "cosign-target"
    target.write_bytes(payload)
    target.chmod(0o755)
    ambient = tmp_path / "cosign"
    ambient.symlink_to(target)
    digest = hashlib.sha256(payload).hexdigest()
    os_name, arch = upgrade_module._detect_platform()

    with (
        patch.dict(
            upgrade_module.COSIGN_BOOTSTRAP_SHA256,
            {(os_name, arch): digest},
            clear=False,
        ),
        TemporaryDirectory() as directory,
    ):
        os.chmod(directory, 0o700)
        copied = upgrade_module._copy_authenticated_cosign(str(ambient), directory)
        assert copied != str(ambient)
        assert Path(copied).read_bytes() == payload
        assert stat.S_IMODE(os.lstat(copied).st_mode) == 0o700


@_POSIX_ONLY
def test_ambient_cosign_copy_never_unlinks_a_preexisting_destination(
    tmp_path: Path,
) -> None:
    ambient = tmp_path / "cosign"
    ambient.write_bytes(b"ambient verifier")
    ambient.chmod(0o755)
    os_name, arch = upgrade_module._detect_platform()
    destination_dir = tmp_path / "private"
    destination_dir.mkdir(mode=0o700)
    destination = destination_dir / f"cosign-{os_name}-{arch}-authenticated"
    destination.write_bytes(b"preexisting custody")
    destination.chmod(0o600)

    with pytest.raises(FileExistsError):
        upgrade_module._copy_authenticated_cosign(
            str(ambient),
            str(destination_dir),
        )

    assert destination.read_bytes() == b"preexisting custody"


@_POSIX_ONLY
def test_private_downloader_enforces_size_mode_and_redirect_policy() -> None:
    response = Mock(
        status_code=200,
        headers={},
        iter_content=Mock(return_value=[b"bounded"]),
    )
    with (
        TemporaryDirectory() as directory,
        patch.dict(os.environ, {}, clear=True),
        patch.object(upgrade_module.requests, "get", return_value=response),
    ):
        destination = str(Path(directory, "resolver"))
        upgrade_module._download_private_channel_resolver(
            (f"https://github.com/{upgrade_module.GITHUB_REPO}/releases/download/{_VERSION}/defenseclaw-upgrade.sh"),
            destination,
            16,
        )
        info = os.lstat(destination)
        assert info.st_size == len(b"bounded")
        assert stat.S_IMODE(info.st_mode) == 0o600

    oversized = Mock(
        status_code=200,
        headers={},
        iter_content=Mock(return_value=[b"too-large"]),
    )
    with (
        TemporaryDirectory() as directory,
        patch.dict(os.environ, {}, clear=True),
        patch.object(upgrade_module.requests, "get", return_value=oversized),
        pytest.raises(OSError, match="size limit"),
    ):
        upgrade_module._download_private_channel_resolver(
            (f"https://github.com/{upgrade_module.GITHUB_REPO}/releases/download/{_VERSION}/defenseclaw-upgrade.sh"),
            str(Path(directory, "oversized")),
            4,
        )

    redirect = Mock(
        status_code=302,
        headers={"location": "https://untrusted.example/evidence"},
    )
    with (
        patch.dict(os.environ, {}, clear=True),
        patch.object(upgrade_module.requests, "get", return_value=redirect),
        pytest.raises(OSError, match="pinned HTTPS host set"),
    ):
        upgrade_module._download_private_channel_resolver(
            (f"https://github.com/{upgrade_module.GITHUB_REPO}/releases/download/{_VERSION}/defenseclaw-upgrade.sh"),
            "/unused/evidence",
            16,
        )


@pytest.mark.parametrize(
    "url",
    (
        f"https://raw.githubusercontent.com/{upgrade_module.GITHUB_REPO}/{'d' * 40}/stable.txt",
        f"https://raw.githubusercontent.com/{upgrade_module.GITHUB_REPO}/{_CHANNEL_COMMIT}/stable.txt.bundle",
    ),
)
def test_channel_asset_redirect_stays_bound_to_requested_commit_and_name(
    url: str,
) -> None:
    with pytest.raises(OSError, match="pinned HTTPS endpoint"):
        upgrade_module._validate_release_channel_url(
            url,
            commit=_CHANNEL_COMMIT,
            name="stable.txt",
        )

    upgrade_module._validate_release_channel_url(
        f"https://raw.githubusercontent.com/{upgrade_module.GITHUB_REPO}/{_CHANNEL_COMMIT}/stable.txt",
        commit=_CHANNEL_COMMIT,
        name="stable.txt",
    )


@_POSIX_ONLY
def test_private_download_paths_share_one_bounded_redirect_budget(
    tmp_path: Path,
) -> None:
    asset_url = f"https://github.com/{upgrade_module.GITHUB_REPO}/releases/download/{_VERSION}/defenseclaw-upgrade.sh"
    redirect = Mock(
        status_code=302,
        headers={"location": asset_url},
    )
    with (
        patch.dict(os.environ, {}, clear=True),
        patch.object(
            upgrade_module.requests,
            "get",
            return_value=redirect,
        ) as private_get,
        pytest.raises(OSError, match="redirect limit"),
    ):
        upgrade_module._download_private_channel_resolver(
            asset_url,
            str(tmp_path / "resolver"),
            16,
        )
    assert private_get.call_count == upgrade_module._MAX_PRIVATE_REDIRECTS

    cosign_url = (
        "https://github.com/sigstore/cosign/releases/download/"
        f"v{upgrade_module.COSIGN_BOOTSTRAP_VERSION}/cosign-linux-amd64"
    )
    cosign_redirect = Mock(
        status_code=302,
        headers={"location": cosign_url},
    )
    cosign_destination = tmp_path / "cosign"
    cosign_destination.mkdir()
    cosign_destination.chmod(0o700)
    with (
        patch.object(
            upgrade_module,
            "_detect_platform",
            return_value=("linux", "amd64"),
        ),
        patch.object(
            upgrade_module.requests,
            "get",
            return_value=cosign_redirect,
        ) as cosign_get,
        pytest.raises(OSError, match="redirect limit"),
    ):
        upgrade_module._download_bootstrap_cosign(str(cosign_destination))
    assert cosign_get.call_count == upgrade_module._MAX_PRIVATE_REDIRECTS


def test_no_shell_execution_in_public_bootstrap_source() -> None:
    source = Path(upgrade_module.__file__).read_text(encoding="utf-8")
    start = source.index("def _maybe_delegate_public_upgrade")
    end = source.index("def _github_headers", start)
    bootstrap = source[start:end]
    assert "shell" + "=True" not in bootstrap
    assert "os." + "system(" not in bootstrap
    assert " | " + "bash" not in bootstrap
