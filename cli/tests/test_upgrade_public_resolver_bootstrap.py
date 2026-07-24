# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import os
import sys
from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

import defenseclaw.commands.cmd_upgrade as upgrade_module
import defenseclaw.main as main_module
import pytest
from defenseclaw.resolver_hint import RESOLVER_COMPLETENESS_MARKER

_POSIX_ONLY = pytest.mark.skipif(
    os.name != "posix",
    reason="release-resolver authentication uses POSIX file custody",
)


def _resolver_payload() -> bytes:
    return f"#!/usr/bin/env bash\nprintf 'resolver\\n'\n{RESOLVER_COMPLETENESS_MARKER}\n".encode()


def _evidence_downloader(
    resolver: bytes,
    *,
    checksum_rows: list[str] | None = None,
    missing: str | None = None,
):
    digest = hashlib.sha256(resolver).hexdigest()
    rows = checksum_rows or [f"{digest}  defenseclaw-upgrade.sh"]
    payloads = {
        "defenseclaw-upgrade.sh": resolver,
        "checksums.txt": ("\n".join(rows) + "\n").encode(),
        "checksums.txt.sig": b"signature\n",
        "checksums.txt.pem": b"certificate\n",
    }

    def download(_version: str, name: str, destination: str, _maximum: int) -> None:
        if name == missing:
            raise OSError(f"{name} unavailable")
        Path(destination).write_bytes(payloads[name])
        os.chmod(destination, 0o600)

    return download


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


def test_public_delegation_forwards_exact_intent_and_marks_handoff() -> None:
    bash = SimpleNamespace(path="/bin/bash", assert_stable=Mock())
    with (
        patch.dict(
            os.environ,
            {
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
                "LD_LIBRARY_PATH": "/poisoned/library",
                "DYLD_INSERT_LIBRARIES": "/poisoned/insert",
                "DYLD_LIBRARY_PATH": "/poisoned/dyld-library",
                "BASH_FUNC_poisoned%%": "() { printf poisoned; }",
                "PRESERVED_OPERATOR_VALUE": "yes",
            },
            clear=True,
        ),
        patch.object(upgrade_module.platform, "system", return_value="Linux"),
        patch.object(upgrade_module.os, "name", "posix"),
        patch.object(upgrade_module, "_fetch_latest_version", return_value="9.9.9"),
        patch.object(
            upgrade_module,
            "_authenticated_release_resolver",
            return_value=nullcontext((bash, "/private/resolver")),
        ),
        patch.object(
            upgrade_module.subprocess,
            "run",
            return_value=Mock(returncode=17),
        ) as run,
        pytest.raises(SystemExit) as raised,
    ):
        upgrade_module._maybe_delegate_public_upgrade(
            ["upgrade", "--yes", "--version=v8.7.6"],
        )

    assert raised.value.code == 17
    assert run.call_args.args[0] == [
        "/bin/bash",
        "/private/resolver",
        "--yes",
        "--version",
        "8.7.6",
    ]
    child_env = run.call_args.kwargs["env"]
    assert child_env["DEFENSECLAW_UPGRADE_FRESH_PROCESS"] == "1"
    assert child_env["PRESERVED_OPERATOR_VALUE"] == "yes"
    assert "VERSION" not in child_env
    assert "PYTHONHOME" not in child_env
    assert "PYTHONPATH" not in child_env
    assert {
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
        "BASHOPTS",
        "BASH_XTRACEFD",
        "IFS",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "BASH_FUNC_poisoned%%",
    }.isdisjoint(child_env)
    assert run.call_args.kwargs["check"] is False
    assert "shell" not in run.call_args.kwargs
    bash.assert_stable.assert_called_once_with()


def test_latest_mode_stays_implicit_for_resolver_auto_bridge() -> None:
    bash = SimpleNamespace(path="/bin/bash", assert_stable=Mock())
    with (
        patch.dict(os.environ, {}, clear=True),
        patch.object(upgrade_module.platform, "system", return_value="Linux"),
        patch.object(upgrade_module.os, "name", "posix"),
        patch.object(upgrade_module, "_fetch_latest_version", return_value="9.9.9"),
        patch.object(
            upgrade_module,
            "_authenticated_release_resolver",
            return_value=nullcontext((bash, "/private/resolver")),
        ),
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
    assert run.call_args.args[0] == ["/bin/bash", "/private/resolver", "--yes"]


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
        patch.object(upgrade_module, "_fetch_latest_version") as latest,
        patch.object(upgrade_module, "_authenticated_release_resolver") as authenticate,
    ):
        upgrade_module._maybe_delegate_public_upgrade(
            ["upgrade", "--future-resolver-controller-flag"],
        )

    latest.assert_not_called()
    authenticate.assert_not_called()


def test_upgrade_help_bypasses_launcher() -> None:
    with (
        patch.dict(os.environ, {}, clear=True),
        patch.object(upgrade_module, "_fetch_latest_version") as latest,
    ):
        upgrade_module._maybe_delegate_public_upgrade(["upgrade", "--help"])
    latest.assert_not_called()


@_POSIX_ONLY
def test_authentication_uses_exact_identity_digest_marker_and_syntax() -> None:
    resolver = _resolver_payload()
    bash = SimpleNamespace(path="/bin/bash", assert_stable=Mock())

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
            "_download_private_release_asset",
            side_effect=_evidence_downloader(resolver),
        ),
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
        upgrade_module._authenticated_release_resolver("9.9.9") as (trusted_bash, path),
    ):
        assert trusted_bash is bash
        assert Path(path).read_bytes() == resolver

    verify_argv = run.call_args_list[0].args[0]
    assert verify_argv[:2] == ["/private/cosign", "verify-blob"]
    identity_index = verify_argv.index("--certificate-identity")
    assert verify_argv[identity_index + 1] == (
        "https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main"
    )
    assert run.call_args_list[1].args[0][0:2] == ["/bin/bash", "-n"]
    assert all(call.kwargs.get("shell") is not True for call in run.call_args_list)
    bash.assert_stable.assert_called_once_with()


@_POSIX_ONLY
@pytest.mark.parametrize("mode", ("tampered", "missing", "duplicate"))
def test_tampered_or_missing_evidence_fails_before_resolver_execution(mode: str) -> None:
    signed = _resolver_payload()
    resolver = signed + b"# tampered\n" if mode == "tampered" else signed
    digest = hashlib.sha256(signed).hexdigest()
    rows = [f"{digest}  defenseclaw-upgrade.sh"]
    if mode == "duplicate":
        rows.append(rows[0])
    missing = "checksums.txt.sig" if mode == "missing" else None
    bash = SimpleNamespace(path="/bin/bash", assert_stable=Mock())

    def run_command(argv: list[str], **_kwargs):
        assert argv[1] == "verify-blob"
        return Mock(returncode=0)

    with (
        patch.dict(os.environ, {}, clear=True),
        patch.object(upgrade_module.platform, "system", return_value="Linux"),
        patch.object(upgrade_module, "_fetch_latest_version", return_value="9.9.9"),
        patch.object(
            upgrade_module,
            "_trusted_system_bash",
            return_value=nullcontext(bash),
        ),
        patch.object(
            upgrade_module,
            "_download_private_release_asset",
            side_effect=_evidence_downloader(
                resolver,
                checksum_rows=rows,
                missing=missing,
            ),
        ),
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
        patch.object(upgrade_module, "_preflight_installed_source_coherence") as coherence,
        pytest.raises(SystemExit) as raised,
    ):
        upgrade_module._maybe_delegate_public_upgrade(["upgrade", "--yes"])

    assert raised.value.code == 1
    assert all(call.args[0][1] == "verify-blob" for call in run.call_args_list)
    coherence.assert_not_called()


@_POSIX_ONLY
def test_signed_but_truncated_resolver_is_rejected() -> None:
    truncated = b"#!/usr/bin/env bash\nprintf 'resolver\\n'\n"
    digest = hashlib.sha256(truncated).hexdigest()
    bash = SimpleNamespace(path="/private/bash", assert_stable=Mock())

    with (
        patch.object(
            upgrade_module,
            "_trusted_system_bash",
            return_value=nullcontext(bash),
        ),
        patch.object(
            upgrade_module,
            "_download_private_release_asset",
            side_effect=_evidence_downloader(
                truncated,
                checksum_rows=[f"{digest}  defenseclaw-upgrade.sh"],
            ),
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
        ),
        pytest.raises(OSError, match="completeness marker"),
    ):
        with upgrade_module._authenticated_release_resolver("9.9.9"):
            pass


@pytest.mark.parametrize(
    "arguments",
    (
        ["upgrade", "--allow-unverified"],
        ["upgrade", "--health-timeout", "61"],
    ),
)
def test_unsupported_public_intent_fails_before_latest_lookup(arguments: list[str]) -> None:
    with (
        patch.dict(os.environ, {}, clear=True),
        patch.object(upgrade_module.platform, "system", return_value="Linux"),
        patch.object(upgrade_module.os, "name", "posix"),
        patch.object(upgrade_module, "_fetch_latest_version") as latest,
        pytest.raises(SystemExit) as raised,
    ):
        upgrade_module._maybe_delegate_public_upgrade(arguments)

    assert raised.value.code == 2
    latest.assert_not_called()


def test_windows_bypasses_shim_and_preserves_existing_native_setup_path() -> None:
    with (
        patch.dict(os.environ, {}, clear=True),
        patch.object(upgrade_module.platform, "system", return_value="Windows"),
        patch.object(upgrade_module, "_fetch_latest_version") as latest,
        patch.object(upgrade_module.upgrade, "make_context") as parse_intent,
    ):
        upgrade_module._maybe_delegate_public_upgrade(["upgrade", "--yes"])

    latest.assert_not_called()
    parse_intent.assert_not_called()


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
def test_system_bash_rejects_group_or_world_writable_metadata() -> None:
    trusted = os.lstat("/bin/bash")
    writable = SimpleNamespace(
        st_dev=trusted.st_dev,
        st_ino=trusted.st_ino,
        st_mode=trusted.st_mode | 0o022,
        st_uid=0,
        st_gid=trusted.st_gid,
        st_size=trusted.st_size,
    )
    assert not upgrade_module._system_bash_info_is_trusted(writable)


@_POSIX_ONLY
def test_private_downloader_enforces_streamed_size_and_owner_only_mode() -> None:
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
        destination = str(Path(directory, "evidence"))
        upgrade_module._download_private_release_asset(
            "9.9.9",
            "checksums.txt.sig",
            destination,
            16,
        )
        info = os.lstat(destination)
        assert info.st_size == len(b"bounded")
        assert info.st_mode & 0o777 == 0o600

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
        upgrade_module._download_private_release_asset(
            "9.9.9",
            "checksums.txt.sig",
            str(Path(directory, "oversized")),
            4,
        )


@_POSIX_ONLY
def test_private_downloader_rejects_redirect_outside_pinned_hosts() -> None:
    response = Mock(
        status_code=302,
        headers={"location": "https://untrusted.example/evidence"},
    )
    with (
        patch.dict(os.environ, {}, clear=True),
        patch.object(upgrade_module.requests, "get", return_value=response),
        pytest.raises(OSError, match="pinned HTTPS host set"),
    ):
        upgrade_module._download_private_release_asset(
            "9.9.9",
            "checksums.txt.sig",
            "/unused/evidence",
            16,
        )


@_POSIX_ONLY
def test_private_downloader_rejects_redirect_without_location() -> None:
    response = Mock(status_code=302, headers={})
    with (
        patch.dict(os.environ, {}, clear=True),
        patch.object(upgrade_module.requests, "get", return_value=response),
        pytest.raises(OSError, match="no location"),
    ):
        upgrade_module._download_private_release_asset(
            "9.9.9",
            "checksums.txt.sig",
            "/unused/evidence",
            16,
        )


@_POSIX_ONLY
def test_private_downloader_rejects_six_redirects() -> None:
    responses = [
        Mock(
            status_code=302,
            headers={"location": f"https://github.com/redirect-{hop}"},
        )
        for hop in range(6)
    ]
    with (
        patch.dict(os.environ, {}, clear=True),
        patch.object(upgrade_module.requests, "get", side_effect=responses),
        pytest.raises(OSError, match="redirect limit"),
    ):
        upgrade_module._download_private_release_asset(
            "9.9.9",
            "checksums.txt.sig",
            "/unused/evidence",
            16,
        )


def test_no_shell_execution_in_public_bootstrap_source() -> None:
    source = Path(upgrade_module.__file__).read_text(encoding="utf-8")
    start = source.index("def _maybe_delegate_public_upgrade")
    end = source.index("def _github_headers", start)
    bootstrap = source[start:end]
    assert "shell" + "=True" not in bootstrap
    assert "os." + "system(" not in bootstrap
    assert " | " + "bash" not in bootstrap
