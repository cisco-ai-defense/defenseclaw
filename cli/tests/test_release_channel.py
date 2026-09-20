# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest
import yaml
from defenseclaw import release_channel as client_release_channel
from defenseclaw import resolver_hint

from scripts import release_candidate, release_channel

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "cisco-ai-defense/defenseclaw"
VERSION = "0.8.8"
COMMIT = "a" * 40
CHANNEL_BRANCH_COMMIT = "f" * 40
RESCUE = ROOT / "scripts/defenseclaw-rescue.sh"
IMMUTABLE_088_RESCUE = ROOT / "cli/tests/fixtures/release/defenseclaw-rescue-0.8.8.sh"
UPGRADE_RESOLVER = ROOT / "scripts/upgrade.sh"
WINDOWS_RESCUE = ROOT / "scripts/defenseclaw-rescue.ps1"
PUBLISHER = ROOT / "scripts/publish-release-channel.sh"
WORKFLOW = ROOT / ".github/workflows/release.yaml"
DOC = ROOT / "docs/RELEASE_CHANNEL.md"
SCRIPT_TIMEOUT_SECONDS = 30
# Exact authenticated 0.8.8 release asset, retained as a hermetic compatibility
# fixture so current rescue hardening cannot rewrite the published-byte proof.
IMMUTABLE_088_RESCUE_SHA256 = "0c98aa9aa7d56e88f04768e0fe70681f2de777fc22021f9af4ccc06be1d8099b"
IMMUTABLE_088_RESCUE_SIZE = 28_419
COSIGN_RELEASE_BASE_URL = (
    f"https://github.com/sigstore/cosign/releases/download/v{resolver_hint.COSIGN_BOOTSTRAP_VERSION}"
)
POISONED_AUTH_ENVIRONMENT = {
    "BASH_ENV": "poisoned-bash-env",
    "ENV": "poisoned-shell-env",
    "CDPATH": "/attacker/cdpath",
    "GLOBIGNORE": "*",
    "BASH_COMPAT": "31",
    "POSIXLY_CORRECT": "1",
    "PROMPT_COMMAND": "exit 88",
    "VERSION": "66.66.66",
    "DEFENSECLAW_UPGRADE_ALLOW_UNVERIFIED": "1",
    "GODEBUG": "http2client=0,x509sha1=1",
    "GOFLAGS": "-mod=mod",
    "PYTHONPATH": "/attacker/python",
    "PYTHONHOME": "/attacker/python-home",
    "PYTHONINSPECT": "1",
    "PYTHONSTARTUP": "/attacker/python-startup",
    "PYTHONUSERBASE": "/attacker/python-user",
    "PYTHONWARNINGS": "ignore",
    "PYTHONBREAKPOINT": "attacker.breakpoint",
    "PERL5OPT": "-MDefenseClaw::Poison",
    "PERL5DB": "BEGIN { die 'poisoned' }",
    "PERL5LIB": "/attacker/perl",
    "PERLLIB": "/attacker/perl",
    # Empty loader values remain observable in a child environment without
    # asking the host dynamic loader to open an invalid test object.
    "LD_PRELOAD": "",
    "LD_LIBRARY_PATH": "",
    "LD_AUDIT": "",
    "DYLD_INSERT_LIBRARIES": "",
    "DYLD_LIBRARY_PATH": "",
    "DYLD_FRAMEWORK_PATH": "",
    "SIGSTORE_ROOT_FILE": "/attacker/sigstore-root.json",
    "SIGSTORE_REKOR_PUBLIC_KEY": "/attacker/rekor.pub",
    "SIGSTORE_CT_LOG_PUBLIC_KEY_FILE": "/attacker/ct.pub",
    "SIGSTORE_TSA_CERTIFICATE_FILE": "/attacker/tsa.pem",
    "TUF_ROOT": "/attacker/tuf-root.json",
    "TUF_MIRROR": "https://attacker.invalid/tuf",
    "TUF_ROOT_JSON": "/attacker/tuf-root-override.json",
}

_COSIGN_FIXTURES = {
    ("Darwin", "arm64"): (
        "cosign-darwin-arm64",
        "ff497a698f125f3130b04f000b2cb0dd163bcaf00b5e776ef536035e6d0b3f3e",
    ),
    ("Linux", "x86_64"): (
        "cosign-linux-amd64",
        "7c78a7f2efc00088bd788a758db6e0928e79f3e0eb83eb5d3c499ed98da4c4f4",
    ),
    ("Linux", "aarch64"): (
        "cosign-linux-arm64",
        "b7c23659a50a59fd8eec44b87188e9062157d0c87796cac7b38727e5390c4917",
    ),
    ("Linux", "arm64"): (
        "cosign-linux-arm64",
        "b7c23659a50a59fd8eec44b87188e9062157d0c87796cac7b38727e5390c4917",
    ),
}


def _record(
    *,
    digest: str = "b" * 64,
    posix_installer_digest: str = "c" * 64,
    windows_installer_digest: str = "d" * 64,
) -> dict[str, str]:
    return release_channel.build_channel(
        repository=REPOSITORY,
        version=VERSION,
        commit=COMMIT,
        resolver_sha256=digest,
        posix_installer_sha256=posix_installer_digest,
        windows_installer_sha256=windows_installer_digest,
    )


def _channel_checksums_text() -> str:
    return f"{'a' * 64}  defenseclaw-upgrade.sh\n{'b' * 64}  install.sh\n{'c' * 64}  install.ps1\n"


def test_channel_manifest_canonically_binds_immutable_release_controllers(
    tmp_path: Path,
) -> None:
    checksums = tmp_path / "checksums.txt"
    checksums.write_bytes(
        (
            f"{'1' * 64}  unrelated.bin\n"
            f"{'b' * 64}  defenseclaw-upgrade.sh\n"
            f"{'c' * 64}  install.sh\n"
            f"{'d' * 64}  install.ps1\n"
        ).encode("ascii"),
    )

    digests = release_channel.channel_asset_digests_from_checksums(checksums)
    payload = release_channel.render_channel(
        _record(
            digest=digests["defenseclaw-upgrade.sh"],
            posix_installer_digest=digests["install.sh"],
            windows_installer_digest=digests["install.ps1"],
        )
    )
    parsed = release_channel.parse_channel(payload)

    assert digests == {
        "defenseclaw-upgrade.sh": "b" * 64,
        "install.sh": "c" * 64,
        "install.ps1": "d" * 64,
    }
    assert list(parsed) == list(release_channel.FIELD_ORDER)
    assert parsed == {
        "schema": "defenseclaw-release-channel-v1",
        "channel": "stable",
        "repository": REPOSITORY,
        "target_version": VERSION,
        "target_tag": VERSION,
        "target_ref": f"refs/tags/{VERSION}",
        "target_commit": COMMIT,
        "resolver_name": "defenseclaw-upgrade.sh",
        "resolver_url": (f"https://github.com/{REPOSITORY}/releases/download/{VERSION}/defenseclaw-upgrade.sh"),
        "resolver_sha256": "b" * 64,
        "posix_installer_name": "install.sh",
        "posix_installer_url": (f"https://github.com/{REPOSITORY}/releases/download/{VERSION}/install.sh"),
        "posix_installer_sha256": "c" * 64,
        "windows_installer_name": "install.ps1",
        "windows_installer_url": (f"https://github.com/{REPOSITORY}/releases/download/{VERSION}/install.ps1"),
        "windows_installer_sha256": "d" * 64,
    }
    assert payload.endswith(b"\n")
    assert len(payload.splitlines()) == 16


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("target_tag", "v0.8.8", "tag does not equal"),
        ("target_ref", "refs/heads/main", "exact immutable tag ref"),
        ("target_commit", "A" * 40, "lowercase Git object ID"),
        ("resolver_name", "bootstrap.sh", "reviewed POSIX resolver"),
        (
            "resolver_url",
            "https://attacker.invalid/defenseclaw-upgrade.sh",
            "not derived",
        ),
        ("resolver_sha256", "B" * 64, "lowercase SHA-256"),
        ("posix_installer_name", "bootstrap.sh", "reviewed installer"),
        (
            "posix_installer_url",
            "https://attacker.invalid/install.sh",
            "not derived",
        ),
        ("posix_installer_sha256", "C" * 64, "lowercase SHA-256"),
        ("windows_installer_name", "setup.ps1", "reviewed installer"),
        (
            "windows_installer_url",
            "https://attacker.invalid/install.ps1",
            "not derived",
        ),
        ("windows_installer_sha256", "D" * 64, "lowercase SHA-256"),
    ],
)
def test_channel_manifest_rejects_unbound_target_fields(
    field: str,
    value: str,
    message: str,
) -> None:
    record = _record()
    record[field] = value

    with pytest.raises(release_channel.ChannelError, match=message):
        release_channel.validate_channel(record)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        release_channel.render_channel_without_validation(_record()).rstrip(b"\n"),
        release_channel.render_channel_without_validation(_record()).replace(
            f"channel=stable\nrepository={REPOSITORY}\n".encode(),
            f"repository={REPOSITORY}\nchannel=stable\n".encode(),
        ),
        release_channel.render_channel_without_validation(_record()) + b"extra=x\n",
        release_channel.render_channel_without_validation(_record()).replace(
            b"stable\n",
            b"stabl\xc3\xa9\n",
            1,
        ),
    ],
)
def test_channel_parser_rejects_noncanonical_wire_encodings(payload: bytes) -> None:
    with pytest.raises(release_channel.ChannelError):
        release_channel.parse_channel(payload)


@pytest.mark.parametrize("separator", [b"\v", b"\f", b"\x1c", b"\x1d", b"\x1e"])
def test_channel_parser_never_treats_non_lf_ascii_separators_as_lines(
    separator: bytes,
) -> None:
    payload = release_channel.render_channel(_record()).replace(b"\n", separator, 1)

    with pytest.raises(release_channel.ChannelError):
        release_channel.parse_channel(payload)


def test_channel_comparison_is_idempotent_and_monotonic() -> None:
    current = _record()
    assert release_channel.compare_channels(current, dict(current)) == "same"

    advanced = release_channel.build_channel(
        repository=REPOSITORY,
        version="0.8.9",
        commit="c" * 40,
        resolver_sha256="d" * 64,
        posix_installer_sha256="e" * 64,
        windows_installer_sha256="f" * 64,
    )
    assert release_channel.compare_channels(current, advanced) == "advance"

    with pytest.raises(release_channel.ChannelError, match="roll back"):
        release_channel.compare_channels(advanced, current)

    conflict = dict(current)
    conflict["target_commit"] = "e" * 40
    with pytest.raises(release_channel.ChannelError, match="already-published"):
        release_channel.compare_channels(current, conflict)

    installer_conflict = dict(current)
    installer_conflict["posix_installer_sha256"] = "f" * 64
    with pytest.raises(release_channel.ChannelError, match="already-published"):
        release_channel.compare_channels(current, installer_conflict)


def test_channel_checksum_extraction_requires_exact_channel_asset_coverage(
    tmp_path: Path,
) -> None:
    checksums = tmp_path / "checksums.txt"
    checksums.write_bytes(f"{'a' * 64}  other.bin\n".encode("ascii"))
    with pytest.raises(release_channel.ChannelError, match="does not bind"):
        release_channel.channel_asset_digests_from_checksums(checksums)

    checksums.write_bytes(
        (
            f"{'a' * 64}  defenseclaw-upgrade.sh\n"
            f"{'b' * 64}  install.sh\n"
            f"{'c' * 64}  install.sh\n"
            f"{'d' * 64}  install.ps1\n"
        ).encode("ascii"),
    )
    with pytest.raises(release_channel.ChannelError, match="duplicate"):
        release_channel.channel_asset_digests_from_checksums(checksums)

    checksums.write_bytes(
        f"{'a' * 64} *defenseclaw-upgrade.sh\n".encode("ascii"),
    )
    with pytest.raises(release_channel.ChannelError, match="invalid"):
        release_channel.channel_asset_digests_from_checksums(checksums)


@pytest.mark.parametrize(
    "payload",
    [
        _channel_checksums_text().encode("ascii").rstrip(b"\n"),
        _channel_checksums_text().encode("ascii").replace(b"\n", b"\v", 1),
        _channel_checksums_text().encode("ascii").replace(b"\n", b"\f", 1),
        _channel_checksums_text().encode("ascii").replace(b"\n", b"\x1e", 1),
    ],
)
def test_channel_checksum_extraction_requires_canonical_lf_text(
    tmp_path: Path,
    payload: bytes,
) -> None:
    checksums = tmp_path / "checksums.txt"
    checksums.write_bytes(payload)

    with pytest.raises(release_channel.ChannelError):
        release_channel.channel_asset_digests_from_checksums(checksums)


def test_channel_file_reader_uses_one_nonfollowing_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = tmp_path / "stable.txt"
    channel.write_bytes(release_channel.render_channel(_record()))
    opened_flags: list[int] = []
    real_open = client_release_channel.os.open

    def tracked_open(path: Path, flags: int) -> int:
        opened_flags.append(flags)
        return real_open(path, flags)

    def reject_path_reopen(_path: Path) -> bytes:
        raise AssertionError("channel reader reopened the validated path")

    monkeypatch.setattr(client_release_channel.os, "open", tracked_open)
    monkeypatch.setattr(Path, "read_bytes", reject_path_reopen)

    payload = client_release_channel._read_bounded_regular_file(
        channel,
        label="channel manifest",
        max_bytes=client_release_channel.MAX_CHANNEL_BYTES,
    )

    assert payload.startswith(b"schema=defenseclaw-release-channel-v1\n")
    assert len(opened_flags) == 1
    if hasattr(client_release_channel.os, "O_NOFOLLOW"):
        assert opened_flags[0] & client_release_channel.os.O_NOFOLLOW


def test_channel_file_reader_reports_close_failure_after_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = tmp_path / "stable.txt"
    channel.write_bytes(release_channel.render_channel(_record()))
    real_open = client_release_channel.os.open
    real_close = client_release_channel.os.close
    opened_descriptor: int | None = None
    close_failure_injected = False

    def tracked_open(path: Path, flags: int) -> int:
        nonlocal opened_descriptor
        descriptor = real_open(path, flags)
        opened_descriptor = descriptor
        return descriptor

    def close_target_then_fail(descriptor: int) -> None:
        nonlocal close_failure_injected
        real_close(descriptor)
        if descriptor == opened_descriptor and not close_failure_injected:
            close_failure_injected = True
            raise OSError("injected channel close failure")

    monkeypatch.setattr(client_release_channel.os, "open", tracked_open)
    monkeypatch.setattr(client_release_channel.os, "close", close_target_then_fail)

    with pytest.raises(client_release_channel.ChannelError, match="injected channel close failure"):
        client_release_channel.load_channel(channel)


def test_channel_file_reader_preserves_primary_failure_when_close_also_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    channel = tmp_path / "stable.txt"
    channel.write_bytes(release_channel.render_channel(_record()))
    real_open = client_release_channel.os.open
    real_read = client_release_channel.os.read
    real_close = client_release_channel.os.close
    opened_descriptor: int | None = None
    read_failure_injected = False
    close_failure_injected = False

    def tracked_open(path: Path, flags: int) -> int:
        nonlocal opened_descriptor
        descriptor = real_open(path, flags)
        opened_descriptor = descriptor
        return descriptor

    def fail_target_read(descriptor: int, size: int) -> bytes:
        nonlocal read_failure_injected
        if descriptor == opened_descriptor and not read_failure_injected:
            read_failure_injected = True
            raise OSError("injected channel read failure")
        return real_read(descriptor, size)

    def close_target_then_fail(descriptor: int) -> None:
        nonlocal close_failure_injected
        real_close(descriptor)
        if descriptor == opened_descriptor and not close_failure_injected:
            close_failure_injected = True
            raise OSError("injected channel close failure")

    monkeypatch.setattr(client_release_channel.os, "open", tracked_open)
    monkeypatch.setattr(client_release_channel.os, "read", fail_target_read)
    monkeypatch.setattr(client_release_channel.os, "close", close_target_then_fail)

    with pytest.raises(client_release_channel.ChannelError, match="injected channel read failure") as raised:
        client_release_channel.load_channel(channel)
    assert "close failure" not in str(raised.value)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink contract")
def test_channel_file_reader_rejects_a_leaf_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_bytes(release_channel.render_channel(_record()))
    channel = tmp_path / "stable.txt"
    channel.symlink_to(target)

    with pytest.raises(client_release_channel.ChannelError, match="must be a regular file"):
        client_release_channel._read_bounded_regular_file(
            channel,
            label="channel manifest",
            max_bytes=client_release_channel.MAX_CHANNEL_BYTES,
        )


@pytest.mark.parametrize("operation", ["open", "write", "fsync", "close"])
def test_channel_create_translates_io_errors_and_removes_partial_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    destination = tmp_path / "stable.txt"
    original_close = release_channel.os.close

    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError(f"injected {operation} failure")

    if operation == "close":

        def close_then_fail(descriptor: int) -> None:
            original_close(descriptor)
            fail()

        monkeypatch.setattr(release_channel.os, "close", close_then_fail)
    else:
        monkeypatch.setattr(release_channel.os, operation, fail)

    with pytest.raises(
        release_channel.ChannelError,
        match=rf"injected {operation} failure",
    ):
        release_channel._write_new(destination, b"channel\n")

    assert not destination.exists()


def _write_executable(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o755)


def _publisher_repair_fixture(
    tmp_path: Path,
    *,
    latest_version: str = VERSION,
    current_valid: bool = False,
    current_signature_valid: bool = True,
) -> tuple[dict[str, str], Path]:
    state = tmp_path / "publisher-state"
    mock_bin = tmp_path / "publisher-bin"
    runner_temp = tmp_path / "publisher-runner"
    state.mkdir()
    mock_bin.mkdir()
    runner_temp.mkdir()
    checksums = tmp_path / "checksums.txt"
    checksums.write_text(_channel_checksums_text(), encoding="ascii")

    current_channel = (
        release_channel.render_channel(
            release_channel.build_channel(
                repository=REPOSITORY,
                version="0.8.7",
                commit="9" * 40,
                resolver_sha256="1" * 64,
                posix_installer_sha256="2" * 64,
                windows_installer_sha256="3" * 64,
            )
        )
        if current_valid
        else b"unsigned channel corruption\n"
    )
    for name, payload in {
        "stable.txt": current_channel,
        "stable.txt.sig": b"fixture signature\n",
        "stable.txt.pem": (b"-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n"),
        "stable.txt.bundle": b'{"fixture":"bundle"}\n',
    }.items():
        (state / f"current-{name}").write_bytes(payload)
    (state / "ref-sha").write_text(CHANNEL_BRANCH_COMMIT, encoding="ascii")

    _write_executable(
        mock_bin / "cosign",
        """#!/usr/bin/env python3
import os
import pathlib
import sys

args = sys.argv[1:]
if args == ["version"]:
    print("GitVersion:    v2.6.3")
    raise SystemExit(0)
if args and args[0] == "sign-blob":
    values = {}
    for argument in args[1:]:
        if argument.startswith("--bundle="):
            values["bundle"] = argument.split("=", 1)[1]
        elif argument.startswith("--output-certificate="):
            values["certificate"] = argument.split("=", 1)[1]
        elif argument.startswith("--output-signature="):
            values["signature"] = argument.split("=", 1)[1]
    pathlib.Path(values["bundle"]).write_text('{"fixture":"bundle"}\\n', encoding="ascii")
    pathlib.Path(values["certificate"]).write_text(
        "-----BEGIN CERTIFICATE-----\\nMAMCAQA=\\n-----END CERTIFICATE-----\\n",
        encoding="ascii",
    )
    pathlib.Path(values["signature"]).write_text("fixture signature\\n", encoding="ascii")
    raise SystemExit(0)
if args and args[0] == "verify-blob":
    payload = pathlib.Path(args[-1]).read_bytes()
    if os.environ.get("FIXTURE_REJECT_CURRENT_SIGNATURE") == "1" and "current" in pathlib.Path(args[-1]).parts:
        raise SystemExit(1)
    raise SystemExit(0 if payload.startswith(b"schema=defenseclaw-release-channel-v1\\n") else 1)
raise SystemExit(90)
""",
    )
    _write_executable(
        mock_bin / "gh",
        """#!/usr/bin/env python3
import base64
import json
import os
from pathlib import Path
import shutil
import sys

args = sys.argv[1:]
state = Path(os.environ["GH_STATE"])
repository = os.environ["GITHUB_REPOSITORY"]
version = os.environ["RELEASE_TAG"]
commit = os.environ["RELEASE_COMMIT"]
current = os.environ["FIXTURE_CURRENT_SHA"]
new_commit = os.environ["FIXTURE_NEW_SHA"]
tree_sha = os.environ["FIXTURE_TREE_SHA"]
include = "--include" in args

def emit(value):
    payload = json.dumps(value, separators=(",", ":"))
    if include:
        print("HTTP/2.0 200 OK")
        print("content-type: application/json")
        print()
    print(payload)

def endpoint():
    for argument in args:
        if argument.startswith(f"repos/{repository}/"):
            return argument
    raise SystemExit("missing endpoint")

def input_path():
    index = args.index("--input")
    return Path(args[index + 1])

route = endpoint()
if "releases?per_page=100&page=1" in route:
    emit(
        [
            {
                "id": 8088,
                "tag_name": os.environ["FIXTURE_LATEST_VERSION"],
                "draft": False,
                "prerelease": False,
                "immutable": True,
                "assets": [],
            }
        ]
    )
elif f"git/ref/tags/{version}" in route:
    emit({"object": {"type": "commit", "sha": commit}})
elif f"compare/{commit}...main" in route:
    emit(
        {
            "status": "identical",
            "base_commit": {"sha": commit},
            "merge_base_commit": {"sha": commit},
        }
    )
elif "git/matching-refs/heads/release-channel" in route:
    ref_sha = (state / "ref-sha").read_text(encoding="ascii")
    emit(
        [
            {
                "ref": "refs/heads/release-channel",
                "object": {"type": "commit", "sha": ref_sha},
            }
        ]
    )
elif "/contents/" in route:
    name = route.split("/contents/", 1)[1]
    ref = next(
        argument.split("=", 1)[1]
        for argument in args
        if argument.startswith("ref=")
    )
    if ref == current:
        source = state / f"current-{name}"
    elif ref == new_commit:
        source = state / "published" / name
    else:
        raise SystemExit(f"unexpected content ref: {ref}")
    payload = source.read_bytes()
    emit(
        {
            "type": "file",
            "name": name,
            "path": name,
            "encoding": "base64",
            "content": base64.b64encode(payload).decode("ascii"),
            "size": len(payload),
        }
    )
elif route.endswith("/git/blobs"):
    request = json.loads(input_path().read_text(encoding="utf-8"))
    payload = base64.b64decode(request["content"], validate=True)
    counter_path = state / "blob-counter"
    counter = int(counter_path.read_text(encoding="ascii")) + 1 if counter_path.exists() else 1
    counter_path.write_text(str(counter), encoding="ascii")
    sha = f"{counter:040x}"
    (state / f"blob-{sha}").write_bytes(payload)
    emit({"sha": sha})
elif route.endswith("/git/trees"):
    request = json.loads(input_path().read_text(encoding="utf-8"))
    published = state / "published"
    published.mkdir(exist_ok=True)
    for item in request["tree"]:
        shutil.copyfile(state / f"blob-{item['sha']}", published / item["path"])
    emit({"sha": tree_sha})
elif route.endswith("/git/commits"):
    request = json.loads(input_path().read_text(encoding="utf-8"))
    (state / "commit-request.json").write_text(
        json.dumps(request, sort_keys=True),
        encoding="utf-8",
    )
    emit({"sha": new_commit})
elif route.endswith("/git/refs/heads/release-channel") and "--method" in args:
    method = args[args.index("--method") + 1]
    if method != "PATCH":
        raise SystemExit(f"unexpected ref method: {method}")
    values = {
        argument.split("=", 1)[0]: argument.split("=", 1)[1]
        for argument in args
        if "=" in argument and not argument.startswith("repos/")
    }
    (state / "ref-update.json").write_text(
        json.dumps(values, sort_keys=True),
        encoding="utf-8",
    )
    (state / "ref-sha").write_text(values["sha"], encoding="ascii")
    emit({"ref": "refs/heads/release-channel"})
else:
    raise SystemExit(f"unexpected gh invocation: {args!r}")
""",
    )

    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{mock_bin}:{env['PATH']}",
            "GITHUB_REPOSITORY": REPOSITORY,
            "RELEASE_TAG": VERSION,
            "RELEASE_COMMIT": COMMIT,
            "RELEASE_CHECKSUMS": str(checksums),
            "RELEASE_CHANNEL_REPAIR": "1",
            "GH_TOKEN": "fixture-token",
            "GH_STATE": str(state),
            "RUNNER_TEMP": str(runner_temp),
            "FIXTURE_LATEST_VERSION": latest_version,
            "FIXTURE_CURRENT_SHA": CHANNEL_BRANCH_COMMIT,
            "FIXTURE_NEW_SHA": "e" * 40,
            "FIXTURE_TREE_SHA": "d" * 40,
            "FIXTURE_REJECT_CURRENT_SIGNATURE": "0" if current_signature_valid else "1",
        }
    )
    return env, state


def _rescue_fixture(
    tmp_path: Path,
    *,
    channel_payload: bytes | None = None,
    resolver_payload: bytes | None = None,
    installer_payload: bytes | None = None,
    cosign_exit: int = 0,
    trust_path_cosign: bool = False,
    patch_cosign_digest: bool = True,
    channel_failure_plan: str = "",
    rescue_source_path: Path = RESCUE,
) -> tuple[dict[str, str], Path]:
    assert channel_failure_plan in {
        "",
        "ref-download",
        "ref-parse",
        "manifest-download",
    }
    platform_key = (platform.system(), platform.machine())
    if platform_key not in _COSIGN_FIXTURES:
        pytest.skip(f"unsupported rescue test platform: {platform_key}")
    cosign_asset, production_cosign_digest = _COSIGN_FIXTURES[platform_key]

    fixture = tmp_path / "fixture"
    fake_bin = tmp_path / "bin"
    fixture.mkdir()
    fake_bin.mkdir()
    resolver_payload = resolver_payload or (
        b"#!/usr/bin/env bash\n"
        b'/usr/bin/env > "$TMPDIR/resolver-env.log"\n'
        b"printf 'resolver-args:'\n"
        b"printf ' <%s>' \"$@\"\n"
        b"printf '\\n'\n"
        b"# DefenseClaw upgrade resolver complete v1\n"
    )
    installer_payload = installer_payload or (
        b"#!/usr/bin/env bash\n"
        b'/usr/bin/env > "$TMPDIR/installer-env.log"\n'
        b"printf 'installer-args:'\n"
        b"printf ' <%s>' \"$@\"\n"
        b"printf '\\n'\n"
    )
    (fixture / "resolver.sh").write_bytes(resolver_payload)
    (fixture / "install.sh").write_bytes(installer_payload)
    resolver_digest = hashlib.sha256(resolver_payload).hexdigest()
    installer_digest = hashlib.sha256(installer_payload).hexdigest()
    channel_payload = channel_payload or release_channel.render_channel(
        _record(
            digest=resolver_digest,
            posix_installer_digest=installer_digest,
        )
    )
    (fixture / "stable.txt").write_bytes(channel_payload)
    (fixture / "stable.txt.bundle").write_text("fixture bundle\n", encoding="ascii")
    (fixture / "release-channel-ref.json").write_text(
        (f'{{"ref":"refs/heads/release-channel","object":{{"type":"commit","sha":"{CHANNEL_BRANCH_COMMIT}"}}}}\n'),
        encoding="ascii",
    )

    _write_executable(
        fake_bin / "curl",
        f"""#!/usr/bin/env bash
set -euo pipefail
destination=""
url=""
while (($#)); do
  case "$1" in
    --output) destination="$2"; shift 2 ;;
    https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
printf '%s\\n' "$url" >> "$TMPDIR/curl.log"
failure_plan="{channel_failure_plan}"
failure_state="$TMPDIR/channel-failure-state"
fail_first_download_generation() {{
  expected="$1"
  [[ "$failure_plan" == "$expected" ]] || return 1
  count=0
  if [[ -f "$failure_state" ]]; then
    IFS= read -r count < "$failure_state"
  fi
  count=$((count + 1))
  printf '%s\\n' "$count" > "$failure_state"
  ((count <= 3))
}}
if [[ "$url" == */git/ref/heads/release-channel ]] &&
   fail_first_download_generation "ref-download"; then
  exit 71
fi
if [[ "$url" == */git/ref/heads/release-channel &&
      "$failure_plan" == "ref-parse" &&
      ! -f "$failure_state" ]]; then
  : > "$failure_state"
  printf '%s\\n' '{{"ref":"refs/heads/release-channel","object":{{"type":"commit"}}}}' > "$destination"
  exit 0
fi
if [[ "$url" == */{CHANNEL_BRANCH_COMMIT}/stable.txt ]] &&
   fail_first_download_generation "manifest-download"; then
  exit 72
fi
case "$url" in
  */git/ref/heads/release-channel) source="$TMPDIR/fixture/release-channel-ref.json" ;;
  */{CHANNEL_BRANCH_COMMIT}/stable.txt) source="$TMPDIR/fixture/stable.txt" ;;
  */{CHANNEL_BRANCH_COMMIT}/stable.txt.bundle) source="$TMPDIR/fixture/stable.txt.bundle" ;;
  */releases/download/*/defenseclaw-upgrade.sh) source="$TMPDIR/fixture/resolver.sh" ;;
  */releases/download/*/install.sh) source="$TMPDIR/fixture/install.sh" ;;
  */sigstore/cosign/releases/download/*/cosign-*) source="$TMPDIR/fixture/authenticated-cosign" ;;
  *) printf 'unexpected URL: %s\\n' "$url" >&2; exit 90 ;;
esac
cp "$source" "$destination"
""",
    )
    path_cosign = fake_bin / "cosign"
    _write_executable(
        path_cosign,
        f"""#!/bin/bash
if [[ "$0" == "$TMPDIR/bin/cosign" ]]; then
  printf 'arbitrary PATH cosign executed\\n' >> "$TMPDIR/path-cosign.log"
  exit 91
fi
/usr/bin/env > "$TMPDIR/auth-env.log"
printf '%s\\n' "$0 $*" >> "$TMPDIR/cosign.log"
exit {cosign_exit}
""",
    )
    _write_executable(
        fake_bin / "bash",
        """#!/bin/sh
printf 'arbitrary PATH bash executed\\n' >> "$TMPDIR/path-bash.log"
exit 92
""",
    )
    authenticated_cosign = fixture / "authenticated-cosign"
    _write_executable(
        authenticated_cosign,
        f"""#!/bin/bash
/usr/bin/env > "$TMPDIR/auth-env.log"
printf '%s\\n' "$0 $*" >> "$TMPDIR/cosign.log"
exit {cosign_exit}
""",
    )
    authenticated_cosign_digest = hashlib.sha256(authenticated_cosign.read_bytes()).hexdigest()
    pinned_fixture_digest = (
        hashlib.sha256(path_cosign.read_bytes()).hexdigest() if trust_path_cosign else authenticated_cosign_digest
    )

    rescue_source = rescue_source_path.read_text(encoding="utf-8")
    assert rescue_source.count(production_cosign_digest) == 1
    if patch_cosign_digest:
        rescue_source = rescue_source.replace(
            production_cosign_digest,
            pinned_fixture_digest,
        )
    rescue_source = rescue_source.replace(
        'readonly CURL_BIN="/usr/bin/curl"',
        f'readonly CURL_BIN="{fake_bin / "curl"}"',
    )
    assert f'cosign_asset="{cosign_asset}"' in rescue_source
    rescue_under_test = tmp_path / "defenseclaw-rescue-under-test.sh"
    _write_executable(rescue_under_test, rescue_source)

    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
            "TMPDIR": str(tmp_path),
        }
    )
    env.update(POISONED_AUTH_ENVIRONMENT)
    env["XDG_CONFIG_HOME"] = str(tmp_path / "ambient-xdg-config")
    env["XDG_CACHE_HOME"] = str(tmp_path / "ambient-xdg-cache")
    env["XDG_DATA_HOME"] = str(tmp_path / "ambient-xdg-data")
    env["XDG_STATE_HOME"] = str(tmp_path / "ambient-xdg-state")
    env["HTTPS_PROXY"] = "http://127.0.0.1:65535"
    env["NO_PROXY"] = "localhost,127.0.0.1"
    bash_env_poison = tmp_path / "bash-env-poison.sh"
    bash_env_poison.write_text(
        'printf "BASH_ENV executed\\n" >> "$TMPDIR/bash-env.log"\nexit 87\n',
        encoding="utf-8",
    )
    env["BASH_ENV"] = str(bash_env_poison)
    env["BASH_FUNC_rescue_poison%%"] = "() { printf poison; }"
    env["BASH_FUNC_unset%%"] = (
        '() { printf "unset function executed\\n" >> "$TMPDIR/exported-function.log"; builtin unset "$@"; }'
    )
    env["BASH_FUNC_set%%"] = (
        '() { printf "set function executed\\n" >> "$TMPDIR/exported-function.log"; builtin set "$@"; }'
    )
    env["BASH_FUNC_[%%"] = (
        '() { printf "test function executed\\n" >> "$TMPDIR/exported-function.log"; builtin [ "$@"; }'
    )
    return env, rescue_under_test


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
@pytest.mark.parametrize(
    "interpreter_argv0",
    ["sh", "bash", "-sh", "-bash", "nested/sh", "nested/bash"],
)
def test_posix_rescue_refuses_stdin_even_if_argv0_names_a_readable_script(
    tmp_path: Path,
    interpreter_argv0: str,
) -> None:
    source = RESCUE.read_text(encoding="utf-8")
    argv0_path = tmp_path / interpreter_argv0
    argv0_path.parent.mkdir(parents=True, exist_ok=True)
    argv0_path.write_text(source, encoding="utf-8")

    completed = subprocess.run(
        ["/bin/sh", "-c", ". /dev/stdin", interpreter_argv0],
        cwd=tmp_path,
        input=source,
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )

    assert completed.returncode != 0
    assert "save this bootstrap as a readable regular file" in completed.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_posix_rescue_forged_legacy_marker_cannot_skip_clean_saved_file_handoff(
    tmp_path: Path,
) -> None:
    env, rescue = _rescue_fixture(tmp_path)
    legacy_marker = "DEFENSE" + "CLAW_RESCUE_TRUSTED_BASH_PID"

    completed = subprocess.run(
        [
            "/bin/sh",
            "-c",
            (f'{legacy_marker}="$$"; export {legacy_marker}; exec "$1" --version'),
            "defenseclaw-rescue-exec",
            str(rescue),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert "authenticated stable channel owns the rescue target version" in completed.stderr
    assert not (tmp_path / "bash-env.log").exists()
    assert not (tmp_path / "exported-function.log").exists()
    assert not (tmp_path / "curl.log").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_posix_rescue_trampoline_accepts_relative_saved_filename(
    tmp_path: Path,
) -> None:
    env, rescue = _rescue_fixture(tmp_path)

    completed = subprocess.run(
        ["/bin/sh", rescue.name, "--version"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert "authenticated stable channel owns the rescue target version" in completed.stderr
    assert not (tmp_path / "curl.log").exists()


def test_posix_rescue_cosign_pins_match_resolver_hint_and_test_fixtures() -> None:
    expected = {
        ("Darwin", "arm64"): (
            "cosign-darwin-arm64",
            resolver_hint.COSIGN_BOOTSTRAP_SHA256[("darwin", "arm64")],
        ),
        ("Linux", "x86_64"): (
            "cosign-linux-amd64",
            resolver_hint.COSIGN_BOOTSTRAP_SHA256[("linux", "amd64")],
        ),
        ("Linux", "aarch64"): (
            "cosign-linux-arm64",
            resolver_hint.COSIGN_BOOTSTRAP_SHA256[("linux", "arm64")],
        ),
        ("Linux", "arm64"): (
            "cosign-linux-arm64",
            resolver_hint.COSIGN_BOOTSTRAP_SHA256[("linux", "arm64")],
        ),
    }
    source = RESCUE.read_text(encoding="utf-8")

    assert _COSIGN_FIXTURES == expected
    assert re.findall(r'^readonly COSIGN_VERSION="([^"]+)"$', source, flags=re.MULTILINE) == [
        resolver_hint.COSIGN_BOOTSTRAP_VERSION
    ]
    observed_pins = {
        (platform_case, asset): digest
        for platform_case, asset, digest in re.findall(
            r"(?m)^    ([^\n)]*)\)\n"
            r'        cosign_asset="([^"]+)"\n'
            r'        cosign_sha256="([0-9a-f]{64})"$',
            source,
        )
    }
    assert observed_pins == {
        ("darwin/arm64", "cosign-darwin-arm64"): resolver_hint.COSIGN_BOOTSTRAP_SHA256[("darwin", "arm64")],
        ("linux/x86_64 | linux/amd64", "cosign-linux-amd64"): resolver_hint.COSIGN_BOOTSTRAP_SHA256[("linux", "amd64")],
        (
            "linux/aarch64 | linux/arm64",
            "cosign-linux-arm64",
        ): resolver_hint.COSIGN_BOOTSTRAP_SHA256[("linux", "arm64")],
    }


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
@pytest.mark.parametrize("intel_arch", ["x86_64", "amd64"])
def test_posix_rescue_rejects_intel_before_network_or_host_state(
    tmp_path: Path,
    intel_arch: str,
) -> None:
    env, rescue = _rescue_fixture(tmp_path)
    source = rescue.read_text(encoding="utf-8")
    platform_probe = 'platform_os="$("${UNAME_BIN}" -s | tr \'[:upper:]\' \'[:lower:]\')"'
    arch_probe = 'platform_arch="$("${UNAME_BIN}" -m)"'
    assert source.count(platform_probe) == 1
    assert source.count(arch_probe) == 1
    assert source.index(platform_probe) < source.index('temp_root_input="${TMPDIR:-/tmp}"')
    assert source.index(arch_probe) < source.index('workdir="$(mktemp -d')
    mktemp_marker = tmp_path / "mktemp-invoked"
    fake_sysctl = tmp_path / "sysctl"
    _write_executable(fake_sysctl, "#!/bin/sh\nprintf '0\\n'\n")
    workdir_probe = 'workdir="$(mktemp -d "${temp_root}/defenseclaw-rescue.XXXXXX")"'
    assert source.count(workdir_probe) == 1
    instrumented_workdir = f"printf invoked > {mktemp_marker!s}; {workdir_probe}"
    _write_executable(
        rescue,
        source.replace('readonly MACOS_SYSCTL_BIN="/usr/sbin/sysctl"', f'readonly MACOS_SYSCTL_BIN="{fake_sysctl!s}"')
        .replace(platform_probe, 'platform_os="darwin"')
        .replace(arch_probe, f'platform_arch="{intel_arch}"')
        .replace(
            workdir_probe,
            instrumented_workdir,
        ),
    )

    completed = subprocess.run(
        [str(rescue)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert "Intel macOS is unsupported" in completed.stderr
    assert not (tmp_path / "curl.log").exists()
    assert not (tmp_path / "resolver-env.log").exists()
    assert not (tmp_path / "installer-env.log").exists()
    assert not mktemp_marker.exists()
    assert list(tmp_path.glob("defenseclaw-rescue.*")) == []


def test_posix_rescue_downloads_have_finite_network_time_bounds() -> None:
    source = RESCUE.read_text(encoding="utf-8")
    download_match = re.search(
        r"(?ms)^download\(\) \{\n(?P<body>.*?)^\}\n(?=\n*[A-Za-z_][A-Za-z0-9_]*\(\) \{)",
        source,
    )
    assert download_match is not None
    download = download_match.group("body")

    assert "readonly CURL_CONNECT_TIMEOUT_SECONDS=30" in source
    assert "readonly CURL_TOTAL_TIMEOUT_SECONDS=300" in source
    assert "readonly CURL_LOW_SPEED_LIMIT_BYTES=1024" in source
    assert "readonly CURL_LOW_SPEED_TIME_SECONDS=60" in source
    assert '--connect-timeout "${CURL_CONNECT_TIMEOUT_SECONDS}"' in download
    assert '--max-time "${CURL_TOTAL_TIMEOUT_SECONDS}"' in download
    assert '--speed-limit "${CURL_LOW_SPEED_LIMIT_BYTES}"' in download
    assert '--speed-time "${CURL_LOW_SPEED_TIME_SECONDS}"' in download
    assert "for attempt in 1 2 3; do" in download
    assert "--proto '=https' --proto-redir '=https' --tlsv1.2" in download
    assert '--max-filesize "${max_bytes}"' in download


def test_posix_rescue_clean_handoff_and_shared_temp_guards_are_fail_closed() -> None:
    source = RESCUE.read_text(encoding="utf-8")
    legacy_marker = "DEFENSE" + "CLAW_RESCUE_TRUSTED_BASH_PID"

    assert legacy_marker not in source
    assert "exec /usr/bin/env -i /bin/sh -c" in source
    assert "exec /bin/bash /dev/fd/3" in source
    assert "3<<'# DefenseClaw rescue bootstrap complete v1'" in source
    assert ("(( (8#${temp_mode} & 8#1000) != 0 || (8#${temp_mode} & 8#022) == 0 ))") in source
    assert "shared system temporary directory root is non-sticky and group or other-writable" in source

    # Sticky public roots and non-public root-owned roots are safe. A root-owned
    # mode that is non-sticky and group- or other-writable must remain rejected.
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("Bash is required to exercise the POSIX mode predicate")
    predicate = 'mode="$1"; (( (8#${mode} & 8#1000) != 0 || (8#${mode} & 8#022) == 0 ))'
    for mode, expected in (
        ("1777", 0),
        ("1775", 0),
        ("0755", 0),
        ("0770", 1),
        ("0775", 1),
        ("0777", 1),
    ):
        completed = subprocess.run(
            [bash, "-c", predicate, "temp-mode-contract", mode],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        assert completed.returncode == expected, mode


@pytest.mark.skipif(platform.system() != "Darwin", reason="BSD stat mode contract")
def test_posix_rescue_macos_identity_keeps_special_mode_bits_under_system_bash() -> None:
    source = RESCUE.read_text(encoding="utf-8")
    assert '"${STAT_BIN}" -f \'%d:%i:%u:%Mp%Lp\' "${path}"' in source

    # macOS' %Lp omits sticky/set-id bits. Exercise the exact Bash-3.2-compatible
    # numeric form used by the rescue against the resolved shared /tmp root.
    completed = subprocess.run(
        [
            "/bin/bash",
            "-c",
            (
                'root="$(cd -P /tmp && pwd -P)"; '
                'mode="$(/usr/bin/stat -f "%Mp%Lp" "${root}")"; '
                '[[ "${mode}" =~ ^[0-7]{3,4}$ ]] && '
                "(( (8#${mode} & 8#1000) != 0 ))"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr


def _environment(path: Path) -> dict[str, str]:
    return {
        name: value
        for line in path.read_text(encoding="utf-8").splitlines()
        if "=" in line
        for name, _, value in (line.partition("="),)
    }


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_does_not_import_exported_shell_functions(tmp_path: Path) -> None:
    env, rescue = _rescue_fixture(tmp_path)
    marker = tmp_path / "exported-function.log"

    completed = subprocess.run(
        [str(rescue), "--version"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert "authenticated stable channel owns the rescue target version" in completed.stderr
    assert not marker.exists()
    assert not (tmp_path / "curl.log").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_copies_digest_authenticated_path_cosign_before_execution(
    tmp_path: Path,
) -> None:
    env, rescue = _rescue_fixture(tmp_path, trust_path_cosign=True)

    completed = subprocess.run(
        [str(rescue), "--yes"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode == 0, completed.stderr
    assert not (tmp_path / "path-cosign.log").exists()
    assert not (tmp_path / "bash-env.log").exists()
    cosign_log = (tmp_path / "cosign.log").read_text(encoding="utf-8")
    assert str(tmp_path / "bin" / "cosign") not in cosign_log
    assert "/defenseclaw-rescue." in cosign_log
    curl_log = (tmp_path / "curl.log").read_text(encoding="utf-8").splitlines()
    assert all("/sigstore/cosign/releases/download/" not in url for url in curl_log)


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_skips_oversized_ambient_cosign_before_copy(
    tmp_path: Path,
) -> None:
    env, rescue = _rescue_fixture(tmp_path)
    source = RESCUE.read_text(encoding="utf-8")
    match = re.search(r"(?m)^readonly MAX_COSIGN_BYTES=([0-9]+)$", source)
    assert match is not None
    max_cosign_bytes = int(match.group(1))
    ambient_cosign = tmp_path / "bin" / "cosign"
    with ambient_cosign.open("r+b") as stream:
        stream.truncate(max_cosign_bytes + 1)
    ambient_cosign.chmod(0o111)

    completed = subprocess.run(
        [str(rescue), "--yes"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode == 0, completed.stderr
    assert not (tmp_path / "path-cosign.log").exists()
    curl_log = (tmp_path / "curl.log").read_text(encoding="utf-8").splitlines()
    assert curl_log[0].startswith(f"{COSIGN_RELEASE_BASE_URL}/cosign-")


def test_rescue_bounds_ambient_cosign_before_private_copy() -> None:
    source = RESCUE.read_text(encoding="utf-8")
    candidate_block = source.split(
        'if [[ "${cosign_candidate}" == /*',
        1,
    )[1].split('if [[ ! -f "${cosign_bin}" ]]', 1)[0]

    size = candidate_block.index('cosign_candidate_size="$(regular_file_size "${cosign_candidate}"')
    bound = candidate_block.index('"${cosign_candidate_size}" -le "${MAX_COSIGN_BYTES}"')
    copy = candidate_block.index('cp "${cosign_candidate}" "${cosign_candidate_copy}"')
    assert size < bound < copy


def test_rescue_authenticated_environment_clears_go_runtime_overrides() -> None:
    source = RESCUE.read_text(encoding="utf-8")
    sanitizer = source.split("sanitize_authenticated_environment() {", 1)[1].split(
        "\n}",
        1,
    )[0]

    assert "unset GODEBUG GOFLAGS" in sanitizer


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_rejects_downloaded_cosign_that_does_not_match_platform_pin(
    tmp_path: Path,
) -> None:
    env, rescue = _rescue_fixture(tmp_path, patch_cosign_digest=False)

    completed = subprocess.run(
        [str(rescue), "--yes"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert "downloaded Cosign digest mismatch" in completed.stderr
    assert not (tmp_path / "cosign.log").exists()
    assert not (tmp_path / "path-cosign.log").exists()
    curl_log = (tmp_path / "curl.log").read_text(encoding="utf-8").splitlines()
    assert len(curl_log) == 1
    assert f"{COSIGN_RELEASE_BASE_URL}/cosign-" in curl_log[0]


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_rejects_operator_owned_public_temporary_root_before_network(
    tmp_path: Path,
) -> None:
    env, rescue = _rescue_fixture(tmp_path)
    public_temp = tmp_path / "public-temp"
    public_temp.mkdir()
    public_temp.chmod(0o777)
    env["TMPDIR"] = str(public_temp)

    completed = subprocess.run(
        [str(rescue), "--yes"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert "temporary directory root is group or other writable" in completed.stderr
    assert not (tmp_path / "curl.log").exists()


def test_rescue_arms_private_workdir_cleanup_before_post_creation_checks() -> None:
    source = RESCUE.read_text(encoding="utf-8")
    create = source.index('workdir="$(mktemp -d ')
    cleanup = source.index("cleanup() {", create)
    trap = source.index("trap cleanup EXIT", cleanup)
    validate = source.index('[[ -d "${workdir}"', trap)
    chmod = source.index('chmod 700 "${workdir}"', validate)
    mkdir = source.index('mkdir -m 700 "${cosign_home}"', chmod)

    assert create < cleanup < trap < validate < chmod < mkdir


def test_rescue_revalidates_private_workdir_before_every_trusted_execution() -> None:
    source = RESCUE.read_text(encoding="utf-8")
    execution = source.split('if [[ "${rescue_mode}" == "install" ]]; then', 1)[1]

    assert 'workdir_identity="$(validate_private_workdir "${workdir}")"' in source
    assert 'current_workdir_identity="$(validate_private_workdir "${workdir}")"' in source
    assert '[[ "${current_workdir_identity}" == "${workdir_identity}" ]]' in source
    assert execution.count("assert_trusted_execution_custody") == 4
    assert execution.count('"${TRUSTED_BASH}"') == 4
    assert execution.count('assert_trusted_execution_custody\n    "${TRUSTED_BASH}"') == 3
    assert (
        'assert_trusted_execution_custody\n    VERSION="${target_version}" \\\n        "${TRUSTED_BASH}"'
    ) in execution


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_authenticates_channel_then_executes_exact_tagged_resolver(
    tmp_path: Path,
) -> None:
    env, rescue = _rescue_fixture(tmp_path)

    completed = subprocess.run(
        [str(rescue), "--yes", "--recover-corrupt-audit"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode == 0, completed.stderr
    assert f"Authenticated stable resolver {VERSION} ({COMMIT})" in completed.stdout
    assert (f"resolver-args: <--version> <{VERSION}> <--yes> <--recover-corrupt-audit>") in completed.stdout
    curl_log = (tmp_path / "curl.log").read_text(encoding="utf-8").splitlines()
    assert curl_log[0].startswith(f"{COSIGN_RELEASE_BASE_URL}/cosign-")
    assert curl_log[1:3] == [
        f"https://api.github.com/repos/{REPOSITORY}/git/ref/heads/release-channel",
        f"https://raw.githubusercontent.com/{REPOSITORY}/{CHANNEL_BRANCH_COMMIT}/stable.txt",
    ]
    assert curl_log[3] == (f"https://raw.githubusercontent.com/{REPOSITORY}/{CHANNEL_BRANCH_COMMIT}/stable.txt.bundle")
    assert curl_log[4] == (f"https://github.com/{REPOSITORY}/releases/download/{VERSION}/defenseclaw-upgrade.sh")
    cosign_log = (tmp_path / "cosign.log").read_text(encoding="utf-8")
    assert "verify-blob" in cosign_log
    assert "--bundle" in cosign_log
    assert (f"https://github.com/{REPOSITORY}/.github/workflows/release.yaml@refs/heads/main") in cosign_log
    assert not (tmp_path / "path-cosign.log").exists()
    assert not (tmp_path / "path-bash.log").exists()
    assert not (tmp_path / "bash-env.log").exists()
    assert not (tmp_path / "exported-function.log").exists()
    assert str(tmp_path / "bin" / "cosign") not in cosign_log

    auth_environment = _environment(tmp_path / "auth-env.log")
    resolver_environment = _environment(tmp_path / "resolver-env.log")
    for observed in (auth_environment, resolver_environment):
        assert observed.keys().isdisjoint(POISONED_AUTH_ENVIRONMENT)
        assert "SHELLOPTS" not in observed
        assert "BASHOPTS" not in observed
        assert not any(name.startswith("BASH_FUNC_") for name in observed)
    assert "/defenseclaw-rescue." in auth_environment["HOME"]
    assert auth_environment["HOME"].endswith("/cosign-home")
    assert auth_environment["XDG_CONFIG_HOME"].endswith("/cosign-config")
    assert auth_environment["XDG_CACHE_HOME"].endswith("/cosign-cache")
    assert auth_environment["XDG_DATA_HOME"].endswith("/cosign-data")
    assert auth_environment["XDG_STATE_HOME"].endswith("/cosign-state")
    assert auth_environment["HTTPS_PROXY"] == env["HTTPS_PROXY"]
    assert auth_environment["NO_PROXY"] == env["NO_PROXY"]
    assert resolver_environment["HOME"] == env["HOME"]
    assert resolver_environment["XDG_CONFIG_HOME"] == env["XDG_CONFIG_HOME"]
    assert resolver_environment["XDG_CACHE_HOME"] == env["XDG_CACHE_HOME"]
    assert resolver_environment["XDG_DATA_HOME"] == env["XDG_DATA_HOME"]
    assert resolver_environment["XDG_STATE_HOME"] == env["XDG_STATE_HOME"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_without_operator_arguments_executes_exact_tagged_resolver(
    tmp_path: Path,
) -> None:
    env, rescue = _rescue_fixture(tmp_path)

    completed = subprocess.run(
        [str(rescue)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode == 0, completed.stderr
    assert f"Authenticated stable resolver {VERSION} ({COMMIT})" in completed.stdout
    assert completed.stdout.endswith(f"resolver-args: <--version> <{VERSION}>\n")


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_immutable_088_rescue_hands_clean_path_to_new_resolver_uv_custody(
    tmp_path: Path,
) -> None:
    rescue_bytes = IMMUTABLE_088_RESCUE.read_bytes()
    assert len(rescue_bytes) == IMMUTABLE_088_RESCUE_SIZE
    assert hashlib.sha256(rescue_bytes).hexdigest() == IMMUTABLE_088_RESCUE_SHA256

    upgrade_source = UPGRADE_RESOLVER.read_text(encoding="utf-8")
    pin = re.search(r'readonly UV_BOOTSTRAP_VERSION="([^"]+)"', upgrade_source)
    maximum = re.search(r'readonly UV_BOOTSTRAP_MAX_BYTES="([^"]+)"', upgrade_source)
    assert pin is not None, "uv bootstrap version constant moved"
    assert maximum is not None, "uv bootstrap size constant moved"
    function_start = upgrade_source.find("resolve_upgrade_uv() {")
    assert function_start >= 0, "resolve_upgrade_uv() was renamed or removed"
    function_end = upgrade_source.find(
        "\n\n# Keep one bounded, fail-closed parser",
        function_start,
    )
    assert function_end > function_start, "resolve_upgrade_uv() end anchor moved"
    resolver_function = upgrade_source[function_start:function_end]
    uv_assets = {
        ("Darwin", "arm64"): (
            "uv-aarch64-apple-darwin.tar.gz",
            "uv-aarch64-apple-darwin/uv",
            "33540eb7c883ab857eff79bd5ac2aa31fe27b595abecb4a9c003a2c998447232",
        ),
        ("Linux", "x86_64"): (
            "uv-x86_64-unknown-linux-gnu.tar.gz",
            "uv-x86_64-unknown-linux-gnu/uv",
            "e490a6464492183c5d4534a5527fb4440f7f2bb2f228162ad7e4afe076dc0224",
        ),
        ("Linux", "amd64"): (
            "uv-x86_64-unknown-linux-gnu.tar.gz",
            "uv-x86_64-unknown-linux-gnu/uv",
            "e490a6464492183c5d4534a5527fb4440f7f2bb2f228162ad7e4afe076dc0224",
        ),
        ("Linux", "aarch64"): (
            "uv-aarch64-unknown-linux-gnu.tar.gz",
            "uv-aarch64-unknown-linux-gnu/uv",
            "03e9fe0a81b0718d0bc84625de3885df6cc3f89a8b6af6121d6b9f6113fb6533",
        ),
        ("Linux", "arm64"): (
            "uv-aarch64-unknown-linux-gnu.tar.gz",
            "uv-aarch64-unknown-linux-gnu/uv",
            "03e9fe0a81b0718d0bc84625de3885df6cc3f89a8b6af6121d6b9f6113fb6533",
        ),
    }
    uv_platform = (platform.system(), platform.machine())
    if uv_platform not in uv_assets:
        pytest.skip(f"unsupported uv bootstrap fixture platform: {uv_platform}")
    uv_asset, uv_member, production_uv_digest = uv_assets[uv_platform]
    pinned_marker = tmp_path / "pinned-uv-executed"
    uv_payload = (
        "#!/bin/sh\n"
        f"printf executed > {str(pinned_marker)!r}\n"
        f"printf 'uv {pin.group(1)} (pinned fixture)\\n'\n"
    ).encode()
    uv_archive = tmp_path / uv_asset
    with tarfile.open(uv_archive, mode="w:gz") as archive:
        directory = tarfile.TarInfo(str(Path(uv_member).parent))
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        archive.addfile(directory)
        executable = tarfile.TarInfo(uv_member)
        executable.mode = 0o755
        executable.size = len(uv_payload)
        archive.addfile(executable, io.BytesIO(uv_payload))
    fixture_uv_digest = hashlib.sha256(uv_archive.read_bytes()).hexdigest()
    assert resolver_function.count(production_uv_digest) == 1
    resolver_function = resolver_function.replace(
        production_uv_digest,
        fixture_uv_digest,
    )
    resolver_payload = (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "umask 077\n"
            f'readonly UV_BOOTSTRAP_VERSION="{pin.group(1)}"\n'
            f'readonly UV_BOOTSTRAP_MAX_BYTES="{maximum.group(1)}"\n'
            f'HOST_SYSTEM="{uv_platform[0]}"\n'
            f'HOST_MACHINE="{uv_platform[1]}"\n'
            'UV_BIN=""\n'
        'die() { printf "die: %s\\n" "$*" >&2; exit 1; }\n'
        'ok() { printf "ok: %s\\n" "$*"; }\n'
        'warn() { printf "warn: %s\\n" "$*" >&2; }\n'
        'info() { printf "info: %s\\n" "$*"; }\n'
        "curl() {\n"
        "  local output='' previous=''\n"
        '  for arg in "$@"; do\n'
        '    if [[ "${previous}" == "--output" ]]; then output="${arg}"; break; fi\n'
        '    previous="${arg}"\n'
        "  done\n"
        '  [[ -n "${output}" ]] || return 94\n'
        f"  cp {str(uv_archive)!r} \"${{output}}\"\n"
        "}\n"
        'STAGING_DIR="$(mktemp -d "${TMPDIR:-/tmp}/resolver-uv.XXXXXX")"\n'
        + resolver_function
        + "\n"
        + "resolve_upgrade_uv\n"
        + '"${UV_BIN}" --version\n'
        + 'printf "resolver-private-uv=%s\\n" "${UV_BIN}"\n'
        + '/usr/bin/env > "$TMPDIR/resolver-env.log"\n'
        + 'printf "resolver-clean-path=%s\\n" "${PATH}"\n'
        + "# DefenseClaw upgrade resolver complete v1\n"
    ).encode()
    env, rescue = _rescue_fixture(
        tmp_path,
        resolver_payload=resolver_payload,
        rescue_source_path=IMMUTABLE_088_RESCUE,
    )
    home = tmp_path / "home"
    known_bin = home / ".local" / "bin"
    known_bin.mkdir(parents=True)
    marker = tmp_path / "known-uv-executed"
    _write_executable(
        known_bin / "uv",
        f"#!/usr/bin/env bash\nprintf executed > {str(marker)!r}\n"
        f"printf 'uv {pin.group(1)} (fixture 2026-07-27)\\n'\n",
    )
    env["HOME"] = str(home)

    completed = subprocess.run(
        [str(rescue), "--yes"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode == 0, completed.stderr
    assert (
        f"Pinned uv {pin.group(1)} authenticated in private upgrade custody"
        in completed.stdout
    )
    assert f"uv {pin.group(1)}" in completed.stdout
    assert "resolver-clean-path=/usr/bin:/bin:/usr/sbin:/sbin" in completed.stdout
    assert not marker.exists()
    assert pinned_marker.read_text(encoding="utf-8") == "executed"
    private_uv_line = next(
        line
        for line in completed.stdout.splitlines()
        if line.startswith("resolver-private-uv=")
    )
    private_uv = Path(private_uv_line.removeprefix("resolver-private-uv="))
    assert private_uv.name == "uv"
    assert private_uv.parent.name == "upgrade-tools"
    assert private_uv.parents[2] == Path(env["TMPDIR"])
    resolver_environment = _environment(tmp_path / "resolver-env.log")
    assert resolver_environment["HOME"] == str(home)
    assert resolver_environment["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin"


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
@pytest.mark.parametrize(
    "failure_plan",
    ["ref-download", "ref-parse", "manifest-download"],
)
def test_rescue_retries_a_complete_channel_generation_after_snapshot_failure(
    tmp_path: Path,
    failure_plan: str,
) -> None:
    env, rescue = _rescue_fixture(
        tmp_path,
        channel_failure_plan=failure_plan,
    )

    completed = subprocess.run(
        [str(rescue), "--yes"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode == 0, completed.stderr
    assert f"Authenticated stable resolver {VERSION} ({COMMIT})" in completed.stdout
    curl_log = (tmp_path / "curl.log").read_text(encoding="utf-8").splitlines()
    channel_ref_url = f"https://api.github.com/repos/{REPOSITORY}/git/ref/heads/release-channel"
    assert curl_log.count(channel_ref_url) >= 2
    assert curl_log[-1] == (f"https://github.com/{REPOSITORY}/releases/download/{VERSION}/defenseclaw-upgrade.sh")


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_install_executes_exact_channel_bound_posix_installer(
    tmp_path: Path,
) -> None:
    env, rescue = _rescue_fixture(tmp_path)

    completed = subprocess.run(
        [str(rescue), "--install", "--yes", "--connector", "none"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode == 0, completed.stderr
    assert f"Authenticated stable POSIX installer {VERSION} ({COMMIT})" in completed.stdout
    assert "installer-args: <--yes> <--connector> <none>" in completed.stdout
    curl_log = (tmp_path / "curl.log").read_text(encoding="utf-8").splitlines()
    assert curl_log[-1] == f"https://github.com/{REPOSITORY}/releases/download/{VERSION}/install.sh"
    assert all(not url.endswith("/defenseclaw-upgrade.sh") for url in curl_log)
    installer_environment = _environment(tmp_path / "installer-env.log")
    assert installer_environment["VERSION"] == VERSION
    assert installer_environment.keys().isdisjoint(set(POISONED_AUTH_ENVIRONMENT) - {"VERSION"})
    assert not (tmp_path / "resolver-env.log").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_install_without_forwarded_arguments_executes_exact_installer(
    tmp_path: Path,
) -> None:
    env, rescue = _rescue_fixture(
        tmp_path,
        installer_payload=(b'#!/usr/bin/env bash\nprintf \'installer-argc:%s\\n\' "$#"\n[[ "$#" == "0" ]]\n'),
    )

    completed = subprocess.run(
        [str(rescue), "--install"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode == 0, completed.stderr
    assert f"Authenticated stable POSIX installer {VERSION} ({COMMIT})" in completed.stdout
    assert completed.stdout.endswith("installer-argc:0\n")
    assert not (tmp_path / "resolver-env.log").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_install_rejects_tagged_installer_digest_mismatch(
    tmp_path: Path,
) -> None:
    payload = release_channel.render_channel(_record(posix_installer_digest="0" * 64))
    env, rescue = _rescue_fixture(tmp_path, channel_payload=payload)

    completed = subprocess.run(
        [str(rescue), "--install", "--yes"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert "installer digest does not match" in completed.stderr
    assert not (tmp_path / "installer-env.log").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_install_rejects_signed_but_redirected_installer_url(
    tmp_path: Path,
) -> None:
    payload = release_channel.render_channel_without_validation(_record()).replace(
        (f"posix_installer_url=https://github.com/{REPOSITORY}/releases/download/{VERSION}/install.sh").encode(),
        b"posix_installer_url=https://attacker.invalid/install.sh",
    )
    env, rescue = _rescue_fixture(tmp_path, channel_payload=payload)

    completed = subprocess.run(
        [str(rescue), "--install", "--yes"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert "POSIX installer URL is not derived" in completed.stderr
    curl_log = (tmp_path / "curl.log").read_text(encoding="utf-8").splitlines()
    assert all("attacker.invalid" not in line for line in curl_log)
    assert not (tmp_path / "installer-env.log").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_rejects_signed_but_redirected_channel_before_resolver_download(
    tmp_path: Path,
) -> None:
    payload = release_channel.render_channel_without_validation(_record()).replace(
        (f"resolver_url=https://github.com/{REPOSITORY}/releases/download/{VERSION}/defenseclaw-upgrade.sh").encode(),
        b"resolver_url=https://attacker.invalid/defenseclaw-upgrade.sh",
    )
    env, rescue = _rescue_fixture(tmp_path, channel_payload=payload)

    completed = subprocess.run(
        [str(rescue), "--yes"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert "resolver URL is not derived" in completed.stderr
    curl_log = (tmp_path / "curl.log").read_text(encoding="utf-8").splitlines()
    assert len(curl_log) == 4
    assert curl_log[0].startswith(f"{COSIGN_RELEASE_BASE_URL}/cosign-")
    assert all("attacker.invalid" not in line for line in curl_log)


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
def test_rescue_signature_failure_stops_before_channel_parse_or_resolver_download(
    tmp_path: Path,
) -> None:
    env, rescue = _rescue_fixture(
        tmp_path,
        channel_payload=b"not a channel\n",
        cosign_exit=42,
    )

    completed = subprocess.run(
        [str(rescue), "--yes"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert "stable channel proof did not authenticate after 3 bounded generations" in completed.stderr
    assert "unsupported channel schema" not in completed.stderr
    cosign_asset = _COSIGN_FIXTURES[(platform.system(), platform.machine())][0]
    curl_log = (tmp_path / "curl.log").read_text(encoding="utf-8").splitlines()
    assert curl_log == [
        f"{COSIGN_RELEASE_BASE_URL}/{cosign_asset}",
        f"https://api.github.com/repos/{REPOSITORY}/git/ref/heads/release-channel",
        f"https://raw.githubusercontent.com/{REPOSITORY}/{CHANNEL_BRANCH_COMMIT}/stable.txt",
        f"https://raw.githubusercontent.com/{REPOSITORY}/{CHANNEL_BRANCH_COMMIT}/stable.txt.bundle",
        f"https://api.github.com/repos/{REPOSITORY}/git/ref/heads/release-channel",
        f"https://raw.githubusercontent.com/{REPOSITORY}/{CHANNEL_BRANCH_COMMIT}/stable.txt.bundle",
        f"https://raw.githubusercontent.com/{REPOSITORY}/{CHANNEL_BRANCH_COMMIT}/stable.txt",
        f"https://api.github.com/repos/{REPOSITORY}/git/ref/heads/release-channel",
        f"https://raw.githubusercontent.com/{REPOSITORY}/{CHANNEL_BRANCH_COMMIT}/stable.txt",
        f"https://raw.githubusercontent.com/{REPOSITORY}/{CHANNEL_BRANCH_COMMIT}/stable.txt.bundle",
    ]
    cosign_log = (tmp_path / "cosign.log").read_text(encoding="utf-8").splitlines()
    assert len(cosign_log) == 3
    assert all("verify-blob" in line for line in cosign_log)
    assert all("/releases/download/" not in url for url in curl_log[1:])


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
@pytest.mark.parametrize(
    "forbidden",
    [
        "--version",
        "--version=0.8.7",
        "--allow-unverified",
        "--allow-unverified=true",
        "--local",
        "--local=/tmp/candidate",
        "--cosign-path",
        "--cosign-path=/tmp/cosign",
    ],
)
@pytest.mark.parametrize("mode", [[], ["--install"]], ids=["upgrade", "install"])
def test_rescue_refuses_target_or_authentication_override_before_network(
    tmp_path: Path,
    forbidden: str,
    mode: list[str],
) -> None:
    env, rescue = _rescue_fixture(tmp_path)

    completed = subprocess.run(
        [str(rescue), *mode, forbidden],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert not (tmp_path / "curl.log").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX rescue bootstrap")
@pytest.mark.parametrize(
    "forbidden",
    [
        "--recover-corrupt-audit",
        "--recover-corrupt-audit=true",
        "--plan",
        "--plan=true",
    ],
)
def test_rescue_install_refuses_upgrade_override_before_network(
    tmp_path: Path,
    forbidden: str,
) -> None:
    env, rescue = _rescue_fixture(tmp_path)

    completed = subprocess.run(
        [str(rescue), "--install", forbidden],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert not (tmp_path / "curl.log").exists()


def test_release_workflow_advances_channel_only_after_immutable_custody() -> None:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    publish = workflow["jobs"]["publish-release"]
    channel = workflow["jobs"]["advance-stable-channel"]
    assert publish["permissions"] == {"contents": "write"}
    assert channel["needs"] == [
        "release-preflight",
        "assemble-release-candidate",
        "publish-release",
    ]
    assert channel["permissions"] == {"contents": "write", "id-token": "write"}
    assert "Sign and advance authenticated stable channel" not in [step.get("name") for step in publish["steps"]]
    names = [step.get("name") for step in channel["steps"]]
    assert names.index("Reverify the exact published candidate") < names.index("Prove published asset custody")
    assert names.index("Prove published asset custody") < names.index("Sign and advance authenticated stable channel")
    channel_step = next(
        step for step in channel["steps"] if step.get("name") == "Sign and advance authenticated stable channel"
    )
    assert channel_step["run"] == "scripts/publish-release-channel.sh"
    assert channel_step["env"]["RELEASE_CHECKSUMS"].endswith("/release-candidate/dist/checksums.txt")

    publisher = PUBLISHER.read_text(encoding="utf-8")
    assert 'readonly COSIGN_VERSION="2.6.3"' in publisher
    assert "cosign sign-blob" in publisher
    assert "scripts/verify-sigstore-blob.py" in publisher
    assert 'scripts/release_channel.py" compare' in publisher
    assert 'scripts/release_api_retry.py" require-latest-immutable' in publisher
    assert "current stable channel tip did not authenticate" in publisher
    assert "latest immutable release proof authorizes a fast-forward repair child" in publisher
    assert "git/matching-refs/heads/${CHANNEL_BRANCH}" in publisher
    assert "require_command cmp" in publisher
    assert "require_command tr" in publisher
    assert "readonly GH_READ_ATTEMPTS=3" in publisher
    assert "readonly GH_READ_RETRY_DELAYS=(1 2)" in publisher
    identity_definitions = re.findall(
        r"^readonly SIGNING_IDENTITY=(.+)$",
        publisher,
        flags=re.MULTILINE,
    )
    assert identity_definitions == [
        '"${SIGNING_IDENTITY_PREFIX}/${GITHUB_REPOSITORY}/.github/workflows/release.yaml@refs/heads/main"'
    ]

    continued_commands: list[str] = []
    command_lines: list[str] = []
    for line in publisher.splitlines():
        command_lines.append(line.strip())
        if line.rstrip().endswith("\\"):
            continue
        continued_commands.append(" ".join(command_lines))
        command_lines = []
    assert not command_lines

    verification_commands = [
        command
        for command in continued_commands
        if "verify-sigstore-blob.py" in command or "cosign verify-blob" in command
    ]
    assert verification_commands
    assert all(
        '--certificate-identity "${SIGNING_IDENTITY}"' in command
        and '--certificate-oidc-issuer "${SIGNING_OIDC_ISSUER}"' in command
        for command in verification_commands
    )

    read_wrapper_match = re.search(
        r"(?ms)^gh_api_read\(\) \{\n(?P<body>.*?)^\}\n",
        publisher,
    )
    assert read_wrapper_match is not None
    read_wrapper = read_wrapper_match.group(0)
    assert "gh api --method GET" in read_wrapper
    assert "GitHub API read failed after" in read_wrapper
    assert "gh api --method GET" not in publisher.replace(read_wrapper, "")
    assert re.search(r"(?m)^[ \t]+gh_api_read \\\n", publisher) is not None
    assert '"parents": [parent] if parent else []' in publisher
    channel_files_match = re.search(
        r"(?ms)^readonly CHANNEL_FILES=\(\n(?P<body>.*?)^\)\n",
        publisher,
    )
    assert channel_files_match is not None
    assert re.findall(
        r'^\s*"([^"]+)"$',
        channel_files_match.group("body"),
        flags=re.MULTILINE,
    ) == [
        "stable.txt",
        "stable.txt.sig",
        "stable.txt.pem",
        "stable.txt.bundle",
    ]
    assert 'tree_name_sha_pairs+=("${CHANNEL_FILES[index]}" "${blob_shas[index]}")' in publisher
    assert "-F force=false" in publisher
    assert "force=true" not in publisher
    assert "git push" not in publisher


@pytest.mark.skipif(os.name == "nt", reason="Bash release-channel publisher")
def test_explicit_repair_fast_forwards_over_invalid_tip_to_latest_release(
    tmp_path: Path,
) -> None:
    env, state = _publisher_repair_fixture(tmp_path)

    completed = subprocess.run(
        [str(PUBLISHER)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Repairing invalid stable channel" in completed.stderr
    commit_request = json.loads((state / "commit-request.json").read_text(encoding="utf-8"))
    assert commit_request["parents"] == [CHANNEL_BRANCH_COMMIT]
    update = json.loads((state / "ref-update.json").read_text(encoding="utf-8"))
    assert update == {"force": "false", "sha": "e" * 40}
    repaired = release_channel.load_channel(state / "published" / "stable.txt")
    assert repaired["target_version"] == VERSION
    assert repaired["target_commit"] == COMMIT


@pytest.mark.skipif(os.name == "nt", reason="Bash release-channel publisher")
def test_explicit_repair_refuses_rollback_before_ref_mutation(tmp_path: Path) -> None:
    env, state = _publisher_repair_fixture(tmp_path, latest_version="0.8.9")

    completed = subprocess.run(
        [str(PUBLISHER)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert "not the latest immutable stable release '0.8.9'" in completed.stderr
    assert "refusing channel rollback" in completed.stderr
    assert not (state / "ref-update.json").exists()
    assert not (state / "commit-request.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="Bash release-channel publisher")
def test_normal_channel_advance_refuses_invalid_current_tip(tmp_path: Path) -> None:
    env, state = _publisher_repair_fixture(tmp_path)
    env.pop("RELEASE_CHANNEL_REPAIR")

    completed = subprocess.run(
        [str(PUBLISHER)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert "current stable channel tip did not authenticate" in completed.stderr
    assert "Repairing invalid stable channel" not in completed.stderr
    assert not (state / "ref-update.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="Bash release-channel publisher")
def test_normal_channel_advance_refuses_canonical_tip_with_bad_signature(
    tmp_path: Path,
) -> None:
    env, state = _publisher_repair_fixture(
        tmp_path,
        current_valid=True,
        current_signature_valid=False,
    )
    env.pop("RELEASE_CHANNEL_REPAIR")

    completed = subprocess.run(
        [str(PUBLISHER)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert "current stable channel tip did not authenticate" in completed.stderr
    assert not (state / "ref-update.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="Bash release-channel publisher")
def test_normal_channel_advance_preserves_valid_monotonic_path(tmp_path: Path) -> None:
    env, state = _publisher_repair_fixture(tmp_path, current_valid=True)
    env.pop("RELEASE_CHANNEL_REPAIR")

    completed = subprocess.run(
        [str(PUBLISHER)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Repairing invalid stable channel" not in completed.stderr
    commit_request = json.loads((state / "commit-request.json").read_text(encoding="utf-8"))
    assert commit_request["parents"] == [CHANNEL_BRANCH_COMMIT]
    update = json.loads((state / "ref-update.json").read_text(encoding="utf-8"))
    assert update == {"force": "false", "sha": "e" * 40}


@pytest.mark.skipif(os.name == "nt", reason="Bash release-channel publisher")
def test_publisher_rejects_oversized_proof_before_any_repository_api(
    tmp_path: Path,
) -> None:
    assert "readonly CHANNEL_BUNDLE_MAX_BYTES=65536" in PUBLISHER.read_text(encoding="utf-8")
    checksums = tmp_path / "checksums.txt"
    checksums.write_text(
        _channel_checksums_text(),
        encoding="ascii",
    )
    mock_bin = tmp_path / "bin"
    mock_bin.mkdir()
    gh_called = tmp_path / "gh-called"
    _write_executable(
        mock_bin / "cosign",
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "${1-}" == "version" ]]; then
    printf 'GitVersion:    v2.6.3\\n'
    exit 0
fi
[[ "${1-}" == "sign-blob" ]] || exit 91
bundle=""
certificate=""
signature=""
for argument in "$@"; do
    case "${argument}" in
        --bundle=*) bundle="${argument#--bundle=}" ;;
        --output-certificate=*) certificate="${argument#--output-certificate=}" ;;
        --output-signature=*) signature="${argument#--output-signature=}" ;;
    esac
done
[[ -n "${bundle}" && -n "${certificate}" && -n "${signature}" ]]
printf 'fixture certificate\\n' > "${certificate}"
printf 'fixture signature\\n' > "${signature}"
python3 - "${bundle}" <<'PY'
import sys
from pathlib import Path

Path(sys.argv[1]).write_bytes(b"x" * (64 * 1024 + 1))
PY
""",
    )
    _write_executable(
        mock_bin / "gh",
        """#!/usr/bin/env bash
set -euo pipefail
: > "${GH_CALLED}"
exit 92
""",
    )
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir()
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{mock_bin}:{env['PATH']}",
            "GITHUB_REPOSITORY": REPOSITORY,
            "RELEASE_TAG": VERSION,
            "RELEASE_COMMIT": COMMIT,
            "RELEASE_CHECKSUMS": str(checksums),
            "GH_TOKEN": "fixture-token",
            "RUNNER_TEMP": str(runner_temp),
            "GH_CALLED": str(gh_called),
        }
    )

    completed = subprocess.run(
        [str(PUBLISHER)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert "candidate channel file has invalid size: stable.txt.bundle" in (completed.stderr)
    assert not gh_called.exists()


@pytest.mark.skipif(os.name == "nt", reason="Bash release-channel publisher")
def test_publisher_rejects_unreviewed_cosign_version_before_signing_or_api(
    tmp_path: Path,
) -> None:
    checksums = tmp_path / "checksums.txt"
    checksums.write_text(
        _channel_checksums_text(),
        encoding="ascii",
    )
    mock_bin = tmp_path / "bin"
    mock_bin.mkdir()
    cosign_called = tmp_path / "cosign-called"
    gh_called = tmp_path / "gh-called"
    _write_executable(
        mock_bin / "cosign",
        """#!/usr/bin/env bash
set -euo pipefail
if [[ "${1-}" == "version" ]]; then
    printf 'GitVersion:    v2.6.2\\n'
    exit 0
fi
: > "${COSIGN_CALLED}"
exit 92
""",
    )
    _write_executable(
        mock_bin / "gh",
        """#!/usr/bin/env bash
set -euo pipefail
: > "${GH_CALLED}"
exit 93
""",
    )
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir()
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{mock_bin}:{env['PATH']}",
            "GITHUB_REPOSITORY": REPOSITORY,
            "RELEASE_TAG": VERSION,
            "RELEASE_COMMIT": COMMIT,
            "RELEASE_CHECKSUMS": str(checksums),
            "GH_TOKEN": "fixture-token",
            "RUNNER_TEMP": str(runner_temp),
            "COSIGN_CALLED": str(cosign_called),
            "GH_CALLED": str(gh_called),
        }
    )

    completed = subprocess.run(
        [str(PUBLISHER)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )

    assert completed.returncode != 0
    assert "Cosign must be exactly v2.6.3" in completed.stderr
    assert not cosign_called.exists()
    assert not gh_called.exists()


def test_rescue_is_an_immutable_signed_asset_from_088_forward(
    tmp_path: Path,
) -> None:
    assert {"defenseclaw-rescue.sh", "defenseclaw-rescue.ps1"}.isdisjoint(
        release_candidate.payload_asset_names("0.8.7", "unverified")
    )
    assert {"defenseclaw-rescue.sh", "defenseclaw-rescue.ps1"} <= set(
        release_candidate.payload_asset_names("0.8.8", "unverified")
    )
    assert release_candidate.RESOLVER_ASSETS["defenseclaw-rescue.sh"].source == RESCUE
    assert release_candidate.RESOLVER_ASSETS["defenseclaw-rescue.ps1"].source == WINDOWS_RESCUE
    assert release_candidate._validated_resolver_source("defenseclaw-rescue.sh") == RESCUE
    assert release_candidate._validated_resolver_source("defenseclaw-rescue.ps1") == WINDOWS_RESCUE
    assert RESCUE.read_bytes().splitlines()[-1] == (release_candidate.RESCUE_COMPLETENESS_MARKER)
    assert WINDOWS_RESCUE.read_bytes().splitlines()[-1] == (release_candidate.WINDOWS_RESCUE_COMPLETENESS_MARKER)
    staged = tmp_path / "staged"
    staged.mkdir()
    release_candidate.stage_resolvers(staged, "0.8.8")
    assert (staged / "defenseclaw-rescue.sh").read_bytes() == RESCUE.read_bytes()
    assert (staged / "defenseclaw-rescue.ps1").read_bytes() == WINDOWS_RESCUE.read_bytes()


@pytest.mark.parametrize("script", [RESCUE, PUBLISHER], ids=lambda path: path.name)
def test_release_channel_scripts_have_valid_bash_syntax(script: Path) -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable")
    subprocess.run(
        [bash, "-n", str(script)],
        cwd=ROOT,
        check=True,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )


def test_release_channel_documentation_preserves_trust_boundary() -> None:
    text = DOC.read_text(encoding="utf-8")
    for required in (
        "mutable pointer to immutable code",
        "`release-channel` branch",
        "`release.yaml@main` Fulcio identity",
        "Do not stream a raw branch or release response directly into a shell.",
        "--output ./defenseclaw-rescue.sh",
        "refuses stdin or pipe execution",
        "The bootstrap rejects an operator-supplied `--version`",
        "defenseclaw-rescue.sh --install",
        "checksummed `install.sh` asset",
        "non-forced, fast-forward Git",
    ):
        assert required in text
