# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw import install_publish

ROOT = Path(__file__).resolve().parents[2]
PUBLISHER = ROOT / "scripts/source-install-publish.py"


def _run(*arguments: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(PUBLISHER), *(str(argument) for argument in arguments)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )


def _claim(completed: subprocess.CompletedProcess[str]) -> tuple[str, tuple[int, int, int, int]]:
    assert completed.returncode == 0, completed.stderr
    value = completed.stdout.strip()
    parts = tuple(int(part) for part in value.split(":"))
    assert len(parts) == 4
    return value, parts


def _path_claim(path: Path) -> tuple[str, tuple[int, int, int, int]]:
    return _claim(_run("path-identity", path))


def _source_marker_bytes(**changes: object) -> bytes:
    marker: dict[str, object] = {
        "schema_version": 2,
        "checkout_root": str(Path(Path.cwd().anchor) / "tmp" / "defenseclaw-checkout"),
        "source_release": "0.8.6",
        "source_install_compatibility_epoch": 2,
        "runtime_config_version": 8,
        "gateway_sha256": "0" * 64,
    }
    marker.update(changes)
    return json.dumps(marker, sort_keys=True).encode("utf-8")


def _parse_source_marker(raw: bytes) -> dict[str, int | str]:
    return install_publish.parse_source_marker(
        raw,
        source_release="0.8.6",
        compatibility_epoch=2,
        runtime_version=8,
        allow_source_transition=True,
    )


@pytest.mark.parametrize("encoding", ("utf-16", "utf-32"))
def test_source_marker_requires_strict_utf8(encoding: str) -> None:
    raw = _source_marker_bytes().decode("utf-8").encode(encoding)

    with pytest.raises(install_publish.SourceMarkerError, match="not valid UTF-8 JSON"):
        _parse_source_marker(raw)


def test_source_marker_rejects_duplicate_fields() -> None:
    raw = _source_marker_bytes()
    duplicated = b'{"schema_version":2,' + raw.removeprefix(b"{")

    with pytest.raises(install_publish.SourceMarkerError, match="duplicate field 'schema_version'"):
        _parse_source_marker(duplicated)


@pytest.mark.parametrize("schema_version", (2.0, "2", True))
def test_source_marker_requires_an_integer_schema_version(schema_version: object) -> None:
    with pytest.raises(install_publish.SourceMarkerError, match="marker schema must be 2"):
        _parse_source_marker(_source_marker_bytes(schema_version=schema_version))


def test_source_marker_wraps_oversized_json_integers() -> None:
    raw = _source_marker_bytes().replace(b'"runtime_config_version": 8', b'"runtime_config_version": ' + b"9" * 5000)

    with pytest.raises(install_publish.SourceMarkerError, match="not valid UTF-8 JSON"):
        _parse_source_marker(raw)


def test_source_marker_rejects_every_c0_and_c1_control() -> None:
    for codepoint in (*range(0x20), *range(0x7F, 0xA0)):
        raw = _source_marker_bytes(checkout_root="/tmp/defenseclaw-" + chr(codepoint) + "checkout")
        with pytest.raises(
            install_publish.SourceMarkerError,
            match="checkout_root must be a canonical non-root absolute path",
        ):
            _parse_source_marker(raw)


@pytest.mark.parametrize(
    "changes",
    (
        {"source_release": "0.8.7"},
        {"source_install_compatibility_epoch": 3},
        {"runtime_config_version": 9},
    ),
)
def test_source_marker_rejects_newer_compatibility_values(changes: dict[str, object]) -> None:
    with pytest.raises(install_publish.SourceMarkerError, match="newer than this checkout"):
        _parse_source_marker(_source_marker_bytes(**changes))


def test_windows_file_disposition_abi_uses_one_byte_boolean() -> None:
    assert ctypes.sizeof(install_publish._WindowsFileDispositionInfo) == 1


@pytest.mark.skipif(os.name != "nt", reason="requires native Win32 relative opens")
def test_windows_publication_pins_parent_and_creates_relative_to_handle(tmp_path: Path) -> None:
    directory = tmp_path / "empty-parent"
    moved = tmp_path / "moved-parent"
    directory.mkdir()
    api = install_publish._windows_api()

    with install_publish._hold_windows_directory_chain(directory, create=False) as chain:
        with pytest.raises(OSError):
            os.replace(directory, moved)
        handle = api.create_regular_at(chain[-1][0], "staged-file")
        api.close(handle)
        handle = api.open_publication_claim_at(chain[-1][0], "staged-file")
        try:
            api.rename_no_replace(handle, chain[-1][0], "anchored-file")
        finally:
            api.close(handle)

        collision = api.create_regular_at(chain[-1][0], "collision-stage")
        api.close(collision)
        collision = api.open_publication_claim_at(chain[-1][0], "collision-stage")
        try:
            with pytest.raises(FileExistsError):
                api.rename_no_replace(collision, chain[-1][0], "anchored-file")
            api.delete_on_close(collision)
        finally:
            api.close(collision)

    assert (directory / "anchored-file").is_file()
    assert not (directory / "staged-file").exists()
    assert not (directory / "collision-stage").exists()
    assert not moved.exists()


def test_source_preflight_publication_verbs_are_directly_executable(tmp_path: Path) -> None:
    install_dir = tmp_path / "home/.local/bin"
    reserved = _run("ensure-directory", install_dir)
    assert reserved.returncode == 0, reserved.stderr
    assert install_dir.is_dir() and not install_dir.is_symlink()

    cli = install_dir / "defenseclaw"
    target = str(tmp_path / "checkout/.venv/bin/defenseclaw")
    Path(target).parent.mkdir(parents=True)
    Path(target).write_bytes(b"cli entrypoint\n")
    linked = _run("symlink", target, cli)
    assert linked.returncode == 0, linked.stderr
    if os.name == "nt":
        assert not cli.is_symlink()
        assert cli.read_bytes() == b"cli entrypoint\n"
    else:
        assert cli.is_symlink() and os.readlink(cli) == target

    source = tmp_path / "checkout/defenseclaw-gateway"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"new gateway\n")
    source.chmod(0o755)
    destination = install_dir / "defenseclaw-gateway"
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    current_arguments: tuple[str, ...] = ()
    if os.name != "nt":
        destination.write_bytes(b"old gateway\n")
        destination.chmod(0o755)
        current_arguments = (
            "--expected-current-sha256",
            hashlib.sha256(destination.read_bytes()).hexdigest(),
        )

    published = _run(
        "regular",
        source,
        destination,
        "--expected-source-sha256",
        source_digest,
        *current_arguments,
    )

    assert published.returncode == 0, published.stderr
    assert destination.read_bytes() == b"new gateway\n"
    assert not list(install_dir.glob(".defenseclaw-gateway.source-install-*"))


def test_source_preflight_digest_and_compare_verbs_are_directly_executable(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first-gateway"
    second = tmp_path / "second-gateway"
    payload = b"matching gateway\n"
    first.write_bytes(payload)
    second.write_bytes(payload)
    first.chmod(0o755)
    second.chmod(0o755)
    expected = hashlib.sha256(payload).hexdigest()

    digested = _run("sha256-regular", first, "--require-executable")
    assert digested.returncode == 0, digested.stderr
    assert digested.stdout.strip() == expected

    compared = _run(
        "compare-regular",
        first,
        second,
        "--require-executable",
    )
    assert compared.returncode == 0, compared.stderr
    assert compared.stdout.strip() == expected

    second.write_bytes(b"different gateway\n")
    mismatched = _run("compare-regular", first, second, "--require-executable")
    assert mismatched.returncode != 0
    assert "do not match" in mismatched.stderr

    if os.name != "nt":
        first.chmod(0o600)
        non_executable = _run("sha256-regular", first, "--require-executable")
        assert non_executable.returncode != 0
        assert "not executable" in non_executable.stderr


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_regular_publication_rejects_wrong_source_digest_before_destination_change(
    tmp_path: Path,
) -> None:
    source = tmp_path / "gateway"
    destination = tmp_path / "installed-gateway"
    source.write_bytes(b"replacement gateway\n")
    destination.write_bytes(b"installed gateway\n")
    current_digest = hashlib.sha256(destination.read_bytes()).hexdigest()

    refused = _run(
        "regular",
        source,
        destination,
        "--expected-source-sha256",
        hashlib.sha256(b"authenticated gateway\n").hexdigest(),
        "--expected-current-sha256",
        current_digest,
    )

    assert refused.returncode != 0
    assert "candidate changed before publication" in refused.stderr
    assert destination.read_bytes() == b"installed gateway\n"
    assert not list(tmp_path.glob(".installed-gateway.source-install-*"))


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_regular_publication_hashes_the_same_open_source_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "gateway"
    replacement = tmp_path / "replacement"
    destination = tmp_path / "installed-gateway"
    authenticated = b"authenticated gateway\n"
    source.write_bytes(authenticated)
    replacement.write_bytes(b"concurrent replacement\n")
    real_open = install_publish.os.open
    source_opened = False

    def race_after_source_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal source_opened
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if dir_fd is None and Path(path) == source and not source_opened:
            source_opened = True
            os.replace(replacement, source)
        return descriptor

    monkeypatch.setattr(install_publish.os, "open", race_after_source_open)

    install_publish.publish_regular(
        source,
        destination,
        None,
        expected_source=hashlib.sha256(authenticated).hexdigest(),
    )

    assert source_opened
    assert source.read_bytes() == b"concurrent replacement\n"
    assert destination.read_bytes() == authenticated


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_regular_comparison_opens_both_paths_before_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = tmp_path / "source-gateway"
    second = tmp_path / "installed-gateway"
    first_replacement = tmp_path / "source-replacement"
    second_replacement = tmp_path / "installed-replacement"
    compared = b"matching gateway\n"
    first.write_bytes(compared)
    second.write_bytes(compared)
    first_replacement.write_bytes(b"new source\n")
    second_replacement.write_bytes(b"new destination\n")
    for path in (first, second, first_replacement, second_replacement):
        path.chmod(0o755)
    real_open = install_publish.os.open
    second_opened = False

    def race_after_second_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal second_opened
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if dir_fd is None and Path(path) == second and not second_opened:
            second_opened = True
            os.replace(first_replacement, first)
            os.replace(second_replacement, second)
        return descriptor

    monkeypatch.setattr(install_publish.os, "open", race_after_second_open)

    digest = install_publish.matching_regular_sha256(
        first,
        second,
        require_executable=True,
    )

    assert second_opened
    assert digest == hashlib.sha256(compared).hexdigest()
    assert first.read_bytes() == b"new source\n"
    assert second.read_bytes() == b"new destination\n"


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_fresh_regular_token_commits_or_rolls_back_only_its_inode(tmp_path: Path) -> None:
    install_dir = tmp_path / "home/.local/bin"
    install_dir.mkdir(parents=True)
    source = tmp_path / "gateway"
    source.write_bytes(b"gateway\n")
    source.chmod(0o755)

    destination = install_dir / "defenseclaw-gateway"
    custody = tmp_path / "custody"
    published = _run(
        "fresh-regular",
        source,
        destination,
        "--retain-token",
        "--custody-root",
        custody,
    )
    assert published.returncode == 0, published.stderr
    token = published.stdout.strip()
    assert token
    assert destination.read_bytes() == b"gateway\n"
    assert len(list(install_dir.iterdir())) == 2

    committed = _run("commit-token", token)
    assert committed.returncode == 0, committed.stderr
    assert destination.read_bytes() == b"gateway\n"
    assert list(install_dir.iterdir()) == [destination]
    retired = [path for path in custody.iterdir() if path.name.startswith("retired-")]
    assert len(retired) == 1
    assert retired[0].stat().st_ino == destination.stat().st_ino

    destination.unlink()
    published = _run(
        "fresh-regular",
        source,
        destination,
        "--retain-token",
        "--custody-root",
        custody,
    )
    assert published.returncode == 0, published.stderr
    rolled_back = _run("rollback-token", published.stdout.strip())
    assert rolled_back.returncode == 0, rolled_back.stderr
    assert list(install_dir.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_rollback_token_preserves_concurrent_replacement(tmp_path: Path) -> None:
    install_dir = tmp_path / "bin"
    install_dir.mkdir()
    source = tmp_path / "gateway"
    source.write_bytes(b"ours\n")
    destination = install_dir / "defenseclaw-gateway"
    custody = tmp_path / "custody"
    published = _run(
        "fresh-regular",
        source,
        destination,
        "--retain-token",
        "--custody-root",
        custody,
    )
    assert published.returncode == 0, published.stderr
    token = published.stdout.strip()

    destination.unlink()
    destination.write_bytes(b"concurrent\n")
    refused = _run("rollback-token", token)
    assert refused.returncode != 0
    assert destination.read_bytes() == b"concurrent\n"
    assert len(list(install_dir.iterdir())) == 2

    committed = _run("commit-token", token)
    assert committed.returncode == 0, committed.stderr
    assert list(install_dir.iterdir()) == [destination]


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_rollback_token_second_leg_preserves_replaced_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_dir = tmp_path / "bin"
    install_dir.mkdir()
    source = tmp_path / "gateway"
    source.write_bytes(b"ours\n")
    destination = install_dir / "defenseclaw-gateway"
    custody = tmp_path / "custody"
    token = install_publish.publish_regular(
        source,
        destination,
        None,
        retain_token=True,
        custody_root=custody,
    )
    assert token is not None
    token_destination, stage, original_identity, token_custody = install_publish._decode_rollback_token(token)
    assert token_destination == destination
    assert token_custody == custody
    real_unlink_exact = install_publish.unlink_exact
    replaced_identity: tuple[int, int, int, int] | None = None

    def replace_stage_after_first_leg(
        path: Path,
        expected: install_publish.ObjectIdentity,
        *,
        custody_root: Path | None = None,
    ) -> bool:
        nonlocal replaced_identity
        assert custody_root == custody
        removed = real_unlink_exact(path, expected, custody_root=custody_root)
        if path == destination and removed:
            stage.unlink()
            stage.write_bytes(b"concurrent replacement\n")
            replaced_identity = install_publish.path_identity(stage)
        return removed

    monkeypatch.setattr(install_publish, "unlink_exact", replace_stage_after_first_leg)

    with pytest.raises(install_publish.PublishError, match="rollback token changed"):
        install_publish.rollback_token(token)

    assert not destination.exists()
    assert stage.read_bytes() == b"concurrent replacement\n"
    assert replaced_identity is not None and replaced_identity != original_identity


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_fresh_symlink_refuses_even_identical_existing_target(tmp_path: Path) -> None:
    install_dir = tmp_path / "bin"
    install_dir.mkdir()
    destination = install_dir / "defenseclaw"
    target = "/private/runtime/bin/defenseclaw"
    destination.symlink_to(target)

    refused = _run("fresh-symlink", target, destination)

    assert refused.returncode != 0
    assert destination.is_symlink()
    assert os.readlink(destination) == target

    fresh_destination = install_dir / "defenseclaw-fresh"
    published = _run("fresh-symlink", target, fresh_destination)
    _value, identity = _claim(published)
    observed = os.lstat(fresh_destination)
    assert identity[:2] == (observed.st_dev, observed.st_ino)


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_fresh_symlink_staging_preserves_late_foreign_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "defenseclaw"
    custody = tmp_path / "custody"
    target = "/private/runtime/bin/defenseclaw"
    foreign = "/foreign/runtime/bin/defenseclaw"
    real_rename = install_publish._rename_no_replace_between
    injected = False

    def inject_before_activation(
        source_parent: int,
        source: str,
        destination_parent: int,
        activated: str,
    ) -> None:
        nonlocal injected
        if activated == destination.name and not injected:
            injected = True
            os.symlink(foreign, destination.name, dir_fd=destination_parent)
        real_rename(source_parent, source, destination_parent, activated)

    monkeypatch.setattr(install_publish, "_rename_no_replace_between", inject_before_activation)

    with pytest.raises(install_publish.PublishError, match="appeared concurrently"):
        install_publish.publish_symlink(
            target,
            destination,
            fresh_only=True,
            custody_root=custody,
        )

    assert destination.is_symlink()
    assert os.readlink(destination) == foreign
    assert len(list(custody.glob("retired-*"))) == 1


@pytest.mark.skipif(sys.platform != "darwin", reason="exact O_SYMLINK regression is Darwin-only")
def test_darwin_system_python_uses_exact_symlink_birth_identity(tmp_path: Path) -> None:
    destination = tmp_path.resolve() / "defenseclaw"
    destination.symlink_to("/private/runtime/bin/defenseclaw")
    expected = ":".join(str(part) for part in install_publish.path_identity(destination))

    observed = subprocess.run(
        ["/usr/bin/python3", str(PUBLISHER), "path-identity", str(destination)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert observed.returncode == 0, observed.stderr
    assert observed.stdout.strip() == expected


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_unlink_exact_preserves_replacement_and_removes_exact_inode(tmp_path: Path) -> None:
    destination = tmp_path / "entry"
    destination.write_bytes(b"original\n")
    original_claim, original_identity = _path_claim(destination)
    destination.unlink()
    destination.write_bytes(b"replacement\n")
    replacement_claim, replacement_identity = _path_claim(destination)

    # Filesystems may immediately recycle the same inode.  The kernel birth
    # identity must still distinguish the replacement without a timing delay.
    assert original_claim != replacement_claim

    custody = tmp_path / "custody"
    refused = _run("unlink-exact", destination, original_claim, "--custody-root", custody)
    assert refused.returncode != 0
    assert destination.read_bytes() == b"replacement\n"

    observed = os.lstat(destination)
    assert replacement_identity[:2] == (observed.st_dev, observed.st_ino)
    assert original_identity[2:] != replacement_identity[2:] or original_identity[:2] != replacement_identity[:2]
    removed = _run("unlink-exact", destination, replacement_claim, "--custody-root", custody)
    assert removed.returncode == 0, removed.stderr
    assert not destination.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_symlink_retirement_revalidates_target_after_entering_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path.resolve() / "defenseclaw"
    foreign_target = tmp_path / "foreign" / "defenseclaw"
    expected_target = tmp_path / "managed" / "defenseclaw"
    destination.symlink_to(foreign_target)
    identity = install_publish.path_identity(destination)
    custody = tmp_path / "custody"
    real_readlink = install_publish.os.readlink
    reads = 0

    def spoof_first_target(path, *args, **kwargs):
        nonlocal reads
        reads += 1
        if reads == 1:
            return str(expected_target)
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(install_publish.os, "readlink", spoof_first_target)
    removed = install_publish.unlink_exact_symlink(
        destination,
        identity,
        (str(expected_target),),
        custody_root=custody,
    )
    monkeypatch.setattr(install_publish.os, "readlink", real_readlink)

    assert not removed
    assert reads == 2
    assert os.readlink(destination) == str(foreign_target)
    intent = json.loads(next(custody.glob("intent-*.json")).read_bytes())
    assert intent["schema_version"] == 2
    assert intent["kind"] == "symlink"
    assert intent["symlink_targets"] == [str(expected_target)]
    with pytest.raises(
        install_publish.PublishError,
        match="retirement recovery preserved unresolved state",
    ):
        install_publish.recover_custody(custody)
    assert os.readlink(destination) == str(foreign_target)


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_real_directory_reservation_refuses_symlink_ancestor(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    managed = tmp_path / "managed"
    managed.symlink_to(outside, target_is_directory=True)

    refused = _run("ensure-real-directory", managed / "bin")

    assert refused.returncode != 0
    assert list(outside.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
@pytest.mark.parametrize("failure_point", ("open", "identity"))
def test_ensure_directory_cleans_attempt_created_stage_after_binding_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    destination = tmp_path / "managed"
    if failure_point == "open":
        real_open = install_publish.os.open
        staged_opens = 0
        failed_open_number = 2 if sys.platform == "darwin" else 1

        def fail_staged_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            nonlocal staged_opens
            if dir_fd is not None and ".install-directory-" in os.fsdecode(path):
                staged_opens += 1
                if staged_opens == failed_open_number:
                    raise OSError("injected staged-directory open failure")
            return real_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(install_publish.os, "open", fail_staged_open)
    else:
        real_strong_identity = install_publish._strong_identity
        identity_calls = 0
        failed_identity_call = 2 if sys.platform == "darwin" else 1

        def fail_staged_identity(_descriptor: int) -> tuple[int, int, int, int]:
            nonlocal identity_calls
            identity_calls += 1
            if identity_calls == failed_identity_call:
                raise OSError("injected staged-directory identity failure")
            return real_strong_identity(_descriptor)

        monkeypatch.setattr(install_publish, "_strong_identity", fail_staged_identity)

    with pytest.raises(install_publish.PublishError, match="appeared concurrently"):
        install_publish.ensure_directory(destination)

    assert not destination.exists()
    assert list(tmp_path.glob(".managed.install-directory-*")) == []


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_ensure_directory_binding_failure_preserves_concurrent_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "managed"
    replacement: Path | None = None
    real_strong_identity = install_publish._strong_identity
    identity_failed = False

    def replace_before_identity(descriptor: int) -> tuple[int, int, int, int]:
        nonlocal identity_failed, replacement
        if not identity_failed:
            identity_failed = True
            staged = next(tmp_path.glob(".managed.install-directory-*"))
            staged.rmdir()
            staged.mkdir()
            replacement = staged / "foreign-sentinel"
            replacement.write_text("preserve", encoding="utf-8")
            raise OSError("injected identity failure after concurrent replacement")
        return real_strong_identity(descriptor)

    monkeypatch.setattr(install_publish, "_strong_identity", replace_before_identity)

    with pytest.raises(install_publish.PublishError, match="appeared concurrently"):
        install_publish.ensure_directory(destination)

    assert replacement is not None
    assert replacement.read_text(encoding="utf-8") == "preserve"
    assert not destination.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_fresh_directory_identity_supports_exact_empty_rollback(tmp_path: Path) -> None:
    destination = tmp_path / "claimed"
    claimed = _run("fresh-directory", destination)
    identity_value, identity = _claim(claimed)
    observed = os.lstat(destination)
    assert identity[:2] == (observed.st_dev, observed.st_ino)

    duplicate = _run("fresh-directory", destination)
    assert duplicate.returncode != 0
    assert destination.is_dir()

    removed = _run("rmdir-exact", destination, identity_value, "--custody-root", tmp_path / "custody")
    assert removed.returncode == 0, removed.stderr
    assert not destination.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_rmdir_exact_preserves_nonempty_or_replaced_directory(tmp_path: Path) -> None:
    destination = tmp_path / "claimed"
    claimed = _run("fresh-directory", destination)
    identity_value, _identity = _claim(claimed)
    keep = destination / "keep"
    keep.write_text("state", encoding="utf-8")

    custody = tmp_path / "custody"
    nonempty = _run("rmdir-exact", destination, identity_value, "--custody-root", custody)
    assert nonempty.returncode != 0
    assert keep.read_text(encoding="utf-8") == "state"

    keep.unlink()
    destination.rmdir()
    destination.mkdir()
    replacement = destination / "replacement"
    replacement.write_text("preserve", encoding="utf-8")
    replaced = _run("rmdir-exact", destination, identity_value, "--custody-root", custody)
    assert replaced.returncode != 0
    assert replacement.read_text(encoding="utf-8") == "preserve"


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_remove_tree_exact_is_bounded_and_never_follows_symlinks(tmp_path: Path) -> None:
    destination = tmp_path / "venv"
    claimed = _run("fresh-directory", destination)
    identity_value, _identity = _claim(claimed)
    package = destination / "lib/python/site-packages/example"
    package.mkdir(parents=True)
    (package / "module.py").write_text("value = 1\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("preserve", encoding="utf-8")
    (destination / "outside-link").symlink_to(outside, target_is_directory=True)

    custody = tmp_path / "custody"
    removed = _run("remove-tree-exact", destination, identity_value, "--custody-root", custody)

    assert removed.returncode == 0, removed.stderr
    assert not destination.exists()
    assert sentinel.read_text(encoding="utf-8") == "preserve"

    deep = tmp_path / "deep-venv"
    claimed = _run("fresh-directory", deep)
    deep_identity_value, _deep_identity = _claim(claimed)
    current = deep
    for _index in range(66):
        current = current / "d"
        current.mkdir()

    refused = _run("remove-tree-exact", deep, deep_identity_value, "--custody-root", custody)

    assert refused.returncode != 0
    assert "depth bound" in refused.stderr
    assert deep.is_dir()
    assert current.is_dir()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_remove_tree_exact_preserves_replacement(tmp_path: Path) -> None:
    destination = tmp_path / "venv"
    claimed = _run("fresh-directory", destination)
    identity_value, original_identity = _claim(claimed)
    destination.rmdir()
    destination.mkdir()
    _replacement_value, replacement_identity = _path_claim(destination)
    assert original_identity != replacement_identity
    sentinel = destination / "concurrent"
    sentinel.write_text("preserve", encoding="utf-8")

    refused = _run(
        "remove-tree-exact",
        destination,
        identity_value,
        "--custody-root",
        tmp_path / "custody",
    )

    assert refused.returncode != 0
    assert sentinel.read_text(encoding="utf-8") == "preserve"


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_exact_retirement_recovers_after_crash_post_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    real_rename = install_publish._rename_no_replace_between
    crashed = False

    def crash_after_rename(
        source_parent: int,
        source: str,
        destination_parent: int,
        retired: str,
    ) -> None:
        nonlocal crashed
        real_rename(source_parent, source, destination_parent, retired)
        if source == destination.name and not crashed:
            crashed = True
            raise SystemExit("simulated process death after durable rename")

    monkeypatch.setattr(install_publish, "_rename_no_replace_between", crash_after_rename)
    with pytest.raises(SystemExit):
        install_publish.unlink_exact(destination, identity, custody_root=custody)
    monkeypatch.setattr(install_publish, "_rename_no_replace_between", real_rename)

    assert not destination.exists()
    assert len(list(custody.glob("intent-*.json"))) == 1
    assert len(list(custody.glob("retired-*"))) == 1
    install_publish.recover_custody(custody)
    assert not destination.exists()
    assert next(custody.glob("retired-*")).read_bytes() == b"attempt-owned\n"


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_policy_custody_works_under_sticky_world_writable_parent(tmp_path: Path) -> None:
    shared_parent = tmp_path / "shared-tmp"
    shared_parent.mkdir()
    shared_parent.chmod(0o1777)
    custody = shared_parent / "policy-custody"

    install_publish.recover_custody(custody)
    assert not custody.exists()

    install_publish.prepare_custody(custody, shared_parent)
    policy_tree = shared_parent / "policy-tree"
    policy_tree.mkdir()
    (policy_tree / "policy.json").write_bytes(b'{"allow":true}\n')
    identity = install_publish.path_identity(policy_tree)
    assert install_publish.remove_tree_exact(policy_tree, identity, custody_root=custody)

    install_publish.recover_custody(custody)

    assert not policy_tree.exists()
    retired = next(custody.glob("retired-*"))
    assert (retired / "policy.json").read_bytes() == b'{"allow":true}\n'


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_custody_locks_are_isolated_per_exact_root(tmp_path: Path) -> None:
    first = tmp_path / "first-custody"
    second = tmp_path / "second-custody"
    first_entered = threading.Event()
    release_first = threading.Event()
    errors: list[BaseException] = []

    def hold_first() -> None:
        parent_fd = install_publish._open_directory(tmp_path, create=False)
        try:
            with install_publish._hold_custody_parent_lock(parent_fd, first):
                first_entered.set()
                if not release_first.wait(5):
                    raise AssertionError("test did not release first custody lock")
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)
        finally:
            os.close(parent_fd)

    holder = threading.Thread(target=hold_first)
    holder.start()
    assert first_entered.wait(5)

    install_publish.prepare_custody(second, tmp_path)
    assert (second / install_publish.CUSTODY_MARKER_NAME).is_file()

    release_first.set()
    holder.join(5)
    assert not holder.is_alive()
    assert not errors
    assert not (tmp_path / install_publish._custody_lock_name(first)).exists()
    assert not (tmp_path / install_publish._custody_lock_name(second)).exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_custody_lock_wait_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    custody = tmp_path / "custody"
    entered = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []

    def hold_lock() -> None:
        parent_fd = install_publish._open_directory(tmp_path, create=False)
        try:
            with install_publish._hold_custody_parent_lock(parent_fd, custody):
                entered.set()
                if not release.wait(5):
                    raise AssertionError("test did not release custody lock")
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)
        finally:
            os.close(parent_fd)

    holder = threading.Thread(target=hold_lock)
    holder.start()
    assert entered.wait(5)
    monkeypatch.setattr(install_publish, "CUSTODY_LOCK_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(install_publish, "CUSTODY_LOCK_POLL_SECONDS", 0.005)
    parent_fd = install_publish._open_directory(tmp_path, create=False)
    try:
        with pytest.raises(install_publish.PublishError, match="timed out waiting"):
            with install_publish._hold_custody_parent_lock(parent_fd, custody):
                raise AssertionError("contended custody lock was entered")
    finally:
        os.close(parent_fd)
        release.set()
        holder.join(5)

    assert not holder.is_alive()
    assert not errors


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_custody_lock_rejects_precreated_unsafe_file(tmp_path: Path) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"preserve\n")
    identity = install_publish.path_identity(destination)
    lock = tmp_path / install_publish._custody_lock_name(custody)
    lock.write_bytes(b"foreign\n")
    lock.chmod(0o600)

    with pytest.raises(install_publish.PublishError, match="lifecycle lock is unsafe"):
        install_publish.unlink_exact(destination, identity, custody_root=custody)

    assert destination.read_bytes() == b"preserve\n"
    assert lock.read_bytes() == b"foreign\n"


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_stale_custody_lock_waiter_retries_new_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    custody = tmp_path / "custody"
    holder_entered = threading.Event()
    waiter_opened = threading.Event()
    release_holder = threading.Event()
    waiter_entered = threading.Event()
    errors: list[BaseException] = []
    real_open = install_publish._open_custody_lock_at
    opened_by_waiter = 0
    first_identity: tuple[int, int, int, int] | None = None
    waiter_identity: tuple[int, int, int, int] | None = None

    def observe_open(parent_fd: int, lock_name: str) -> int:
        nonlocal opened_by_waiter
        descriptor = real_open(parent_fd, lock_name)
        if threading.current_thread().name == "custody-waiter":
            opened_by_waiter += 1
            if opened_by_waiter == 1:
                waiter_opened.set()
        return descriptor

    monkeypatch.setattr(install_publish, "_open_custody_lock_at", observe_open)

    def hold_old_inode() -> None:
        nonlocal first_identity
        parent_fd = install_publish._open_directory(tmp_path, create=False)
        try:
            with install_publish._hold_custody_parent_lock(parent_fd, custody):
                first_identity = install_publish.path_identity(tmp_path / install_publish._custody_lock_name(custody))
                holder_entered.set()
                if not release_holder.wait(5):
                    raise AssertionError("test did not release old custody lock")
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)
        finally:
            os.close(parent_fd)

    def wait_for_new_inode() -> None:
        nonlocal waiter_identity
        parent_fd = install_publish._open_directory(tmp_path, create=False)
        try:
            with install_publish._hold_custody_parent_lock(parent_fd, custody):
                waiter_identity = install_publish.path_identity(tmp_path / install_publish._custody_lock_name(custody))
                waiter_entered.set()
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)
        finally:
            os.close(parent_fd)

    holder = threading.Thread(target=hold_old_inode, name="custody-holder")
    waiter = threading.Thread(target=wait_for_new_inode, name="custody-waiter")
    holder.start()
    assert holder_entered.wait(5)
    waiter.start()
    assert waiter_opened.wait(5)
    release_holder.set()
    holder.join(5)
    waiter.join(5)

    assert not holder.is_alive()
    assert not waiter.is_alive()
    assert waiter_entered.is_set()
    assert not errors
    assert opened_by_waiter >= 2
    assert first_identity is not None
    assert waiter_identity is not None
    assert waiter_identity != first_identity
    assert not (tmp_path / install_publish._custody_lock_name(custody)).exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_inspection_removes_crash_left_idle_lock(tmp_path: Path) -> None:
    custody = tmp_path / "custody"
    lock_name = install_publish._custody_lock_name(custody)
    parent_fd = install_publish._open_directory(tmp_path, create=False)
    try:
        lock_fd = install_publish._open_custody_lock_at(parent_fd, lock_name)
        os.close(lock_fd)
    finally:
        os.close(parent_fd)

    assert (tmp_path / lock_name).is_file()
    assert install_publish.inspect_custody_cleanup(custody) is None
    assert not (tmp_path / lock_name).exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_nonsticky_world_writable_custody_parent_is_rejected(tmp_path: Path) -> None:
    shared_parent = tmp_path / "unsafe-shared"
    shared_parent.mkdir()
    shared_parent.chmod(0o777)
    custody = shared_parent / "custody"

    with pytest.raises(install_publish.PublishError, match="sticky shared"):
        install_publish.prepare_custody(custody, shared_parent)

    assert not custody.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_attacker_owned_sticky_custody_parent_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent_fd = install_publish._open_directory(tmp_path, create=False)
    real_fstat = install_publish.os.fstat
    attacker_uid = os.geteuid() + 1 if os.geteuid() != 0 else 12345

    def fake_fstat(descriptor: int):
        if descriptor == parent_fd:
            return SimpleNamespace(st_uid=attacker_uid, st_mode=stat.S_IFDIR | 0o1777)
        return real_fstat(descriptor)

    monkeypatch.setattr(install_publish.os, "fstat", fake_fstat)
    try:
        with pytest.raises(install_publish.PublishError, match="sticky shared"):
            install_publish._validate_custody_lifecycle_parent(parent_fd, tmp_path / "custody")
    finally:
        os.close(parent_fd)


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_system_temporary_parent_is_accepted_for_custody_lock() -> None:
    shared_parent = Path("/tmp").resolve()
    metadata = shared_parent.stat()
    if not metadata.st_mode & stat.S_ISVTX or metadata.st_uid not in {0, os.geteuid()}:
        pytest.skip("system temporary parent does not use the supported sticky policy")
    parent_fd = install_publish._open_directory(shared_parent, create=False)
    try:
        install_publish._validate_custody_lifecycle_parent(parent_fd, shared_parent / "policy-custody")
    finally:
        os.close(parent_fd)


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_custody_lock_name_accepts_surrogateescaped_path(tmp_path: Path) -> None:
    raw = os.fsencode(tmp_path) + b"/custody-\xff"
    custody = Path(os.fsdecode(raw))

    lock_name = install_publish._custody_lock_name(custody)

    expected = hashlib.sha256(os.fsencode(custody)).hexdigest()[:32]
    assert lock_name == f"{install_publish.CUSTODY_LOCK_PREFIX}{expected}"


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_discard_custody_rejects_unknown_entry_before_deleting_records(tmp_path: Path) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    retired = next(custody.glob("retired-*"))
    intent = next(custody.glob("intent-*.json"))
    foreign = custody / "operator-note"
    foreign.write_bytes(b"preserve\n")

    with pytest.raises(install_publish.PublishError, match="unexpected or incomplete"):
        install_publish.discard_custody(custody)

    assert retired.read_bytes() == b"attempt-owned\n"
    assert intent.is_file()
    assert foreign.read_bytes() == b"preserve\n"
    assert not (custody / install_publish.CUSTODY_DISCARD_MARKER).exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_discard_custody_rejects_substituted_retired_entry(tmp_path: Path) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    retired = next(custody.glob("retired-*"))
    retired.unlink()
    retired.write_bytes(b"foreign replacement\n")

    with pytest.raises(install_publish.PublishError, match="entry changed"):
        install_publish.discard_custody(custody)

    assert retired.read_bytes() == b"foreign replacement\n"
    assert next(custody.glob("intent-*.json")).is_file()
    assert not (custody / install_publish.CUSTODY_DISCARD_MARKER).exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_stale_discard_marker_is_reconciled_before_retirement_writer(tmp_path: Path) -> None:
    custody = tmp_path / "custody"
    retired = tmp_path / "retired"
    retired.write_bytes(b"attempt-owned\n")
    retired_identity = install_publish.path_identity(retired)
    assert install_publish.unlink_exact(retired, retired_identity, custody_root=custody)
    custody_fd = install_publish._open_custody_root(custody, create=False)
    try:
        install_publish._start_custody_discard(custody_fd)
    finally:
        os.close(custody_fd)

    destination = tmp_path / "new-entry"
    destination.write_bytes(b"preserve\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.unlink_exact(destination, identity, custody_root=custody)

    assert not destination.exists()
    assert next(custody.glob("retired-*")).read_bytes() == b"preserve\n"
    assert len(list(custody.glob("retired-*"))) == 1
    install_publish.discard_custody(custody)
    assert not custody.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
@pytest.mark.parametrize(
    ("crash_prefix", "remaining_intents", "remaining_retired"),
    (("retired-", 2, 1), ("intent-", 1, 0)),
)
def test_discard_custody_resumes_after_crash_during_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_prefix: str,
    remaining_intents: int,
    remaining_retired: int,
) -> None:
    custody = tmp_path / "custody"
    for name in ("first", "second"):
        destination = tmp_path / name
        destination.write_bytes(name.encode())
        identity = install_publish.path_identity(destination)
        assert install_publish.unlink_exact(destination, identity, custody_root=custody)

    real_unlink = install_publish.os.unlink
    crashed = False

    def crash_after_first_retired_unlink(path, *args, **kwargs):
        nonlocal crashed
        real_unlink(path, *args, **kwargs)
        if str(path).startswith(crash_prefix) and not crashed:
            crashed = True
            raise SystemExit("simulated process death during custody discard")

    monkeypatch.setattr(install_publish.os, "unlink", crash_after_first_retired_unlink)
    with pytest.raises(SystemExit):
        install_publish.discard_custody(custody)
    monkeypatch.setattr(install_publish.os, "unlink", real_unlink)

    assert crashed
    assert (custody / install_publish.CUSTODY_DISCARD_MARKER).is_file()
    assert len(list(custody.glob("intent-*.json"))) == remaining_intents
    assert len(list(custody.glob("retired-*"))) == remaining_retired

    install_publish.recover_custody(custody)

    assert not custody.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_discard_custody_resumes_after_crash_between_binding_unlink_and_rmdir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    real_unlink = install_publish.os.unlink
    crashed = False

    def crash_after_binding_unlink(path, *args, **kwargs):
        nonlocal crashed
        real_unlink(path, *args, **kwargs)
        if path == install_publish.CUSTODY_MARKER_NAME and not crashed:
            crashed = True
            raise SystemExit("simulated process death before custody rmdir")

    monkeypatch.setattr(install_publish.os, "unlink", crash_after_binding_unlink)
    with pytest.raises(SystemExit):
        install_publish.discard_custody(custody)
    monkeypatch.setattr(install_publish.os, "unlink", real_unlink)

    close_intent = custody.parent / install_publish._custody_close_name(custody)
    assert crashed
    assert custody.is_dir()
    assert [entry.name for entry in custody.iterdir()] == [install_publish.CUSTODY_DISCARD_MARKER]
    assert close_intent.is_file()

    real_fsync = install_publish.os.fsync
    custody_inode = custody.stat().st_ino
    close_barrier_synced = False

    def record_close_barrier(descriptor):
        nonlocal close_barrier_synced
        real_fsync(descriptor)
        if os.fstat(descriptor).st_ino == custody_inode:
            close_barrier_synced = True

    def crash_before_resumed_discard_unlink(path, *args, **kwargs):
        if path == install_publish.CUSTODY_DISCARD_MARKER:
            assert close_barrier_synced
            raise SystemExit("simulated second death during markerless close")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(install_publish.os, "fsync", record_close_barrier)
    monkeypatch.setattr(install_publish.os, "unlink", crash_before_resumed_discard_unlink)
    with pytest.raises(SystemExit, match="markerless close"):
        install_publish.recover_custody(custody)
    monkeypatch.setattr(install_publish.os, "fsync", real_fsync)
    monkeypatch.setattr(install_publish.os, "unlink", real_unlink)

    assert close_barrier_synced
    assert not (custody / install_publish.CUSTODY_MARKER_NAME).exists()
    assert (custody / install_publish.CUSTODY_DISCARD_MARKER).is_file()
    install_publish.recover_custody(custody)

    assert not custody.exists()
    assert not close_intent.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_retirement_finishes_close_interrupted_between_marker_unlinks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_entry = tmp_path / "old-entry"
    new_entry = tmp_path / "new-entry"
    custody = tmp_path / "custody"
    old_entry.write_bytes(b"old\n")
    new_entry.write_bytes(b"new\n")
    old_identity = install_publish.path_identity(old_entry)
    new_identity = install_publish.path_identity(new_entry)
    assert install_publish.unlink_exact(old_entry, old_identity, custody_root=custody)
    old_custody_identity = install_publish.path_identity(custody)
    real_unlink = install_publish.os.unlink
    real_fsync = install_publish.os.fsync
    crashed = False
    binding_unlinked = False
    binding_unlink_synced = False

    def crash_before_discard_marker_unlink(path, *args, **kwargs):
        nonlocal binding_unlinked, crashed
        if path == install_publish.CUSTODY_DISCARD_MARKER and not crashed:
            assert binding_unlinked
            assert binding_unlink_synced
            crashed = True
            raise SystemExit("simulated process death between custody marker unlinks")
        real_unlink(path, *args, **kwargs)
        if path == install_publish.CUSTODY_MARKER_NAME:
            binding_unlinked = True

    def record_fsync(descriptor):
        nonlocal binding_unlink_synced
        real_fsync(descriptor)
        if binding_unlinked:
            binding_unlink_synced = True

    monkeypatch.setattr(install_publish.os, "unlink", crash_before_discard_marker_unlink)
    monkeypatch.setattr(install_publish.os, "fsync", record_fsync)
    with pytest.raises(SystemExit, match="between custody marker unlinks"):
        install_publish.discard_custody(custody)
    monkeypatch.setattr(install_publish.os, "unlink", real_unlink)
    monkeypatch.setattr(install_publish.os, "fsync", real_fsync)

    close_intent = custody.parent / install_publish._custody_close_name(custody)
    assert not (custody / install_publish.CUSTODY_MARKER_NAME).exists()
    assert (custody / install_publish.CUSTODY_DISCARD_MARKER).is_file()
    assert close_intent.is_file()

    assert install_publish.unlink_exact(new_entry, new_identity, custody_root=custody)

    assert not new_entry.exists()
    assert custody.is_dir()
    assert install_publish.path_identity(custody) != old_custody_identity
    assert (custody / install_publish.CUSTODY_MARKER_NAME).is_file()
    assert not (custody / install_publish.CUSTODY_DISCARD_MARKER).exists()
    assert not close_intent.exists()
    assert next(custody.glob("retired-*")).read_bytes() == b"new\n"


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_cleanup_inspection_ignores_absent_parent(tmp_path: Path) -> None:
    custody = tmp_path / "missing" / "custody"

    assert install_publish.inspect_custody_cleanup(custody) is None


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_prepare_custody_finishes_root_absent_close_before_reinstall(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    old_identity = install_publish.path_identity(custody)
    real_remove_close = install_publish._remove_custody_close_intent

    def crash_before_close_intent_removal(*_args, **_kwargs):
        raise SystemExit("simulated process death after custody rmdir")

    monkeypatch.setattr(install_publish, "_remove_custody_close_intent", crash_before_close_intent_removal)
    with pytest.raises(SystemExit):
        install_publish.discard_custody(custody)
    monkeypatch.setattr(install_publish, "_remove_custody_close_intent", real_remove_close)

    close_intent = custody.parent / install_publish._custody_close_name(custody)
    assert not custody.exists()
    assert close_intent.is_file()

    install_publish.prepare_custody(custody, tmp_path)

    assert custody.is_dir()
    assert install_publish.path_identity(custody) != old_identity
    assert (custody / install_publish.CUSTODY_MARKER_NAME).is_file()
    assert not close_intent.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_discard_marker_write_fault_never_publishes_partial_final_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    install_publish.arm_custody_discard(custody, tmp_path)
    real_write = install_publish.os.write
    faulted = False

    def fail_after_partial_write(descriptor, data):
        nonlocal faulted
        if not faulted:
            faulted = True
            real_write(descriptor, data[:5])
            raise OSError("simulated marker write fault")
        return real_write(descriptor, data)

    monkeypatch.setattr(install_publish.os, "write", fail_after_partial_write)
    with pytest.raises(OSError, match="marker write fault"):
        install_publish.discard_custody(custody)
    monkeypatch.setattr(install_publish.os, "write", real_write)

    assert not (custody / install_publish.CUSTODY_DISCARD_MARKER).exists()
    assert (custody / f"{install_publish.CUSTODY_DISCARD_MARKER}.stage").is_file()
    assert next(custody.glob("retired-*")).read_bytes() == b"attempt-owned\n"

    install_publish.discard_custody(custody)

    assert not custody.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_resumed_discard_syncs_marker_before_retired_unlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    retired = next(custody.glob("retired-*"))
    real_rename = install_publish._rename_no_replace_between
    crashed = False

    def crash_after_discard_marker_rename(source_parent, source, destination_parent, destination_name):
        nonlocal crashed
        real_rename(source_parent, source, destination_parent, destination_name)
        if destination_name == install_publish.CUSTODY_DISCARD_MARKER and not crashed:
            crashed = True
            raise SystemExit("simulated death before discard marker directory sync")

    monkeypatch.setattr(install_publish, "_rename_no_replace_between", crash_after_discard_marker_rename)
    with pytest.raises(SystemExit, match="discard marker directory sync"):
        install_publish.discard_custody(custody)
    monkeypatch.setattr(install_publish, "_rename_no_replace_between", real_rename)

    assert crashed
    assert (custody / install_publish.CUSTODY_DISCARD_MARKER).is_file()
    assert retired.read_bytes() == b"attempt-owned\n"

    real_fsync = install_publish.os.fsync
    real_unlink = install_publish.os.unlink
    custody_inode = custody.stat().st_ino
    discard_barrier_synced = False

    def record_discard_barrier(descriptor):
        nonlocal discard_barrier_synced
        real_fsync(descriptor)
        if os.fstat(descriptor).st_ino == custody_inode:
            discard_barrier_synced = True

    def crash_before_retired_unlink(path, *args, **kwargs):
        if str(path).startswith("retired-"):
            assert discard_barrier_synced
            raise SystemExit("simulated second death before retired unlink")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(install_publish.os, "fsync", record_discard_barrier)
    monkeypatch.setattr(install_publish.os, "unlink", crash_before_retired_unlink)
    with pytest.raises(SystemExit, match="before retired unlink"):
        install_publish.recover_custody(custody)
    monkeypatch.setattr(install_publish.os, "fsync", real_fsync)
    monkeypatch.setattr(install_publish.os, "unlink", real_unlink)

    assert discard_barrier_synced
    assert retired.read_bytes() == b"attempt-owned\n"
    install_publish.recover_custody(custody)
    assert not custody.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_close_intent_write_fault_is_recoverable_before_retirement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    custody = tmp_path / "custody"
    install_publish.prepare_custody(custody, tmp_path)
    real_write = install_publish.os.write
    faulted = False

    def fail_after_partial_write(descriptor, data):
        nonlocal faulted
        if not faulted:
            faulted = True
            real_write(descriptor, data[:5])
            raise OSError("simulated close-intent write fault")
        return real_write(descriptor, data)

    monkeypatch.setattr(install_publish.os, "write", fail_after_partial_write)
    with pytest.raises(OSError, match="close-intent write fault"):
        install_publish.arm_custody_discard(custody, tmp_path)
    monkeypatch.setattr(install_publish.os, "write", real_write)

    close_name = install_publish._custody_close_name(custody)
    assert not (custody.parent / close_name).exists()
    assert (custody.parent / f"{close_name}.stage").is_file()

    install_publish.arm_custody_discard(custody, tmp_path)
    install_publish.discard_custody(custody)

    assert not custody.exists()
    assert not (custody.parent / close_name).exists()
    assert not (custody.parent / f"{close_name}.stage").exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_binding_marker_write_fault_never_publishes_partial_final_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    custody = tmp_path / "custody"
    real_write = install_publish.os.write
    faulted = False

    def fail_after_partial_write(descriptor, data):
        nonlocal faulted
        if not faulted:
            faulted = True
            real_write(descriptor, data[:5])
            raise OSError("simulated binding-marker write fault")
        return real_write(descriptor, data)

    monkeypatch.setattr(install_publish.os, "write", fail_after_partial_write)
    with pytest.raises(OSError, match="binding-marker write fault"):
        install_publish.prepare_custody(custody, tmp_path)
    monkeypatch.setattr(install_publish.os, "write", real_write)

    assert not (custody / install_publish.CUSTODY_MARKER_NAME).exists()
    assert (custody / f"{install_publish.CUSTODY_MARKER_NAME}.stage").is_file()

    install_publish.prepare_custody(custody, tmp_path)

    assert (custody / install_publish.CUSTODY_MARKER_NAME).read_bytes() == install_publish.CUSTODY_MARKER
    assert not (custody / f"{install_publish.CUSTODY_MARKER_NAME}.stage").exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_binding_marker_retry_clears_stage_when_final_already_exists(tmp_path: Path) -> None:
    custody = tmp_path / "custody"
    install_publish.prepare_custody(custody, tmp_path)
    stage = custody / f"{install_publish.CUSTODY_MARKER_NAME}.stage"
    stage.write_bytes(b"partial")
    stage.chmod(0o600)

    install_publish.prepare_custody(custody, tmp_path)

    assert (custody / install_publish.CUSTODY_MARKER_NAME).read_bytes() == install_publish.CUSTODY_MARKER
    assert not stage.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_retirement_intent_write_fault_never_publishes_partial_final_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    install_publish.prepare_custody(custody, tmp_path)
    real_write = install_publish.os.write
    faulted = False

    def fail_after_partial_write(descriptor, data):
        nonlocal faulted
        if not faulted:
            faulted = True
            real_write(descriptor, data[:5])
            raise OSError("simulated retirement-intent write fault")
        return real_write(descriptor, data)

    monkeypatch.setattr(install_publish.os, "write", fail_after_partial_write)
    with pytest.raises(OSError, match="retirement-intent write fault"):
        install_publish.unlink_exact(destination, identity, custody_root=custody)
    monkeypatch.setattr(install_publish.os, "write", real_write)

    assert destination.read_bytes() == b"attempt-owned\n"
    assert not list(custody.glob("intent-*.json"))
    assert len(list(custody.glob("intent-*.json.stage"))) == 1

    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    install_publish.discard_custody(custody)

    assert not destination.exists()
    assert not custody.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_retirement_intent_retry_clears_stage_when_final_already_exists(tmp_path: Path) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    intent = next(custody.glob("intent-*.json"))
    stage = intent.with_name(f"{intent.name}.stage")
    stage.write_bytes(b"partial")
    stage.chmod(0o600)

    assert install_publish.unlink_exact(destination, identity, custody_root=custody)

    assert not stage.exists()
    install_publish.discard_custody(custody)
    assert not custody.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_discard_lock_excludes_retirement_after_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_entry = tmp_path / "old-entry"
    new_entry = tmp_path / "new-entry"
    custody = tmp_path / "custody"
    old_entry.write_bytes(b"old\n")
    new_entry.write_bytes(b"new\n")
    old_identity = install_publish.path_identity(old_entry)
    new_identity = install_publish.path_identity(new_entry)
    assert install_publish.unlink_exact(old_entry, old_identity, custody_root=custody)

    discard_started = threading.Event()
    release_discard = threading.Event()
    retirement_entered = threading.Event()
    real_start = install_publish._start_custody_discard
    real_retire = install_publish._retire_exact_at

    def pause_after_preflight(custody_fd: int) -> None:
        real_start(custody_fd)
        discard_started.set()
        if not release_discard.wait(5):
            raise AssertionError("test did not release discard")

    def record_retirement(*args, **kwargs):
        retirement_entered.set()
        return real_retire(*args, **kwargs)

    monkeypatch.setattr(install_publish, "_start_custody_discard", pause_after_preflight)
    monkeypatch.setattr(install_publish, "_retire_exact_at", record_retirement)
    discard_errors: list[BaseException] = []
    retirement_errors: list[BaseException] = []

    def run_discard() -> None:
        try:
            install_publish.discard_custody(custody)
        except BaseException as exc:  # pragma: no cover - asserted below
            discard_errors.append(exc)

    def run_retirement() -> None:
        try:
            install_publish.unlink_exact(new_entry, new_identity, custody_root=custody)
        except BaseException as exc:
            retirement_errors.append(exc)

    discard_thread = threading.Thread(target=run_discard)
    retirement_thread = threading.Thread(target=run_retirement)
    discard_thread.start()
    assert discard_started.wait(5)
    retirement_thread.start()

    assert not retirement_entered.wait(0.2)
    assert new_entry.read_bytes() == b"new\n"
    release_discard.set()
    discard_thread.join(5)
    retirement_thread.join(5)

    assert not discard_thread.is_alive()
    assert not retirement_thread.is_alive()
    assert not discard_errors
    assert not retirement_errors
    assert retirement_entered.is_set()
    assert not new_entry.exists()
    assert next(custody.glob("retired-*")).read_bytes() == b"new\n"


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_retirement_syncs_destination_custody_before_source_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    real_rename = install_publish._rename_no_replace_between
    real_fsync = install_publish.os.fsync
    renamed = False
    sync_order: list[int] = []

    def record_rename(source_parent, source, destination_parent, destination_name):
        nonlocal renamed
        real_rename(source_parent, source, destination_parent, destination_name)
        if source == destination.name and destination_name.startswith("retired-"):
            renamed = True

    def record_fsync(descriptor):
        real_fsync(descriptor)
        if renamed:
            sync_order.append(os.fstat(descriptor).st_ino)

    monkeypatch.setattr(install_publish, "_rename_no_replace_between", record_rename)
    monkeypatch.setattr(install_publish.os, "fsync", record_fsync)

    assert install_publish.unlink_exact(destination, identity, custody_root=custody)

    assert sync_order[:2] == [custody.stat().st_ino, tmp_path.stat().st_ino]


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_substitution_restore_syncs_destination_parent_before_source_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    retired = next(custody.glob("retired-*"))
    retired.rename(custody / "owned-preserved")
    retired.write_bytes(b"foreign substitution\n")
    real_rename = install_publish._rename_no_replace_between
    real_fsync = install_publish.os.fsync
    restored = False
    sync_order: list[int] = []

    def record_rename(source_parent, source, destination_parent, destination_name):
        nonlocal restored
        real_rename(source_parent, source, destination_parent, destination_name)
        if source == retired.name and destination_name == destination.name:
            restored = True

    def record_fsync(descriptor):
        real_fsync(descriptor)
        if restored:
            sync_order.append(os.fstat(descriptor).st_ino)

    monkeypatch.setattr(install_publish, "_rename_no_replace_between", record_rename)
    monkeypatch.setattr(install_publish.os, "fsync", record_fsync)

    with pytest.raises(install_publish.PublishError, match="unresolved state"):
        install_publish.recover_custody(custody)

    assert destination.read_bytes() == b"foreign substitution\n"
    assert sync_order[:2] == [tmp_path.stat().st_ino, custody.stat().st_ino]


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_recovery_converges_duplicate_canonical_and_retired_hardlinks(tmp_path: Path) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    retired = next(custody.glob("retired-*"))
    os.link(retired, destination)

    assert install_publish.path_identity(destination) == identity
    assert install_publish.path_identity(retired) == identity

    install_publish.recover_custody(custody)

    assert not destination.exists()
    assert retired.read_bytes() == b"attempt-owned\n"
    assert not list(custody.glob("duplicate-*"))


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_recovery_restores_foreign_duplicate_staging(tmp_path: Path) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    retired = next(custody.glob("retired-*"))
    duplicate = custody / install_publish._retirement_duplicate_name(retired.name)
    duplicate.write_bytes(b"foreign substitution\n")

    with pytest.raises(install_publish.PublishError, match="unresolved state"):
        install_publish.recover_custody(custody)

    assert destination.read_bytes() == b"foreign substitution\n"
    assert install_publish.path_identity(retired) == identity
    assert not duplicate.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_discard_resume_converges_duplicate_staging(tmp_path: Path) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    retired = next(custody.glob("retired-*"))
    duplicate = custody / install_publish._retirement_duplicate_name(retired.name)
    os.link(retired, destination)
    os.link(retired, duplicate)
    install_publish.arm_custody_discard(custody, tmp_path)
    custody_fd = install_publish._open_custody_root(custody, create=False)
    try:
        install_publish._start_custody_discard(custody_fd)
    finally:
        os.close(custody_fd)

    assert install_publish.custody_discard_pending(custody)
    install_publish.recover_custody(custody)

    assert not destination.exists()
    assert not custody.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
@pytest.mark.parametrize("retired_present", [True, False])
def test_discard_resume_converges_duplicate_when_canonical_parent_is_missing(
    tmp_path: Path,
    retired_present: bool,
) -> None:
    managed_parent = tmp_path / "managed"
    managed_parent.mkdir()
    destination = managed_parent / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    retired = next(custody.glob("retired-*"))
    duplicate = custody / install_publish._retirement_duplicate_name(retired.name)
    if retired_present:
        os.link(retired, duplicate)
    else:
        retired.rename(duplicate)
    managed_parent.rmdir()
    install_publish.arm_custody_discard(custody, tmp_path)
    custody_fd = install_publish._open_custody_root(custody, create=False)
    try:
        install_publish._start_custody_discard(custody_fd)
    finally:
        os.close(custody_fd)

    install_publish.recover_custody(custody)

    assert not custody.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_discard_resume_preserves_foreign_canonical_after_retired_deletion(tmp_path: Path) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    retired = next(custody.glob("retired-*"))
    install_publish.arm_custody_discard(custody, tmp_path)
    custody_fd = install_publish._open_custody_root(custody, create=False)
    try:
        install_publish._start_custody_discard(custody_fd)
        os.unlink(retired.name, dir_fd=custody_fd)
        os.fsync(custody_fd)
    finally:
        os.close(custody_fd)
    destination.write_bytes(b"foreign replacement\n")

    install_publish.recover_custody(custody)

    assert destination.read_bytes() == b"foreign replacement\n"
    assert not custody.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_discard_resume_retires_exact_canonical_after_source_name_replay(tmp_path: Path) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    retired = next(custody.glob("retired-*"))
    install_publish.arm_custody_discard(custody, tmp_path)
    custody_fd = install_publish._open_custody_root(custody, create=False)
    try:
        install_publish._start_custody_discard(custody_fd)
    finally:
        os.close(custody_fd)
    retired.rename(destination)

    assert install_publish.path_identity(destination) == identity
    install_publish.recover_custody(custody)

    assert not destination.exists()
    assert not custody.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_parent_lock_blocks_binding_recreation_during_root_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_entry = tmp_path / "old-entry"
    new_entry = tmp_path / "new-entry"
    custody = tmp_path / "custody"
    old_entry.write_bytes(b"old\n")
    new_entry.write_bytes(b"new\n")
    old_identity = install_publish.path_identity(old_entry)
    new_identity = install_publish.path_identity(new_entry)
    assert install_publish.unlink_exact(old_entry, old_identity, custody_root=custody)

    markers_removed = threading.Event()
    release_close = threading.Event()
    retirement_entered = threading.Event()
    real_rmdir = install_publish.os.rmdir
    real_retire = install_publish._retire_exact_at
    paused = False

    def pause_before_root_rmdir(path, *args, **kwargs):
        nonlocal paused
        if path == custody.name and not paused:
            paused = True
            markers_removed.set()
            if not release_close.wait(5):
                raise AssertionError("test did not release custody close")
        return real_rmdir(path, *args, **kwargs)

    def record_retirement(*args, **kwargs):
        retirement_entered.set()
        return real_retire(*args, **kwargs)

    monkeypatch.setattr(install_publish.os, "rmdir", pause_before_root_rmdir)
    monkeypatch.setattr(install_publish, "_retire_exact_at", record_retirement)
    discard_errors: list[BaseException] = []
    retirement_errors: list[BaseException] = []

    def run_discard() -> None:
        try:
            install_publish.discard_custody(custody)
        except BaseException as exc:  # pragma: no cover - asserted below
            discard_errors.append(exc)

    def run_retirement() -> None:
        try:
            install_publish.unlink_exact(new_entry, new_identity, custody_root=custody)
        except BaseException as exc:  # pragma: no cover - asserted below
            retirement_errors.append(exc)

    discard_thread = threading.Thread(target=run_discard)
    retirement_thread = threading.Thread(target=run_retirement)
    discard_thread.start()
    assert markers_removed.wait(5)
    assert list(custody.iterdir()) == []
    retirement_thread.start()

    assert not retirement_entered.wait(0.2)
    assert list(custody.iterdir()) == []
    release_close.set()
    discard_thread.join(5)
    retirement_thread.join(5)

    assert not discard_thread.is_alive()
    assert not retirement_thread.is_alive()
    assert not discard_errors
    assert not retirement_errors
    assert retirement_entered.is_set()
    assert not new_entry.exists()
    assert next(custody.glob("retired-*")).read_bytes() == b"new\n"


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
@pytest.mark.parametrize("verb", ["unlink", "rmdir", "remove-tree"])
def test_public_retirement_reconciles_root_absent_close_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    verb: str,
) -> None:
    old_entry = tmp_path / "old-entry"
    custody = tmp_path / "custody"
    old_entry.write_bytes(b"old\n")
    old_identity = install_publish.path_identity(old_entry)
    assert install_publish.unlink_exact(old_entry, old_identity, custody_root=custody)
    real_remove_close = install_publish._remove_custody_close_intent

    def crash_after_root_rmdir(*_args, **_kwargs):
        raise SystemExit("simulated process death before close-intent removal")

    monkeypatch.setattr(install_publish, "_remove_custody_close_intent", crash_after_root_rmdir)
    with pytest.raises(SystemExit, match="close-intent removal"):
        install_publish.discard_custody(custody)
    monkeypatch.setattr(install_publish, "_remove_custody_close_intent", real_remove_close)

    close_intent = custody.parent / install_publish._custody_close_name(custody)
    assert not custody.exists()
    assert close_intent.is_file()

    destination = tmp_path / f"new-{verb}"
    if verb == "unlink":
        destination.write_bytes(b"new\n")
        identity = install_publish.path_identity(destination)
        assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    elif verb == "rmdir":
        destination.mkdir()
        identity = install_publish.path_identity(destination)
        assert install_publish.rmdir_exact(destination, identity, custody_root=custody)
    else:
        destination.mkdir()
        (destination / "state").write_bytes(b"new\n")
        identity = install_publish.path_identity(destination)
        assert install_publish.remove_tree_exact(destination, identity, custody_root=custody)

    assert not destination.exists()
    assert custody.is_dir()
    assert not close_intent.exists()
    install_publish.arm_custody_discard(custody, tmp_path)
    if verb == "remove-tree":
        with pytest.raises(install_publish.PublishError, match="directory tree"):
            install_publish.discard_custody(custody)
    else:
        install_publish.discard_custody(custody)
        assert not custody.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_internal_unlink_fallback_reconciles_root_absent_close_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    custody = tmp_path / ".defenseclaw-install-custody"
    old_entry = tmp_path / "old-entry"
    old_entry.write_bytes(b"old\n")
    old_identity = install_publish.path_identity(old_entry)
    assert install_publish.unlink_exact(old_entry, old_identity, custody_root=custody)
    real_remove_close = install_publish._remove_custody_close_intent

    def crash_after_root_rmdir(*_args, **_kwargs):
        raise SystemExit("simulated process death before close-intent removal")

    monkeypatch.setattr(install_publish, "_remove_custody_close_intent", crash_after_root_rmdir)
    with pytest.raises(SystemExit, match="close-intent removal"):
        install_publish.discard_custody(custody)
    monkeypatch.setattr(install_publish, "_remove_custody_close_intent", real_remove_close)

    destination = tmp_path / "entry"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    parent_fd = install_publish._open_directory(tmp_path, create=False)
    try:
        assert install_publish._unlink_exact_at(
            parent_fd,
            destination.name,
            identity,
            canonical=str(destination),
        )
    finally:
        os.close(parent_fd)

    assert not destination.exists()
    assert next(custody.glob("retired-*")).read_bytes() == b"attempt-owned\n"
    assert not (custody.parent / install_publish._custody_close_name(custody)).exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_discard_custody_removes_proven_empty_directory(tmp_path: Path) -> None:
    destination = tmp_path / "attempt-created"
    custody = tmp_path / "custody"
    destination.mkdir()
    identity = install_publish.path_identity(destination)

    assert install_publish.rmdir_exact(destination, identity, custody_root=custody)
    install_publish.discard_custody(custody)

    assert not destination.exists()
    assert not custody.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_discard_custody_preserves_retired_directory_tree(tmp_path: Path) -> None:
    destination = tmp_path / "managed-tree"
    custody = tmp_path / "custody"
    destination.mkdir()
    (destination / "state").write_bytes(b"preserve\n")
    identity = install_publish.path_identity(destination)
    assert install_publish.remove_tree_exact(destination, identity, custody_root=custody)
    retired = next(custody.glob("retired-*"))

    with pytest.raises(install_publish.PublishError, match="directory tree"):
        install_publish.discard_custody(custody)

    assert (retired / "state").read_bytes() == b"preserve\n"
    assert next(custody.glob("intent-*.json")).is_file()
    assert not (custody / install_publish.CUSTODY_DISCARD_MARKER).exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_retirement_recovery_wraps_non_object_intent(tmp_path: Path) -> None:
    custody = tmp_path / "custody"
    install_publish.prepare_custody(custody, tmp_path)
    (custody / "intent-invalid.json").write_text("[]\n", encoding="utf-8")

    with pytest.raises(install_publish.PublishError, match="invalid intent"):
        install_publish.recover_custody(custody)


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_retirement_recovery_rejects_boolean_birth_identity(tmp_path: Path) -> None:
    custody = tmp_path / "custody"
    install_publish.prepare_custody(custody, tmp_path)
    canonical = tmp_path / "entry"
    identity = (1, 2, 3, True)
    intent, _retired = install_publish._retirement_names(str(canonical), identity, "entry")
    document = install_publish._retirement_document(str(canonical), identity, "entry")
    (custody / intent).write_bytes(document)

    with pytest.raises(install_publish.PublishError, match="invalid intent"):
        install_publish.recover_custody(custody)


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_retirement_restores_foreign_substitution_moved_during_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "entry"
    custody = tmp_path / "custody"
    displaced_owned = tmp_path / "owned-away"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    real_rename = install_publish._rename_no_replace_between
    substituted = False

    def substitute_before_rename(
        source_parent: int,
        source: str,
        destination_parent: int,
        retired: str,
    ) -> None:
        nonlocal substituted
        if source == destination.name and not substituted:
            substituted = True
            os.rename(destination, displaced_owned)
            destination.write_bytes(b"foreign\n")
        real_rename(source_parent, source, destination_parent, retired)

    monkeypatch.setattr(install_publish, "_rename_no_replace_between", substitute_before_rename)

    assert not install_publish.unlink_exact(destination, identity, custody_root=custody)
    assert destination.read_bytes() == b"foreign\n"
    assert displaced_owned.read_bytes() == b"attempt-owned\n"
    assert not list(custody.glob("retired-*"))


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_retirement_refuses_when_claim_moves_away_before_custody_rename(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "entry"
    moved_away = tmp_path / "owned-away"
    custody = tmp_path / "custody"
    destination.write_bytes(b"attempt-owned\n")
    identity = install_publish.path_identity(destination)
    real_rename = install_publish._rename_no_replace_between
    moved = False

    def move_claim_before_retirement(
        source_parent: int,
        source: str,
        destination_parent: int,
        retired: str,
    ) -> None:
        nonlocal moved
        if source == destination.name and not moved:
            moved = True
            os.rename(destination, moved_away)
        real_rename(source_parent, source, destination_parent, retired)

    monkeypatch.setattr(
        install_publish,
        "_rename_no_replace_between",
        move_claim_before_retirement,
    )

    assert not install_publish.unlink_exact(destination, identity, custody_root=custody)
    assert install_publish.path_identity(moved_away) == identity
    assert moved_away.read_bytes() == b"attempt-owned\n"
    assert len(list(custody.glob("intent-*.json"))) == 1
    assert not list(custody.glob("retired-*"))
    with pytest.raises(
        install_publish.PublishError,
        match="retirement recovery preserved unresolved state",
    ):
        install_publish.recover_custody(custody)


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_tree_retirement_recovery_converges_after_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tree = tmp_path / "venv"
    custody = tmp_path / "custody"
    identity = install_publish.fresh_directory(tree)
    (tree / "state").write_bytes(b"attempt-owned\n")
    real_rename = install_publish._rename_no_replace_between
    crashed = False

    def crash_after_rename(
        source_parent: int,
        source: str,
        destination_parent: int,
        retired: str,
    ) -> None:
        nonlocal crashed
        real_rename(source_parent, source, destination_parent, retired)
        if source == tree.name and not crashed:
            crashed = True
            raise SystemExit("simulated tree retirement crash")

    monkeypatch.setattr(install_publish, "_rename_no_replace_between", crash_after_rename)
    with pytest.raises(SystemExit):
        install_publish.remove_tree_exact(tree, identity, custody_root=custody)
    monkeypatch.setattr(install_publish, "_rename_no_replace_between", real_rename)

    install_publish.recover_custody(custody)
    assert not tree.exists()
    retired = next(custody.glob("retired-*"))
    assert (retired / "state").read_bytes() == b"attempt-owned\n"


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or os.environ.get("INSTALL_PUBLISH_BIND_TEST") != "1",
    reason="native bind-mount regression requires an isolated privileged Linux runner",
)
def test_tree_retirement_refuses_same_device_bind_mount(tmp_path: Path) -> None:
    mount = shutil.which("mount")
    umount = shutil.which("umount")
    if mount is None or umount is None or os.geteuid() != 0:
        pytest.skip("bind mount tools or isolated root are unavailable")
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_bytes(b"preserve\n")
    tree = tmp_path / "venv"
    identity = install_publish.fresh_directory(tree)
    mounted = tree / "mounted"
    mounted.mkdir()
    subprocess.run([mount, "--bind", str(outside), str(mounted)], check=True)
    try:
        assert mounted.stat().st_dev == tree.stat().st_dev
        with pytest.raises(install_publish.PublishError, match="mount boundary"):
            install_publish.remove_tree_exact(
                tree,
                identity,
                custody_root=tmp_path / "custody",
            )
        assert sentinel.read_bytes() == b"preserve\n"
        assert tree.is_dir()
    finally:
        subprocess.run([umount, str(mounted)], check=True)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="cross-filesystem fixture is Linux-only")
def test_exact_retirement_cross_filesystem_fails_closed(tmp_path: Path) -> None:
    shared_memory = Path("/dev/shm")
    if not shared_memory.is_dir() or shared_memory.stat().st_dev == tmp_path.stat().st_dev:
        pytest.skip("no distinct temporary filesystem is available")
    destination = tmp_path / "entry"
    destination.write_bytes(b"preserve\n")
    identity = install_publish.path_identity(destination)
    custody = Path(tempfile.mkdtemp(prefix="defenseclaw-custody-", dir=shared_memory))
    try:
        with pytest.raises(install_publish.PublishError, match="filesystem"):
            install_publish.unlink_exact(destination, identity, custody_root=custody)
        assert destination.read_bytes() == b"preserve\n"
    finally:
        shutil.rmtree(custody)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="cross-filesystem fixture is Linux-only")
def test_custody_preflight_refuses_cross_filesystem_before_publication(tmp_path: Path) -> None:
    shared_memory = Path("/dev/shm")
    if not shared_memory.is_dir() or shared_memory.stat().st_dev == tmp_path.stat().st_dev:
        pytest.skip("no distinct temporary filesystem is available")
    custody = Path(tempfile.mkdtemp(prefix="defenseclaw-preflight-", dir=shared_memory))
    not_published = tmp_path / "managed-parent" / "payload"
    managed_parent = not_published.parent
    managed_parent.mkdir()
    try:
        with pytest.raises(install_publish.PublishError, match="share the managed object's mount"):
            install_publish.prepare_custody(custody, managed_parent)
        assert not not_published.exists()
    finally:
        shutil.rmtree(custody)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="cross-filesystem fixture is Linux-only")
def test_custom_state_retirement_uses_custody_on_its_own_filesystem(tmp_path: Path) -> None:
    shared_memory = Path("/dev/shm")
    if not shared_memory.is_dir() or shared_memory.stat().st_dev == tmp_path.stat().st_dev:
        pytest.skip("no distinct temporary filesystem is available")
    state_parent = Path(tempfile.mkdtemp(prefix="defenseclaw-state-", dir=shared_memory))
    destination = state_parent / ".defenseclaw"
    custody = state_parent / ".defenseclaw-install-custody"
    try:
        install_publish.prepare_custody(custody, state_parent)
        destination.write_bytes(b"attempt-owned state\n")
        identity = install_publish.path_identity(destination)

        assert install_publish.unlink_exact(destination, identity, custody_root=custody)
        assert not destination.exists()
        assert next(custody.glob("retired-*")).read_bytes() == b"attempt-owned state\n"
    finally:
        shutil.rmtree(state_parent)


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_exact_retirement_refuses_precreated_unbound_custody(tmp_path: Path) -> None:
    destination = tmp_path / "entry"
    destination.write_bytes(b"preserve\n")
    identity = install_publish.path_identity(destination)
    custody = tmp_path / "custody"
    custody.mkdir(mode=0o700)
    planted = custody / "foreign"
    planted.write_bytes(b"preserve\n")

    with pytest.raises(install_publish.PublishError, match="not empty"):
        install_publish.unlink_exact(destination, identity, custody_root=custody)

    assert destination.read_bytes() == b"preserve\n"
    assert planted.read_bytes() == b"preserve\n"
    assert not (custody / ".defenseclaw-custody-v1").exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_exact_retirement_custody_entry_count_is_bounded(tmp_path: Path) -> None:
    destination = tmp_path / "entry"
    destination.write_bytes(b"preserve\n")
    identity = install_publish.path_identity(destination)
    custody = tmp_path / "custody"
    custody_fd = install_publish._open_custody_root(custody, create=True)
    os.close(custody_fd)
    for index in range(install_publish.MAX_CUSTODY_ENTRIES - 4):
        (custody / f"retained-{index:03d}").write_bytes(b"retained\n")

    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    assert not destination.exists()
    assert len(list(custody.iterdir())) == install_publish.MAX_CUSTODY_ENTRIES - 1

    second = tmp_path / "second-entry"
    second.write_bytes(b"preserve\n")
    second_identity = install_publish.path_identity(second)
    with pytest.raises(install_publish.PublishError, match="bounded entry limit"):
        install_publish.unlink_exact(second, second_identity, custody_root=custody)

    assert second.read_bytes() == b"preserve\n"
    assert len(list(custody.iterdir())) == install_publish.MAX_CUSTODY_ENTRIES - 1
    assert len(list(custody.glob("intent-*.json"))) == 1
    assert len(list(custody.glob("retired-*"))) == 1
