# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

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


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_source_preflight_publication_verbs_are_directly_executable(tmp_path: Path) -> None:
    install_dir = tmp_path / "home/.local/bin"
    reserved = _run("ensure-directory", install_dir)
    assert reserved.returncode == 0, reserved.stderr
    assert install_dir.is_dir() and not install_dir.is_symlink()

    cli = install_dir / "defenseclaw"
    target = str(tmp_path / "checkout/.venv/bin/defenseclaw")
    linked = _run("symlink", target, cli)
    assert linked.returncode == 0, linked.stderr
    assert cli.is_symlink() and os.readlink(cli) == target

    source = tmp_path / "checkout/defenseclaw-gateway"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"new gateway\n")
    source.chmod(0o755)
    destination = install_dir / "defenseclaw-gateway"
    destination.write_bytes(b"old gateway\n")
    destination.chmod(0o755)
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    current_digest = hashlib.sha256(destination.read_bytes()).hexdigest()

    published = _run(
        "regular",
        source,
        destination,
        "--expected-source-sha256",
        source_digest,
        "--expected-current-sha256",
        current_digest,
    )

    assert published.returncode == 0, published.stderr
    assert destination.read_bytes() == b"new gateway\n"
    assert not list(install_dir.glob(".defenseclaw-gateway.source-install-*"))


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
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
    for index in range(install_publish.MAX_CUSTODY_ENTRIES - 3):
        (custody / f"retained-{index:03d}").write_bytes(b"retained\n")

    assert install_publish.unlink_exact(destination, identity, custody_root=custody)
    assert not destination.exists()
    assert len(list(custody.iterdir())) == install_publish.MAX_CUSTODY_ENTRIES

    second = tmp_path / "second-entry"
    second.write_bytes(b"preserve\n")
    second_identity = install_publish.path_identity(second)
    with pytest.raises(install_publish.PublishError, match="bounded entry limit"):
        install_publish.unlink_exact(second, second_identity, custody_root=custody)

    assert second.read_bytes() == b"preserve\n"
    assert len(list(custody.iterdir())) == install_publish.MAX_CUSTODY_ENTRIES
    assert len(list(custody.glob("intent-*.json"))) == 1
    assert len(list(custody.glob("retired-*"))) == 1
