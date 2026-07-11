# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import os
import subprocess
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
    published = _run("fresh-regular", source, destination, "--retain-token")
    assert published.returncode == 0, published.stderr
    token = published.stdout.strip()
    assert token
    assert destination.read_bytes() == b"gateway\n"
    assert len(list(install_dir.iterdir())) == 2

    committed = _run("commit-token", token)
    assert committed.returncode == 0, committed.stderr
    assert destination.read_bytes() == b"gateway\n"
    assert list(install_dir.iterdir()) == [destination]

    destination.unlink()
    published = _run("fresh-regular", source, destination, "--retain-token")
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
    published = _run("fresh-regular", source, destination, "--retain-token")
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
    assert published.returncode == 0, published.stderr
    device, inode = (int(value) for value in published.stdout.strip().split(":"))
    observed = os.lstat(fresh_destination)
    assert (device, inode) == (observed.st_dev, observed.st_ino)


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_unlink_exact_preserves_replacement_and_removes_exact_inode(tmp_path: Path) -> None:
    destination = tmp_path / "entry"
    destination.write_bytes(b"original\n")
    original = os.lstat(destination)
    destination.unlink()
    destination.write_bytes(b"replacement\n")

    refused = _run("unlink-exact", destination, original.st_dev, original.st_ino)
    assert refused.returncode != 0
    assert destination.read_bytes() == b"replacement\n"

    replacement = os.lstat(destination)
    removed = _run("unlink-exact", destination, replacement.st_dev, replacement.st_ino)
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

        def fail_staged_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> int:
            if dir_fd is not None and ".install-directory-" in os.fsdecode(path):
                raise OSError("injected staged-directory open failure")
            return real_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(install_publish.os, "open", fail_staged_open)
    else:
        def fail_staged_identity(_descriptor: int) -> tuple[int, int]:
            raise OSError("injected staged-directory identity failure")

        monkeypatch.setattr(install_publish, "_identity", fail_staged_identity)

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

    def replace_before_identity(_descriptor: int) -> tuple[int, int]:
        nonlocal replacement
        staged = next(tmp_path.glob(".managed.install-directory-*"))
        staged.rmdir()
        staged.mkdir()
        replacement = staged / "foreign-sentinel"
        replacement.write_text("preserve", encoding="utf-8")
        raise OSError("injected identity failure after concurrent replacement")

    monkeypatch.setattr(install_publish, "_identity", replace_before_identity)

    with pytest.raises(install_publish.PublishError, match="appeared concurrently"):
        install_publish.ensure_directory(destination)

    assert replacement is not None
    assert replacement.read_text(encoding="utf-8") == "preserve"
    assert not destination.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_fresh_directory_identity_supports_exact_empty_rollback(tmp_path: Path) -> None:
    destination = tmp_path / "claimed"
    claimed = _run("fresh-directory", destination)
    assert claimed.returncode == 0, claimed.stderr
    device, inode = (int(value) for value in claimed.stdout.strip().split(":"))
    observed = os.lstat(destination)
    assert (device, inode) == (observed.st_dev, observed.st_ino)

    duplicate = _run("fresh-directory", destination)
    assert duplicate.returncode != 0
    assert destination.is_dir()

    removed = _run("rmdir-exact", destination, device, inode)
    assert removed.returncode == 0, removed.stderr
    assert not destination.exists()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_rmdir_exact_preserves_nonempty_or_replaced_directory(tmp_path: Path) -> None:
    destination = tmp_path / "claimed"
    claimed = _run("fresh-directory", destination)
    assert claimed.returncode == 0, claimed.stderr
    device, inode = (int(value) for value in claimed.stdout.strip().split(":"))
    keep = destination / "keep"
    keep.write_text("state", encoding="utf-8")

    nonempty = _run("rmdir-exact", destination, device, inode)
    assert nonempty.returncode != 0
    assert keep.read_text(encoding="utf-8") == "state"

    keep.unlink()
    destination.rmdir()
    destination.mkdir()
    replacement = destination / "replacement"
    replacement.write_text("preserve", encoding="utf-8")
    replaced = _run("rmdir-exact", destination, device, inode)
    assert replaced.returncode != 0
    assert replacement.read_text(encoding="utf-8") == "preserve"


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_remove_tree_exact_is_bounded_and_never_follows_symlinks(tmp_path: Path) -> None:
    destination = tmp_path / "venv"
    claimed = _run("fresh-directory", destination)
    assert claimed.returncode == 0, claimed.stderr
    device, inode = (int(value) for value in claimed.stdout.strip().split(":"))
    package = destination / "lib/python/site-packages/example"
    package.mkdir(parents=True)
    (package / "module.py").write_text("value = 1\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("preserve", encoding="utf-8")
    (destination / "outside-link").symlink_to(outside, target_is_directory=True)

    removed = _run("remove-tree-exact", destination, device, inode)

    assert removed.returncode == 0, removed.stderr
    assert not destination.exists()
    assert sentinel.read_text(encoding="utf-8") == "preserve"

    deep = tmp_path / "deep-venv"
    claimed = _run("fresh-directory", deep)
    assert claimed.returncode == 0, claimed.stderr
    device, inode = (int(value) for value in claimed.stdout.strip().split(":"))
    current = deep
    for _index in range(66):
        current = current / "d"
        current.mkdir()

    refused = _run("remove-tree-exact", deep, device, inode)

    assert refused.returncode != 0
    assert "depth bound" in refused.stderr
    assert deep.is_dir()
    assert current.is_dir()


@pytest.mark.skipif(os.name == "nt", reason="descriptor-bound publisher is POSIX-only")
def test_remove_tree_exact_preserves_replacement(tmp_path: Path) -> None:
    destination = tmp_path / "venv"
    claimed = _run("fresh-directory", destination)
    assert claimed.returncode == 0, claimed.stderr
    device, inode = (int(value) for value in claimed.stdout.strip().split(":"))
    destination.rmdir()
    destination.mkdir()
    sentinel = destination / "concurrent"
    sentinel.write_text("preserve", encoding="utf-8")

    refused = _run("remove-tree-exact", destination, device, inode)

    assert refused.returncode != 0
    assert sentinel.read_text(encoding="utf-8") == "preserve"
