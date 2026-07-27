# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import runpy
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts import download_release_custody

pytestmark = pytest.mark.skipif(
    os.name != "posix" or not hasattr(os, "O_NOFOLLOW"),
    reason="release custody downloads require POSIX O_NOFOLLOW semantics",
)


def _asset_rows() -> list[dict[str, object]]:
    return [
        {"name": name, "id": index}
        for index, name in enumerate(download_release_custody.REQUIRED_PROOF_ASSETS, start=101)
    ]


def _write_release(path: Path, assets: object) -> None:
    path.write_text(json.dumps({"assets": assets}), encoding="utf-8")


def _successful_runner(calls: list[tuple[list[str], dict[str, Any]]]):
    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append((command, kwargs))
        kwargs["stdout"].write(f"proof:{command[-1]}\n".encode())
        return subprocess.CompletedProcess(command, 0, stdout=None, stderr=b"")

    return run


def test_download_size_bounds_match_repair_verifier_contract() -> None:
    verifier = runpy.run_path(
        str(Path(download_release_custody.__file__).with_name("verify-release-channel-target.py"))
    )

    assert download_release_custody.MAX_PROOF_BYTES == verifier["MAX_PROOF_BYTES"]


def test_downloads_exact_required_assets_by_positive_id_with_bounded_calls(tmp_path: Path) -> None:
    release_json = tmp_path / "published-release.json"
    rows = [*_asset_rows(), {"name": "DefenseClawSetup-x64.exe", "id": 999}]
    _write_release(release_json, rows)
    output = tmp_path / "release-custody"
    calls: list[tuple[list[str], dict[str, Any]]] = []

    download_release_custody.download_release_custody(
        repository=download_release_custody.EXPECTED_REPOSITORY,
        release_json=release_json,
        output_dir=output,
        runner=_successful_runner(calls),
    )

    assert [path.name for path in sorted(output.iterdir())] == sorted(download_release_custody.REQUIRED_PROOF_ASSETS)
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert len(calls) == len(download_release_custody.REQUIRED_PROOF_ASSETS)
    for index, (name, (command, kwargs)) in enumerate(
        zip(download_release_custody.REQUIRED_PROOF_ASSETS, calls, strict=True),
        start=101,
    ):
        assert command == [
            "gh",
            "api",
            "-H",
            "Accept: application/octet-stream",
            f"repos/{download_release_custody.EXPECTED_REPOSITORY}/releases/assets/{index}",
        ]
        assert kwargs["check"] is False
        assert kwargs["stderr"] is subprocess.PIPE
        assert kwargs["timeout"] == download_release_custody.ASSET_DOWNLOAD_TIMEOUT_SECONDS
        assert (output / name).read_text(encoding="utf-8").endswith(f"/{index}\n")
        assert stat.S_IMODE((output / name).stat().st_mode) == 0o600
        assert (output / name).stat().st_nlink == 1


def test_rejects_download_outside_the_asset_specific_verifier_bound(tmp_path: Path) -> None:
    release_json = tmp_path / "published-release.json"
    _write_release(release_json, _asset_rows())
    target = "checksums.txt.sig"
    asset_names_by_id = {str(row["id"]): str(row["name"]) for row in _asset_rows()}

    def oversized_runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        name = asset_names_by_id[command[-1].rsplit("/", 1)[-1]]
        size = download_release_custody.MAX_PROOF_BYTES[name] + 1 if name == target else 1
        kwargs["stdout"].write(b"x" * size)
        return subprocess.CompletedProcess(command, 0, stdout=None, stderr=b"")

    with pytest.raises(download_release_custody.ReleaseCustodyError, match="outside its size bound") as raised:
        download_release_custody.download_release_custody(
            repository=download_release_custody.EXPECTED_REPOSITORY,
            release_json=release_json,
            output_dir=tmp_path / "custody",
            runner=oversized_runner,
        )

    assert repr(target) in str(raised.value)


def test_final_custody_scandir_is_context_managed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_json = tmp_path / "published-release.json"
    _write_release(release_json, _asset_rows())
    real_scandir = os.scandir
    exited = False

    class ScandirContext:
        def __init__(self, path: os.PathLike[str]) -> None:
            self._iterator = real_scandir(path)

        def __enter__(self) -> os.ScandirIterator[str]:
            return self._iterator.__enter__()

        def __exit__(self, *args: object) -> None:
            nonlocal exited
            exited = True
            self._iterator.__exit__(*args)

    monkeypatch.setattr(download_release_custody.os, "scandir", ScandirContext)
    download_release_custody.download_release_custody(
        repository=download_release_custody.EXPECTED_REPOSITORY,
        release_json=release_json,
        output_dir=tmp_path / "custody",
        runner=_successful_runner([]),
    )

    assert exited


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("missing", "missing exact custody assets"),
        ("renamed", "missing exact custody assets"),
        ("duplicate", "ambiguous custody"),
        ("zero", "ambiguous custody"),
        ("negative", "ambiguous custody"),
        ("boolean", "ambiguous custody"),
        ("string", "ambiguous custody"),
    ],
)
def test_rejects_missing_renamed_duplicate_or_invalid_asset_ids_before_download(
    tmp_path: Path,
    case: str,
    message: str,
) -> None:
    rows = _asset_rows()
    if case == "missing":
        rows = rows[1:]
    elif case == "renamed":
        rows[0]["name"] = "Checksums.txt"
    elif case == "duplicate":
        rows.append(dict(rows[0]))
    elif case == "zero":
        rows[0]["id"] = 0
    elif case == "negative":
        rows[0]["id"] = -1
    elif case == "boolean":
        rows[0]["id"] = True
    elif case == "string":
        rows[0]["id"] = "101"
    release_json = tmp_path / f"{case}.json"
    _write_release(release_json, rows)
    output = tmp_path / f"custody-{case}"

    with pytest.raises(download_release_custody.ReleaseCustodyError, match=message):
        download_release_custody.download_release_custody(
            repository=download_release_custody.EXPECTED_REPOSITORY,
            release_json=release_json,
            output_dir=output,
            runner=lambda *_args, **_kwargs: pytest.fail("invalid inventory reached the downloader"),
        )

    assert not output.exists()


@pytest.mark.parametrize(
    "document",
    [
        [],
        {"assets": "not-a-list"},
        {"assets": [None]},
    ],
)
def test_rejects_invalid_release_inventory_shapes(tmp_path: Path, document: object) -> None:
    release_json = tmp_path / "published-release.json"
    release_json.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(download_release_custody.ReleaseCustodyError, match="invalid asset inventory"):
        download_release_custody.download_release_custody(
            repository=download_release_custody.EXPECTED_REPOSITORY,
            release_json=release_json,
            output_dir=tmp_path / "custody",
        )


def test_timeout_is_bounded_and_names_the_exact_asset(tmp_path: Path) -> None:
    release_json = tmp_path / "published-release.json"
    _write_release(release_json, _asset_rows())
    observed_timeout: list[int] = []

    def timeout_runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        observed_timeout.append(kwargs["timeout"])
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    with pytest.raises(download_release_custody.ReleaseCustodyError) as raised:
        download_release_custody.download_release_custody(
            repository=download_release_custody.EXPECTED_REPOSITORY,
            release_json=release_json,
            output_dir=tmp_path / "custody",
            runner=timeout_runner,
        )

    assert observed_timeout == [download_release_custody.ASSET_DOWNLOAD_TIMEOUT_SECONDS]
    assert repr(download_release_custody.REQUIRED_PROOF_ASSETS[0]) in str(raised.value)
    assert f"{download_release_custody.ASSET_DOWNLOAD_TIMEOUT_SECONDS} seconds" in str(raised.value)


def test_nonzero_download_names_asset_and_bounds_diagnostic(tmp_path: Path) -> None:
    release_json = tmp_path / "published-release.json"
    _write_release(release_json, _asset_rows())

    def failed_runner(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(command, 22, stdout=None, stderr=b"  remote   refused  " + b"x" * 800)

    with pytest.raises(download_release_custody.ReleaseCustodyError) as raised:
        download_release_custody.download_release_custody(
            repository=download_release_custody.EXPECTED_REPOSITORY,
            release_json=release_json,
            output_dir=tmp_path / "custody",
            runner=failed_runner,
        )

    message = str(raised.value)
    assert repr(download_release_custody.REQUIRED_PROOF_ASSETS[0]) in message
    assert "exit 22: remote refused" in message
    assert len(message) < 650


@pytest.mark.parametrize("preexisting", ["directory", "symlink", "dangling-symlink"])
def test_rejects_every_preexisting_output_path(tmp_path: Path, preexisting: str) -> None:
    release_json = tmp_path / "published-release.json"
    _write_release(release_json, _asset_rows())
    output = tmp_path / "custody"
    if preexisting == "directory":
        output.mkdir()
    elif preexisting == "symlink":
        target = tmp_path / "target"
        target.mkdir()
        output.symlink_to(target, target_is_directory=True)
    else:
        output.symlink_to(tmp_path / "missing", target_is_directory=True)

    with pytest.raises(download_release_custody.ReleaseCustodyError, match="must not exist"):
        download_release_custody.download_release_custody(
            repository=download_release_custody.EXPECTED_REPOSITORY,
            release_json=release_json,
            output_dir=output,
        )


def test_rejects_asset_if_downloader_changes_owner_only_mode(tmp_path: Path) -> None:
    release_json = tmp_path / "published-release.json"
    _write_release(release_json, _asset_rows())

    def chmod_runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        kwargs["stdout"].write(b"proof")
        os.fchmod(kwargs["stdout"].fileno(), 0o644)
        return subprocess.CompletedProcess(command, 0, stdout=None, stderr=b"")

    with pytest.raises(download_release_custody.ReleaseCustodyError, match="custody is unsafe"):
        download_release_custody.download_release_custody(
            repository=download_release_custody.EXPECTED_REPOSITORY,
            release_json=release_json,
            output_dir=tmp_path / "custody",
            runner=chmod_runner,
        )


def test_rejects_hardlinked_asset_custody(tmp_path: Path) -> None:
    release_json = tmp_path / "published-release.json"
    _write_release(release_json, _asset_rows())
    output = tmp_path / "custody"

    def hardlink_runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        kwargs["stdout"].write(b"proof")
        os.link(output / download_release_custody.REQUIRED_PROOF_ASSETS[0], tmp_path / "alias")
        return subprocess.CompletedProcess(command, 0, stdout=None, stderr=b"")

    with pytest.raises(download_release_custody.ReleaseCustodyError, match="custody is unsafe"):
        download_release_custody.download_release_custody(
            repository=download_release_custody.EXPECTED_REPOSITORY,
            release_json=release_json,
            output_dir=output,
            runner=hardlink_runner,
        )


def test_rejects_asset_path_replaced_with_symlink(tmp_path: Path) -> None:
    release_json = tmp_path / "published-release.json"
    _write_release(release_json, _asset_rows())
    output = tmp_path / "custody"
    external = tmp_path / "external"
    external.write_bytes(b"external")

    def symlink_runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        kwargs["stdout"].write(b"proof")
        path = output / download_release_custody.REQUIRED_PROOF_ASSETS[0]
        path.unlink()
        path.symlink_to(external)
        return subprocess.CompletedProcess(command, 0, stdout=None, stderr=b"")

    with pytest.raises(download_release_custody.ReleaseCustodyError, match="custody is unsafe"):
        download_release_custody.download_release_custody(
            repository=download_release_custody.EXPECTED_REPOSITORY,
            release_json=release_json,
            output_dir=output,
            runner=symlink_runner,
        )


def test_rejects_any_extra_file_in_final_custody_set(tmp_path: Path) -> None:
    release_json = tmp_path / "published-release.json"
    _write_release(release_json, _asset_rows())
    output = tmp_path / "custody"
    calls = 0

    def extra_file_runner(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        nonlocal calls
        calls += 1
        kwargs["stdout"].write(b"proof")
        if calls == len(download_release_custody.REQUIRED_PROOF_ASSETS):
            (output / "unexpected").write_bytes(b"unexpected")
        return subprocess.CompletedProcess(command, 0, stdout=None, stderr=b"")

    expected_count = len(download_release_custody.REQUIRED_PROOF_ASSETS)
    with pytest.raises(
        download_release_custody.ReleaseCustodyError,
        match=rf"exact {expected_count}-file set",
    ):
        download_release_custody.download_release_custody(
            repository=download_release_custody.EXPECTED_REPOSITORY,
            release_json=release_json,
            output_dir=output,
            runner=extra_file_runner,
        )


def test_rejects_wrong_repository_and_nonpositive_timeout_before_mutation(tmp_path: Path) -> None:
    release_json = tmp_path / "published-release.json"
    _write_release(release_json, _asset_rows())
    with pytest.raises(download_release_custody.ReleaseCustodyError, match="repository must be exactly"):
        download_release_custody.download_release_custody(
            repository="attacker/fork",
            release_json=release_json,
            output_dir=tmp_path / "wrong-repository",
        )
    with pytest.raises(download_release_custody.ReleaseCustodyError, match="timeout must be positive"):
        download_release_custody.download_release_custody(
            repository=download_release_custody.EXPECTED_REPOSITORY,
            release_json=release_json,
            output_dir=tmp_path / "bad-timeout",
            timeout_seconds=0,
        )
