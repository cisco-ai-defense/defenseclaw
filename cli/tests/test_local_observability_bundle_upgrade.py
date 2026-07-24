# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Exact P7-WP03 tests for the local-observability bundle transaction."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from defenseclaw.bundle_refresh import (
    _LOCAL_OBSERVABILITY_DASHBOARD_UIDS,
    LocalObservabilityUpgradeError,
    _atomic_copy_file,
    _live_local_observability_smoke,
    restart_upgraded_local_observability_stack,
    upgrade_local_observability_stack,
)
from defenseclaw.commands.cmd_upgrade import (
    _crash_bundle_rollback_result,
    _restore_local_observability_upgrade_backup,
)

ROOT = Path(__file__).resolve().parents[2]
REAL_BUNDLE = ROOT / "bundles" / "local_observability_stack"


@pytest.fixture()
def installed_bundle(tmp_path: Path) -> tuple[Path, Path, Path]:
    source = tmp_path / "target-bundle"
    data_dir = tmp_path / "data"
    destination = data_dir / "observability-stack"
    shutil.copytree(REAL_BUNDLE, source)
    shutil.copytree(source, destination)
    return source, data_dir, destination


def _upgrade(
    source: Path,
    data_dir: Path,
    backup: Path,
    *,
    version: str = "8.0.0",
    fault=None,
):
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh._strict_compose_project_running", return_value=False),
    ):
        return upgrade_local_observability_stack(
            str(data_dir),
            str(backup),
            bundle_version=version,
            fault_injector=fault,
        )


def _managed_snapshot(destination: Path) -> dict[str, tuple[bytes, int]]:
    result: dict[str, tuple[bytes, int]] = {}
    for path in sorted(destination.rglob("*")):
        if path.is_file() and not path.is_symlink():
            result[path.relative_to(destination).as_posix()] = (
                path.read_bytes(),
                stat.S_IMODE(path.stat().st_mode),
            )
    return result


def test_untouched_baseline_refreshes_without_false_conflict(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    first = _upgrade(source, data_dir, tmp_path / "backup-1", version="7.9.0")
    assert first.conflict_paths == ()

    old = destination.joinpath("README.md").read_bytes()
    source.joinpath("README.md").write_bytes(old + b"\nnew target release\n")
    second = _upgrade(source, data_dir, tmp_path / "backup-2", version="8.0.0")

    assert second.refreshed is True
    assert "README.md" in second.changed_paths
    assert second.conflict_paths == ()
    assert destination.joinpath("README.md").read_bytes().endswith(b"new target release\n")
    assert (tmp_path / "backup-2/local-observability-stack/managed/README.md").read_bytes() == old


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows flush semantics")
def test_windows_transaction_preserves_raw_crlf_backup_bytes(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    managed = destination / "prometheus/prometheus.yml"
    operator_bytes = b"# operator override\r\nglobal:\r\n  scrape_interval: 15s\r\n"
    managed.write_bytes(operator_bytes)

    result = _upgrade(source, data_dir, tmp_path / "backup")

    backup = tmp_path / "backup/local-observability-stack/managed/prometheus/prometheus.yml"
    assert result.refreshed is True
    assert result.conflict_paths == ("prometheus/prometheus.yml",)
    assert backup.read_bytes() == operator_bytes
    assert managed.read_bytes() == source.joinpath("prometheus/prometheus.yml").read_bytes()


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows file attributes")
def test_windows_atomic_copy_flushes_read_only_source_bytes(tmp_path: Path) -> None:
    source = tmp_path / "operator.yaml"
    destination = tmp_path / "rollback.yaml"
    payload = b"operator: retained\r\n"
    source.write_bytes(payload)
    os.chmod(source, stat.S_IREAD)
    expected_mode = stat.S_IMODE(source.stat().st_mode)
    try:
        _atomic_copy_file(str(source), str(destination))
        assert destination.read_bytes() == payload
        assert stat.S_IMODE(destination.stat().st_mode) == expected_mode
    finally:
        os.chmod(source, stat.S_IWRITE)
        if destination.exists():
            os.chmod(destination, stat.S_IWRITE)


def test_upgrade_canonicalizes_wheel_modes_for_non_root_containers(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    if os.name == "nt":
        pytest.skip("POSIX bind-mount mode contract")
    source, data_dir, destination = installed_bundle
    for path in source.rglob("*"):
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
    for path in destination.rglob("*"):
        os.chmod(path, 0o700 if path.is_dir() else 0o600)

    result = _upgrade(source, data_dir, tmp_path / "backup")

    assert result.refreshed is True
    assert stat.S_IMODE((destination / "otel-collector/config.yaml").stat().st_mode) == 0o644
    assert stat.S_IMODE((destination / "grafana/dashboards").stat().st_mode) == 0o755
    assert stat.S_IMODE((destination / "run.sh").stat().st_mode) == 0o755
    manifest = json.loads(
        (destination / ".defenseclaw-bundle-manifest.json").read_text(encoding="utf-8")
    )
    modes = {entry["path"]: entry["mode"] for entry in manifest["files"]}
    assert modes["otel-collector/config.yaml"] == 0o644
    assert modes["run.sh"] == 0o755


def test_custom_file_survives_and_managed_conflict_is_backed_up(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    _upgrade(source, data_dir, tmp_path / "backup-1", version="7.9.0")
    custom = destination / "grafana/dashboards/team-custom.json"
    custom.write_text('{"uid":"team-custom"}\n', encoding="utf-8")
    managed = destination / "prometheus/prometheus.yml"
    operator_bytes = b"# operator modified managed config\n"
    managed.write_bytes(operator_bytes)

    result = _upgrade(source, data_dir, tmp_path / "backup-2", version="8.0.0")

    assert custom.read_text(encoding="utf-8") == '{"uid":"team-custom"}\n'
    assert "grafana/dashboards/team-custom.json" in result.preserved_custom_paths
    assert result.conflict_paths == ("prometheus/prometheus.yml",)
    conflict_backup = tmp_path / ("backup-2/local-observability-stack/managed/prometheus/prometheus.yml")
    assert conflict_backup.read_bytes() == operator_bytes
    backup_metadata = json.loads(
        (tmp_path / "backup-2/local-observability-stack/refresh-backup.json").read_text(
            encoding="utf-8"
        )
    )
    assert backup_metadata["managed_paths"] == sorted(
        [
            *result.managed_paths,
            ".defenseclaw-bundle-manifest.json",
        ]
    )
    if os.name != "nt":
        assert stat.S_IMODE((tmp_path / "backup-2/local-observability-stack").stat().st_mode) == 0o700
        assert stat.S_IMODE(conflict_backup.stat().st_mode) == 0o600
    assert managed.read_bytes() == source.joinpath("prometheus/prometheus.yml").read_bytes()


def test_installed_manifest_cannot_claim_and_delete_an_operator_file(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    _upgrade(source, data_dir, tmp_path / "backup-1", version="7.9.0")
    custom = destination / "operator/private-notes.txt"
    custom.parent.mkdir()
    custom.write_bytes(b"must survive\n")
    manifest_path = destination / ".defenseclaw-bundle-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].append(
        {
            "path": "operator/private-notes.txt",
            "sha256": hashlib.sha256(custom.read_bytes()).hexdigest(),
            "size": custom.stat().st_size,
            "mode": stat.S_IMODE(custom.stat().st_mode),
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = _upgrade(source, data_dir, tmp_path / "backup-2", version="8.0.0")

    assert custom.read_bytes() == b"must survive\n"
    assert "operator/private-notes.txt" in result.preserved_custom_paths


def test_retired_path_collision_is_preserved_when_bytes_are_not_a_shipped_asset(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    retired = destination / "grafana/dashboards/defenseclaw-reliability.json"
    retired.write_bytes(b'{"uid":"operator-reliability"}\n')

    result = _upgrade(source, data_dir, tmp_path / "backup")

    assert retired.read_bytes() == b'{"uid":"operator-reliability"}\n'
    assert result.conflict_paths == ()
    assert "grafana/dashboards/defenseclaw-reliability.json" in result.preserved_custom_paths


def test_reviewed_retired_bundle_asset_is_backed_up_then_removed(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    retired = destination / "grafana/dashboards/defenseclaw-reliability.json"
    retired_bytes = b'{"uid":"old-shipped-reliability"}\n'
    retired.write_bytes(retired_bytes)
    digest = hashlib.sha256(retired_bytes).hexdigest()

    with patch.dict(
        "defenseclaw.bundle_refresh._LOCAL_OBSERVABILITY_RETIRED_SHA256",
        {"grafana/dashboards/defenseclaw-reliability.json": frozenset({digest})},
        clear=True,
    ):
        result = _upgrade(source, data_dir, tmp_path / "backup")

    assert not retired.exists()
    assert result.conflict_paths == ()
    backup = tmp_path / ("backup/local-observability-stack/managed/grafana/dashboards/defenseclaw-reliability.json")
    assert backup.read_bytes() == retired_bytes


def test_named_volumes_are_declared_and_running_stack_uses_down_without_v(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, _destination = installed_bundle
    completed = MagicMock(returncode=0, stdout="", stderr="")
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch(
            "defenseclaw.bundle_refresh._strict_compose_project_running",
            side_effect=[True, False],
        ),
        patch("defenseclaw.bundle_refresh.subprocess.run", return_value=completed) as run,
    ):
        result = upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
        )

    assert result.was_running is True
    assert result.stopped is True
    assert result.restart_required is True
    assert result.named_volumes == (
        "grafana-data",
        "loki-data",
        "prometheus-data",
        "tempo-data",
    )
    command = run.call_args.args[0]
    assert command[-1] == "down"
    assert "-v" not in command
    assert "reset" not in command


def test_partial_activation_restores_exact_managed_tree_and_manifest(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    _upgrade(source, data_dir, tmp_path / "backup-1", version="7.9.0")
    custom = destination / "grafana/dashboards/team-custom.json"
    custom.write_text('{"uid":"team-custom"}\n', encoding="utf-8")
    source.joinpath("README.md").write_text("replacement\n", encoding="utf-8")
    before = _managed_snapshot(destination)

    def fail_after_first_write(event: str, path: str | None) -> None:
        if event == "after_activate" and path == "README.md":
            raise OSError("injected write failure")

    with pytest.raises(LocalObservabilityUpgradeError, match="activation_failed"):
        _upgrade(
            source,
            data_dir,
            tmp_path / "backup-2",
            version="8.0.0",
            fault=fail_after_first_write,
        )

    assert _managed_snapshot(destination) == before
    assert custom.read_text(encoding="utf-8") == '{"uid":"team-custom"}\n'


def test_stop_failure_prevents_refresh_and_leaves_bytes_untouched(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    before = _managed_snapshot(destination)
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh._strict_compose_project_running", return_value=True),
        patch(
            "defenseclaw.bundle_refresh.subprocess.run",
            return_value=MagicMock(returncode=1, stdout="", stderr="failure"),
        ),
        pytest.raises(LocalObservabilityUpgradeError, match="stack_stop_failed"),
    ):
        upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
        )
    assert _managed_snapshot(destination) == before
    backup_root = tmp_path / "backup/local-observability-stack"
    intent = json.loads((backup_root / "restart-intent.json").read_text(encoding="utf-8"))
    assert intent["restart_required"] is True
    assert not (backup_root / "refresh-backup.json").exists()


def test_post_stop_backup_failure_retains_exact_restart_intent_before_descriptor(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    before = _managed_snapshot(destination)
    completed = MagicMock(returncode=0, stdout="", stderr="")

    def fail_before_backup(event: str, _path: str | None) -> None:
        if event == "after_stop":
            raise OSError("injected post-stop failure")

    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch(
            "defenseclaw.bundle_refresh._strict_compose_project_running",
            side_effect=[True, False],
        ),
        patch("defenseclaw.bundle_refresh.subprocess.run", return_value=completed) as run,
        pytest.raises(LocalObservabilityUpgradeError, match="backup_failed"),
    ):
        upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
            fault_injector=fail_before_backup,
        )

    backup_root = tmp_path / "backup/local-observability-stack"
    intent = json.loads((backup_root / "restart-intent.json").read_text(encoding="utf-8"))
    assert set(intent) == {
        "schema_version",
        "target_manifest_sha256",
        "restart_required",
    }
    assert intent["schema_version"] == 1
    assert len(intent["target_manifest_sha256"]) == 64
    assert set(intent["target_manifest_sha256"]) <= set("0123456789abcdef")
    assert intent["restart_required"] is True
    if os.name == "posix":
        assert stat.S_IMODE(backup_root.stat().st_mode) == 0o700
        assert stat.S_IMODE((backup_root / "restart-intent.json").stat().st_mode) == 0o600
    assert not (backup_root / "refresh-backup.json").exists()
    assert not (backup_root / "managed").exists()
    assert _managed_snapshot(destination) == before
    assert run.call_args.args[0][-1] == "down"


def test_receipt_restart_intent_is_recorded_before_stack_stop(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, _destination = installed_bundle
    recorded: list[bool] = []

    def fail_after_intent(event: str, _path: str | None) -> None:
        if event == "after_restart_intent":
            raise OSError("stop before stack mutation")

    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh._strict_compose_project_running", return_value=True),
        patch("defenseclaw.bundle_refresh.subprocess.run") as run,
        pytest.raises(LocalObservabilityUpgradeError, match="backup_failed"),
    ):
        upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
            fault_injector=fail_after_intent,
            restart_intent_recorder=recorded.append,
        )

    assert recorded == [True]
    run.assert_not_called()


def test_failed_receipt_recorder_discards_only_new_custody_and_allows_retry(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    before = _managed_snapshot(destination)
    backup_dir = tmp_path / "backup"
    recorder_error = OSError("receipt write failed")

    def fail_recorder(_required: bool) -> None:
        raise recorder_error

    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh._strict_compose_project_running", return_value=True),
        patch("defenseclaw.bundle_refresh.subprocess.run") as run,
        pytest.raises(LocalObservabilityUpgradeError, match="backup_failed") as raised,
    ):
        upgrade_local_observability_stack(
            str(data_dir),
            str(backup_dir),
            bundle_version="8.0.0",
            restart_intent_recorder=fail_recorder,
        )

    assert raised.value.__cause__ is recorder_error
    assert not (backup_dir / "local-observability-stack").exists()
    assert _managed_snapshot(destination) == before
    run.assert_not_called()

    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh._strict_compose_project_running", return_value=False),
    ):
        retried = upgrade_local_observability_stack(
            str(data_dir),
            str(backup_dir),
            bundle_version="8.0.0",
            restart_intent_recorder=lambda _required: None,
        )

    assert retried.installed is True
    assert (backup_dir / "local-observability-stack/refresh-backup.json").is_file()


def test_failed_receipt_recorder_cleanup_does_not_follow_replaced_intent_symlink(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    if os.name != "posix":
        pytest.skip("symlink race regression requires POSIX")
    source, data_dir, destination = installed_bundle
    before = _managed_snapshot(destination)
    backup_dir = tmp_path / "backup"
    backup_root = backup_dir / "local-observability-stack"
    intent = backup_root / "restart-intent.json"
    sentinel = tmp_path / "must-not-delete"
    sentinel.write_text("sentinel\n", encoding="utf-8")
    recorder_error = OSError("receipt write failed")

    def replace_intent_then_fail(_required: bool) -> None:
        intent.unlink()
        intent.symlink_to(sentinel)
        raise recorder_error

    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh._strict_compose_project_running", return_value=True),
        patch("defenseclaw.bundle_refresh.subprocess.run") as run,
        pytest.raises(LocalObservabilityUpgradeError, match="backup_failed") as raised,
    ):
        upgrade_local_observability_stack(
            str(data_dir),
            str(backup_dir),
            bundle_version="8.0.0",
            restart_intent_recorder=replace_intent_then_fail,
        )

    assert raised.value.__cause__ is recorder_error
    assert intent.is_symlink()
    assert sentinel.read_text(encoding="utf-8") == "sentinel\n"
    assert _managed_snapshot(destination) == before
    run.assert_not_called()


def test_backup_source_race_fails_before_descriptor_or_bundle_mutation(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    before = _managed_snapshot(destination)
    backup_root = tmp_path / "backup/local-observability-stack"

    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh._strict_compose_project_running", return_value=False),
        patch(
            "defenseclaw.bundle_refresh._rollback_source_snapshot_unchanged",
            return_value=False,
        ),
        pytest.raises(LocalObservabilityUpgradeError, match="backup_source_changed"),
    ):
        upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
        )

    assert (backup_root / "restart-intent.json").is_file()
    assert not (backup_root / "refresh-backup.json").exists()
    assert _managed_snapshot(destination) == before


def test_same_target_retry_is_idempotent(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    custom = destination / "grafana/dashboards/team-custom.json"
    custom.write_text('{"uid":"team-custom"}\n', encoding="utf-8")
    first = _upgrade(source, data_dir, tmp_path / "backup-1")
    first_manifest = destination.joinpath(".defenseclaw-bundle-manifest.json").read_bytes()
    second = _upgrade(source, data_dir, tmp_path / "backup-2")

    assert first.refreshed is True
    assert second.refreshed is False
    assert second.changed_paths == ()
    assert second.conflict_paths == ()
    assert destination.joinpath(".defenseclaw-bundle-manifest.json").read_bytes() == first_manifest
    assert custom.exists()


def test_schema_two_backup_round_trips_through_bridge_rollback(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    source.joinpath("README.md").write_text("target replacement\n", encoding="utf-8")
    before = _managed_snapshot(destination)
    backup_dir = tmp_path / "backup"

    result = _upgrade(source, data_dir, backup_dir)
    metadata = json.loads(
        (backup_dir / "local-observability-stack/refresh-backup.json").read_text(
            encoding="utf-8"
        )
    )

    assert set(metadata) == {
        "schema_version",
        "managed_paths",
        "existing_paths",
        "old_sha256",
        "old_modes",
        "created_sha256",
        "old_windows_security",
        "restart_required",
    }
    assert metadata["schema_version"] == 2
    assert metadata["restart_required"] is False
    assert set(metadata["created_sha256"]) == {".defenseclaw-bundle-manifest.json"}
    assert os.path.samefile(
        backup_dir / "local-observability-stack/created/.defenseclaw-bundle-manifest.json",
        destination / ".defenseclaw-bundle-manifest.json",
    )

    durable_restart = _restore_local_observability_upgrade_backup(
        str(data_dir),
        str(backup_dir),
        result.to_dict(),
    )

    assert durable_restart is False
    assert _managed_snapshot(destination) == before


def test_crash_after_first_publish_replays_schema_two_custody_exactly(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    source.joinpath("README.md").write_text("target replacement\n", encoding="utf-8")
    before = _managed_snapshot(destination)
    backup_dir = tmp_path / "backup"

    def crash_after_publish(event: str, relative: str | None) -> None:
        if event == "after_activate" and relative == "README.md":
            raise SystemExit("injected hard crash")

    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh._strict_compose_project_running", return_value=False),
        pytest.raises(SystemExit, match="injected hard crash"),
    ):
        upgrade_local_observability_stack(
            str(data_dir),
            str(backup_dir),
            bundle_version="8.0.0",
            fault_injector=crash_after_publish,
        )

    assert destination.joinpath("README.md").read_text(encoding="utf-8") == "target replacement\n"
    recovered = _crash_bundle_rollback_result(str(backup_dir), required=True)
    assert recovered is not None
    assert recovered["installed"] is True
    assert recovered["restart_required"] is False

    durable_restart = _restore_local_observability_upgrade_backup(
        str(data_dir),
        str(backup_dir),
        recovered,
    )

    assert durable_restart is False
    assert _managed_snapshot(destination) == before


def test_non_local_bundle_install_is_a_noop_before_docker_or_source_lookup(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir") as source,
        patch("defenseclaw.bundle_refresh._strict_compose_project_running") as running,
    ):
        result = upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
        )
    assert result.installed is False
    source.assert_not_called()
    running.assert_not_called()


def test_seeded_but_unused_bundle_refreshes_without_docker(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, _destination = installed_bundle
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh.shutil.which", return_value=None),
        patch("defenseclaw.bundle_refresh._local_observability_ports_active", return_value=False),
    ):
        result = upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
        )
    assert result.installed is True
    assert result.was_running is False
    assert result.restart_required is False


def test_uninspectable_active_stack_fails_before_backup(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, _destination = installed_bundle
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh.shutil.which", return_value=None),
        patch("defenseclaw.bundle_refresh._local_observability_ports_active", return_value=True),
        pytest.raises(LocalObservabilityUpgradeError, match="docker_state_unknown"),
    ):
        upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
        )
    assert not (tmp_path / "backup/local-observability-stack").exists()


def test_restart_smoke_never_uses_reset_and_reports_success(
    installed_bundle: tuple[Path, Path, Path],
) -> None:
    _source, data_dir, _destination = installed_bundle
    contract = (
        '{"otlp_endpoint":"127.0.0.1:4317",'
        '"grafana_url":"http://localhost:3000",'
        '"prometheus_url":"http://localhost:9090",'
        '"tempo_url":"http://localhost:3200",'
        '"loki_url":"http://localhost:3100"}\n'
    )
    with (
        patch(
            "defenseclaw.bundle_refresh.subprocess.run",
            return_value=MagicMock(returncode=0, stdout=contract, stderr=""),
        ) as run,
        patch("defenseclaw.bundle_refresh._live_local_observability_smoke", return_value=[]),
    ):
        result = restart_upgraded_local_observability_stack(str(data_dir), timeout=5)

    assert result.restarted is True
    command = run.call_args.args[0]
    assert command[1] == "up"
    assert "reset" not in command
    assert "-v" not in command


def test_live_smoke_requires_every_readiness_probe_and_dashboard_uid() -> None:
    complete = [{"uid": uid} for uid in _LOCAL_OBSERVABILITY_DASHBOARD_UIDS]
    with (
        patch("defenseclaw.bundle_refresh._http_ready", return_value=True) as ready,
        patch("defenseclaw.bundle_refresh._http_get_json", return_value=complete),
    ):
        assert _live_local_observability_smoke(1) == []
    assert ready.call_count == 5

    with (
        patch("defenseclaw.bundle_refresh._http_ready", return_value=True),
        patch("defenseclaw.bundle_refresh._http_get_json", return_value=complete[:-1]),
    ):
        assert _live_local_observability_smoke(1) == ["grafana_dashboard_inventory_incomplete"]


@pytest.mark.skipif(os.name == "nt", reason="symlink semantics require POSIX")
def test_managed_parent_symlink_fails_before_stack_state_or_backup(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, destination = installed_bundle
    shutil.rmtree(destination / "prometheus")
    outside = tmp_path / "outside"
    outside.mkdir()
    (destination / "prometheus").symlink_to(outside, target_is_directory=True)
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh._strict_compose_project_running") as running,
        pytest.raises(LocalObservabilityUpgradeError, match="managed_parent_symlink"),
    ):
        upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
        )
    running.assert_not_called()
    assert not (tmp_path / "backup/local-observability-stack").exists()


@pytest.mark.skipif(os.name == "nt", reason="symlink semantics require POSIX")
def test_backup_root_symlink_is_rejected_before_copy(
    installed_bundle: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    source, data_dir, _destination = installed_bundle
    outside = tmp_path / "outside"
    outside.mkdir()
    backup = tmp_path / "backup"
    backup.symlink_to(outside, target_is_directory=True)
    with (
        patch("defenseclaw.bundle_refresh.bundled_local_observability_dir", return_value=source),
        patch("defenseclaw.bundle_refresh._strict_compose_project_running", return_value=False),
        pytest.raises(LocalObservabilityUpgradeError, match="unsafe_backup_root"),
    ):
        upgrade_local_observability_stack(
            str(data_dir),
            str(backup),
            bundle_version="8.0.0",
        )
    assert list(outside.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="symlink semantics require POSIX")
def test_dangling_install_root_symlink_is_not_treated_as_absent(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "observability-stack").symlink_to(tmp_path / "missing")

    with pytest.raises(LocalObservabilityUpgradeError, match="unsafe_install_root"):
        upgrade_local_observability_stack(
            str(data_dir),
            str(tmp_path / "backup"),
            bundle_version="8.0.0",
        )
