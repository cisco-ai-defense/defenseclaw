# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import errno
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import click
import pytest
from click.testing import CliRunner
from defenseclaw.commands.cmd_setup_observability import (
    _build_v8_preset_destination,
    _print_v8_destination_list,
    _remove_v8_destination,
    _set_v8_destination_enabled,
    _test_v8_destination,
    _v8_destination_update_mutations,
    _v8_source_destination_index,
    observability,
)
from defenseclaw.context import AppContext
from defenseclaw.observability import PRESETS
from defenseclaw.observability import v8_activation as v8_activation_module
from defenseclaw.observability.v8_activation import V8ActivationError
from defenseclaw.observability.v8_config import load_validate_v8
from defenseclaw.observability.v8_presets import apply_secret
from defenseclaw.observability.v8_status import V8DestinationStatus, V8OperatorStatus
from defenseclaw.observability.v8_writer import V8PolicyWriteResult
from defenseclaw.observability.v8_yaml import DELETE
from defenseclaw.safety import DotenvValueError
from dotenv import dotenv_values


def _source() -> str:
    return """config_version: 8
observability:
  destinations:
    - name: terminal
      kind: console
    - name: archive
      kind: jsonl
      path: /tmp/archive.jsonl
"""


def _status() -> V8OperatorStatus:
    return V8OperatorStatus(
        source="/tmp/config.yaml",
        data_dir="/tmp",
        plan_digest="a" * 64,
        bucket_catalog_version=1,
        retention_days=90,
        local_path="/tmp/audit.db",
        judge_bodies_path="",
        destinations=(
            V8DestinationStatus(
                name="local-sqlite",
                kind="sqlite",
                enabled=True,
                generated=True,
                capabilities=("logs",),
                selected_signals=("logs",),
                policy_form="implicit_local",
                endpoint="/tmp/audit.db",
                route_count=1,
                buckets=("compliance.activity",),
                redaction_profiles=("none",),
            ),
            V8DestinationStatus(
                name="collector",
                kind="otlp",
                enabled=True,
                generated=False,
                capabilities=("logs", "traces", "metrics"),
                selected_signals=("logs", "traces", "metrics"),
                policy_form="capability_default",
                endpoint="https://collector.example.test",
                route_count=1,
                buckets=("compliance.activity",),
                redaction_profiles=("none",),
            ),
        ),
        buckets=(),
        warnings=(),
    )


def _setup_app(tmp_path: Path) -> AppContext:
    (tmp_path / "config.yaml").write_text("config_version: 8\nobservability: {}\n")
    app = AppContext()
    app.cfg = SimpleNamespace(data_dir=str(tmp_path))
    return app


def _stub_canonical_v8_gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "defenseclaw.commands.cmd_setup_observability._require_v8_operator_status",
        lambda _data_dir: _status(),
    )
    monkeypatch.setattr(
        "defenseclaw.observability.v8_writer.inspect_v8_config",
        lambda *_args, **_kwargs: SimpleNamespace(valid=True),
    )


def test_setup_v8_accepts_observability_token_from_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_canonical_v8_gateway(monkeypatch)
    secret = "environment-only-dd-key"
    result = CliRunner().invoke(
        observability,
        [
            "add",
            "datadog",
            "--non-interactive",
            "--site",
            "us5",
            "--signals",
            "traces,metrics",
        ],
        obj=_setup_app(tmp_path),
        env={"DEFENSECLAW_SETUP_OBSERVABILITY_TOKEN": secret},
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.output
    assert secret not in result.output
    assert "Using token from DEFENSECLAW_SETUP_OBSERVABILITY_TOKEN." in result.output
    assert dotenv_values(tmp_path / ".env").get("DD_API_KEY") == secret


def test_setup_v8_explicit_token_takes_precedence_over_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_canonical_v8_gateway(monkeypatch)
    environment_secret = "environment-dd-key"
    explicit_secret = "explicit-dd-key"
    result = CliRunner().invoke(
        observability,
        [
            "add",
            "datadog",
            "--non-interactive",
            "--token",
            explicit_secret,
            "--site",
            "us5",
            "--signals",
            "traces",
        ],
        obj=_setup_app(tmp_path),
        env={"DEFENSECLAW_SETUP_OBSERVABILITY_TOKEN": environment_secret},
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.output
    assert dotenv_values(tmp_path / ".env").get("DD_API_KEY") == explicit_secret
    assert environment_secret not in result.output
    assert explicit_secret not in result.output


def test_v8_secret_dotenv_fsyncs_staged_file_before_atomic_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preset = PRESETS["datadog"]
    events: list[str] = []
    real_fsync = os.fsync
    real_link = os.link

    def fsync(descriptor: int) -> None:
        kind = "directory" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "file"
        events.append(f"fsync:{kind}")
        real_fsync(descriptor)

    def link(source, destination, *args, **kwargs):
        if os.fspath(destination) == ".env":
            events.append("publish")
        return real_link(source, destination, *args, **kwargs)

    monkeypatch.setattr(v8_activation_module.os, "fsync", fsync)
    monkeypatch.setattr(v8_activation_module.os, "link", link)
    monkeypatch.setenv(preset.token_env, "before-test")

    apply_secret(str(tmp_path), preset, "durable-secret", dry_run=False)

    publish = events.index("publish")
    assert "fsync:file" in events[:publish]
    assert "fsync:directory" in events[publish + 1 :]
    assert dotenv_values(tmp_path / ".env").get(preset.token_env) == "durable-secret"


def test_v8_secret_dotenv_replace_failure_preserves_existing_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preset = PRESETS["datadog"]
    monkeypatch.setenv(preset.token_env, "before-test")
    apply_secret(str(tmp_path), preset, "original-secret", dry_run=False)
    dotenv = tmp_path / ".env"
    before = dotenv.read_bytes()

    def reject_replace(*_args, **_kwargs) -> None:
        raise V8ActivationError("replace_failed", "locked_publish_check", target_path=str(dotenv))

    monkeypatch.setattr(v8_activation_module, "_exchange_entries", reject_replace)
    with pytest.raises(V8ActivationError) as captured:
        apply_secret(str(tmp_path), preset, "replacement-secret", dry_run=False)

    assert captured.value.code == "replace_failed"
    assert dotenv.read_bytes() == before
    assert os.environ[preset.token_env] == "original-secret"
    assert not list(tmp_path.glob("..env.observability-v8-*.tmp"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode/xattr regression")
@pytest.mark.parametrize("mode", [0o600, 0o640, 0o644])
def test_v8_secret_dotenv_preserves_owner_xattrs_and_tightens_read_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: int,
) -> None:
    preset = PRESETS["datadog"]
    dotenv = tmp_path / ".env"
    dotenv.write_text("EXISTING=keep\n", encoding="utf-8")
    os.chmod(dotenv, mode)
    before = dotenv.stat()
    attribute = "user.defenseclaw-test"
    xattr_supported = hasattr(os, "setxattr")
    if xattr_supported:
        try:
            os.setxattr(dotenv, attribute, b"preserve")
        except OSError:
            xattr_supported = False
    monkeypatch.setenv(preset.token_env, "before-test")

    apply_secret(str(tmp_path), preset, "replacement-secret", dry_run=False)

    after = dotenv.stat()
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)
    assert stat.S_IMODE(after.st_mode) == 0o600
    if xattr_supported:
        assert os.getxattr(dotenv, attribute) == b"preserve"
    assert dotenv_values(dotenv).get("EXISTING") == "keep"
    assert dotenv_values(dotenv).get(preset.token_env) == "replacement-secret"


@pytest.mark.skipif(os.name == "nt", reason="POSIX read-permission regression")
def test_v8_secret_dotenv_read_only_discovery_rejects_broadly_readable_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preset = PRESETS["datadog"]
    dotenv = tmp_path / ".env"
    original = f"{preset.token_env}=existing-secret\n".encode()
    dotenv.write_bytes(original)
    os.chmod(dotenv, 0o644)
    before = os.lstat(dotenv)
    monkeypatch.delenv(preset.token_env, raising=False)

    with pytest.raises(V8ActivationError) as captured:
        apply_secret(str(tmp_path), preset, None, dry_run=False)

    after = os.lstat(dotenv)
    assert captured.value.code == "environment_permissions_unsafe"
    assert dotenv.read_bytes() == original
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    assert stat.S_IMODE(after.st_mode) == 0o644


@pytest.mark.skipif(os.name == "nt", reason="POSIX file-type regression")
@pytest.mark.parametrize("target_kind", ["symlink", "directory", "fifo"])
def test_v8_secret_dotenv_rejects_non_regular_target_before_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_kind: str,
) -> None:
    preset = PRESETS["datadog"]
    dotenv = tmp_path / ".env"
    backing = tmp_path / "managed-secrets.env"
    backing.write_text("MANAGED=unchanged\n", encoding="utf-8")
    if target_kind == "symlink":
        dotenv.symlink_to(backing)
        expected_code = "symlink_forbidden"
    elif target_kind == "directory":
        dotenv.mkdir()
        expected_code = "regular_file_required"
    else:
        os.mkfifo(dotenv)
        expected_code = "regular_file_required"
    monkeypatch.setenv(preset.token_env, "before-test")

    with pytest.raises(V8ActivationError) as captured:
        apply_secret(str(tmp_path), preset, "replacement-secret", dry_run=False)

    assert captured.value.code == expected_code
    assert backing.read_text(encoding="utf-8") == "MANAGED=unchanged\n"
    if target_kind == "symlink":
        assert dotenv.is_symlink()
    elif target_kind == "directory":
        assert dotenv.is_dir()
    else:
        assert stat.S_ISFIFO(os.lstat(dotenv).st_mode)
    assert os.environ[preset.token_env] == "before-test"


@pytest.mark.skipif(os.name == "nt", reason="POSIX parent-symlink regression")
def test_v8_secret_dotenv_rejects_symlinked_data_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preset = PRESETS["datadog"]
    real_data = tmp_path / "real-data"
    real_data.mkdir()
    linked_data = tmp_path / "linked-data"
    linked_data.symlink_to(real_data, target_is_directory=True)
    monkeypatch.setenv(preset.token_env, "before-test")

    with pytest.raises(V8ActivationError) as captured:
        apply_secret(str(linked_data), preset, "replacement-secret", dry_run=False)

    assert captured.value.code in {"symlink_forbidden", "parent_symlink_forbidden"}
    assert linked_data.is_symlink()
    assert not (real_data / ".env").exists()
    assert os.environ[preset.token_env] == "before-test"


def test_v8_secret_dotenv_final_window_cas_restores_concurrent_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preset = PRESETS["datadog"]
    monkeypatch.setenv(preset.token_env, "before-test")
    apply_secret(str(tmp_path), preset, "original-secret", dry_run=False)
    dotenv = tmp_path / ".env"
    concurrent = b"EXTERNAL_ROTATION=preserve\n"
    real_exchange = v8_activation_module._exchange_entries
    raced = False

    def race(parent_descriptor, first, second, target_path):
        nonlocal raced
        if not raced and target_path == str(dotenv):
            raced = True
            dotenv.write_bytes(concurrent)
        return real_exchange(parent_descriptor, first, second, target_path)

    monkeypatch.setattr(v8_activation_module, "_exchange_entries", race)

    with pytest.raises(V8ActivationError) as captured:
        apply_secret(str(tmp_path), preset, "replacement-secret", dry_run=False)

    assert captured.value.code == "source_changed"
    assert raced
    assert dotenv.read_bytes() == concurrent
    assert os.environ[preset.token_env] == "original-secret"
    assert not list(tmp_path.glob("..env.observability-v8-*.tmp"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX parent-mode regression")
def test_v8_secret_dotenv_parent_mode_drift_cannot_return_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preset = PRESETS["datadog"]
    monkeypatch.setenv(preset.token_env, "before-test")
    apply_secret(str(tmp_path), preset, "original-secret", dry_run=False)
    dotenv = tmp_path / ".env"
    original = dotenv.read_bytes()
    original_parent_mode = stat.S_IMODE(os.lstat(tmp_path).st_mode)
    real_exchange = v8_activation_module._exchange_entries
    raced = False

    def weaken_parent(parent_descriptor, first, second, target_path):
        nonlocal raced
        if not raced and target_path == str(dotenv):
            raced = True
            os.chmod(tmp_path, 0o777)
        return real_exchange(parent_descriptor, first, second, target_path)

    monkeypatch.setattr(v8_activation_module, "_exchange_entries", weaken_parent)
    try:
        with pytest.raises(V8ActivationError) as captured:
            apply_secret(str(tmp_path), preset, "replacement-secret", dry_run=False)

        assert captured.value.code == "parent_permissions_unsafe"
        assert raced
        assert dotenv.read_bytes() == original
        assert stat.S_IMODE(os.lstat(tmp_path).st_mode) == 0o777
        assert os.environ[preset.token_env] == "original-secret"
    finally:
        os.chmod(tmp_path, original_parent_mode)


@pytest.mark.skipif(os.name == "nt", reason="POSIX parent-mode regression")
def test_v8_secret_dotenv_parent_postcheck_never_clobbers_external_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preset = PRESETS["datadog"]
    monkeypatch.setenv(preset.token_env, "before-test")
    apply_secret(str(tmp_path), preset, "original-secret", dry_run=False)
    dotenv = tmp_path / ".env"
    external = b"EXTERNAL_AFTER_VERIFICATION=authoritative\n"
    external_path = tmp_path / "external.env"
    original_parent_mode = stat.S_IMODE(os.lstat(tmp_path).st_mode)
    real_assert_expected = v8_activation_module._assert_expected_file_state
    raced = False

    def race_after_verification(path, expected):
        nonlocal raced
        real_assert_expected(path, expected)
        if not raced and path == str(dotenv):
            raced = True
            external_path.write_bytes(external)
            os.chmod(external_path, 0o600)
            os.replace(external_path, dotenv)
            os.chmod(tmp_path, 0o777)

    monkeypatch.setattr(v8_activation_module, "_assert_expected_file_state", race_after_verification)
    try:
        with pytest.raises(V8ActivationError) as captured:
            apply_secret(str(tmp_path), preset, "replacement-secret", dry_run=False)

        assert captured.value.code == "parent_permissions_unsafe"
        assert raced
        assert dotenv.read_bytes() == external
        assert os.environ[preset.token_env] == "original-secret"
    finally:
        os.chmod(tmp_path, original_parent_mode)


def test_v8_secret_dotenv_incomplete_cas_rollback_retains_external_recovery_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preset = PRESETS["datadog"]
    monkeypatch.setenv(preset.token_env, "before-test")
    apply_secret(str(tmp_path), preset, "original-secret", dry_run=False)
    dotenv = tmp_path / ".env"
    concurrent = b"EXTERNAL_ROTATION=must-remain-recoverable\n"
    real_exchange = v8_activation_module._exchange_entries
    raced = False

    def race(parent_descriptor, first, second, target_path):
        nonlocal raced
        if not raced and target_path == str(dotenv):
            raced = True
            dotenv.write_bytes(concurrent)
        return real_exchange(parent_descriptor, first, second, target_path)

    monkeypatch.setattr(v8_activation_module, "_exchange_entries", race)
    monkeypatch.setattr(v8_activation_module, "_restore_displaced_exchange", lambda *_args: False)

    with pytest.raises(v8_activation_module.V8ActivationRollbackError) as captured:
        apply_secret(str(tmp_path), preset, "replacement-secret", dry_run=False)

    recovery = Path(captured.value.backup_directory or "")
    assert captured.value.code == "rollback_incomplete"
    assert raced
    assert recovery.parent == tmp_path
    assert recovery.exists()
    assert recovery.read_bytes() == concurrent
    assert b"replacement-secret" in dotenv.read_bytes()
    assert os.environ[preset.token_env] == "original-secret"
    recovery.unlink()


def test_v8_secret_dotenv_absent_target_cas_preserves_concurrent_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preset = PRESETS["datadog"]
    dotenv = tmp_path / ".env"
    concurrent = b"EXTERNAL_CREATION=preserve\n"
    real_preflight = v8_activation_module._preflight_atomic_replace

    def create_concurrently(*args, **kwargs) -> None:
        real_preflight(*args, **kwargs)
        dotenv.write_bytes(concurrent)

    monkeypatch.setattr(v8_activation_module, "_preflight_atomic_replace", create_concurrently)
    monkeypatch.setenv(preset.token_env, "before-test")

    with pytest.raises(V8ActivationError) as captured:
        apply_secret(str(tmp_path), preset, "replacement-secret", dry_run=False)

    assert captured.value.code == "source_changed"
    assert dotenv.read_bytes() == concurrent
    assert os.environ[preset.token_env] == "before-test"
    assert not list(tmp_path.glob("..env.observability-v8-*.tmp"))


def test_v8_secret_dotenv_directory_fsync_failure_retains_exact_original(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preset = PRESETS["datadog"]
    monkeypatch.setenv(preset.token_env, "before-test")
    apply_secret(str(tmp_path), preset, "original-secret", dry_run=False)
    dotenv = tmp_path / ".env"
    before = dotenv.read_bytes()
    before_stat = dotenv.stat()
    real_fsync = os.fsync
    failed = False

    def fail_publish_fsync(descriptor: int) -> None:
        nonlocal failed
        if not failed and stat.S_ISDIR(os.fstat(descriptor).st_mode) and b"replacement-secret" in dotenv.read_bytes():
            failed = True
            raise OSError(errno.EIO, "injected directory fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(v8_activation_module.os, "fsync", fail_publish_fsync)

    with pytest.raises(v8_activation_module.V8ActivationRollbackError) as captured:
        apply_secret(str(tmp_path), preset, "replacement-secret", dry_run=False)

    recovery = Path(captured.value.backup_directory or "")
    assert captured.value.code == "rollback_incomplete"
    assert captured.value.stage == "publication_commit"
    assert failed
    assert b"replacement-secret" in dotenv.read_bytes()
    assert recovery.read_bytes() == before
    recovery_stat = recovery.stat()
    assert (recovery_stat.st_uid, recovery_stat.st_gid) == (before_stat.st_uid, before_stat.st_gid)
    assert stat.S_IMODE(recovery_stat.st_mode) == stat.S_IMODE(before_stat.st_mode)
    assert os.environ[preset.token_env] == "original-secret"
    recovery.unlink()


def test_v8_secret_dotenv_parent_open_failure_propagates_without_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preset = PRESETS["datadog"]
    monkeypatch.setenv(preset.token_env, "before-test")
    apply_secret(str(tmp_path), preset, "original-secret", dry_run=False)
    dotenv = tmp_path / ".env"
    before = dotenv.read_bytes()
    real_open_parent = v8_activation_module._open_pinned_parent
    calls = 0

    def fail_actual_publish(snapshot):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError(errno.EIO, "injected parent open failure")
        return real_open_parent(snapshot)

    monkeypatch.setattr(v8_activation_module, "_open_pinned_parent", fail_actual_publish)

    with pytest.raises(OSError) as captured:
        apply_secret(str(tmp_path), preset, "replacement-secret", dry_run=False)

    assert captured.value.errno == errno.EIO
    assert dotenv.read_bytes() == before
    assert os.environ[preset.token_env] == "original-secret"
    assert not list(tmp_path.glob("..env.observability-v8-*.tmp"))


@pytest.mark.skipif(sys.platform != "darwin", reason="native macOS ACL regression")
def test_v8_secret_dotenv_named_acl_fails_closed_without_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preset = PRESETS["datadog"]
    dotenv = tmp_path / ".env"
    original = b"EXISTING=keep\n"
    dotenv.write_bytes(original)
    subprocess.run(["/bin/chmod", "+a", "everyone deny write", str(dotenv)], check=True)
    monkeypatch.setenv(preset.token_env, "before-test")
    try:
        with pytest.raises(V8ActivationError) as captured:
            apply_secret(str(tmp_path), preset, "replacement-secret", dry_run=False)
        assert captured.value.code == "acl_preservation_unsupported"
        assert dotenv.read_bytes() == original
        acl = subprocess.run(
            ["/bin/ls", "-le", str(dotenv)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        assert "everyone deny write" in acl
    finally:
        subprocess.run(["/bin/chmod", "-N", str(dotenv)], check=False)


@pytest.mark.skipif(sys.platform != "darwin", reason="native macOS metadata-CAS regression")
@pytest.mark.parametrize("drift", ["acl", "flags"])
def test_v8_secret_dotenv_final_window_rejects_macos_metadata_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    preset = PRESETS["datadog"]
    monkeypatch.setenv(preset.token_env, "before-test")
    apply_secret(str(tmp_path), preset, "original-secret", dry_run=False)
    dotenv = tmp_path / ".env"
    original = dotenv.read_bytes()
    original_flags = os.lstat(dotenv).st_flags
    real_exchange = v8_activation_module._exchange_entries
    raced = False

    def add_metadata(parent_descriptor, first, second, target_path):
        nonlocal raced
        if not raced and target_path == str(dotenv):
            raced = True
            if drift == "acl":
                subprocess.run(["/bin/chmod", "+a", "everyone deny write", str(dotenv)], check=True)
            else:
                os.chflags(dotenv, original_flags | stat.UF_NODUMP)
        return real_exchange(parent_descriptor, first, second, target_path)

    monkeypatch.setattr(v8_activation_module, "_exchange_entries", add_metadata)
    try:
        with pytest.raises(V8ActivationError) as captured:
            apply_secret(str(tmp_path), preset, "replacement-secret", dry_run=False)

        assert captured.value.code == "source_changed"
        assert raced
        assert dotenv.read_bytes() == original
        if drift == "acl":
            acl = subprocess.run(
                ["/bin/ls", "-le", str(dotenv)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            assert "everyone deny write" in acl
        else:
            assert os.lstat(dotenv).st_flags & stat.UF_NODUMP
        assert os.environ[preset.token_env] == "original-secret"
    finally:
        subprocess.run(["/bin/chmod", "-N", str(dotenv)], check=False)
        os.chflags(dotenv, original_flags)


@pytest.mark.skipif(sys.platform != "darwin", reason="native macOS parent-ACL regression")
def test_v8_secret_dotenv_parent_acl_drift_cannot_return_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preset = PRESETS["datadog"]
    monkeypatch.setenv(preset.token_env, "before-test")
    apply_secret(str(tmp_path), preset, "original-secret", dry_run=False)
    dotenv = tmp_path / ".env"
    original = dotenv.read_bytes()
    real_exchange = v8_activation_module._exchange_entries
    raced = False

    def weaken_parent(parent_descriptor, first, second, target_path):
        nonlocal raced
        if not raced and target_path == str(dotenv):
            raced = True
            subprocess.run(["/bin/chmod", "+a", "everyone allow add_file", str(tmp_path)], check=True)
        return real_exchange(parent_descriptor, first, second, target_path)

    monkeypatch.setattr(v8_activation_module, "_exchange_entries", weaken_parent)
    try:
        with pytest.raises(V8ActivationError) as captured:
            apply_secret(str(tmp_path), preset, "replacement-secret", dry_run=False)

        assert captured.value.code == "parent_acl_unsafe"
        assert raced
        assert dotenv.read_bytes() == original
        assert os.environ[preset.token_env] == "original-secret"
    finally:
        subprocess.run(["/bin/chmod", "-N", str(tmp_path)], check=False)


def test_v8_secret_dry_run_sanitizes_and_reports_selected_data_dir(tmp_path: Path) -> None:
    selected = tmp_path / "selected-data"
    selected.mkdir()
    preset = PRESETS["datadog"]

    with pytest.raises(DotenvValueError):
        apply_secret(
            str(selected),
            preset,
            "token\nINJECTED=1",
            dry_run=True,
        )

    warnings = apply_secret(str(selected), preset, "safe-token", dry_run=True)
    assert warnings == [f"{preset.token_env}: (would write to {selected / '.env'})"]
    assert not (selected / ".env").exists()


def test_splunk_verify_tls_rejects_non_boolean_input() -> None:
    with pytest.raises(ValueError, match="verify_tls must be a boolean"):
        _build_v8_preset_destination(
            PRESETS["splunk-enterprise"],
            {
                "endpoint": "https://splunk.example.test:8088/services/collector/event",
                "verify_tls": "definitely",
            },
            name="splunk",
            enabled=True,
            signals=None,
            target=None,
        )


def test_v8_source_destination_index_uses_authored_not_generated_order(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(_source())
    assert _v8_source_destination_index(str(tmp_path), "terminal") == 0
    assert _v8_source_destination_index(str(tmp_path), "archive") == 1
    with pytest.raises(click.ClickException, match="mandatory"):
        _v8_source_destination_index(str(tmp_path), "local-sqlite")
    with pytest.raises(click.ClickException, match="terminal, archive|archive, terminal"):
        _v8_source_destination_index(str(tmp_path), "missing")


def test_v8_enable_mutates_exact_source_index() -> None:
    result = V8PolicyWriteResult(True, "a" * 64, "b" * 64)
    with (
        patch(
            "defenseclaw.commands.cmd_setup_observability._v8_source_destination_index",
            return_value=3,
        ),
        patch(
            "defenseclaw.observability.v8_writer.mutate_v8_config",
            return_value=result,
        ) as mutate,
    ):
        _set_v8_destination_enabled("/tmp/dc", "collector", True, "")
    args, kwargs = mutate.call_args
    assert str(args[0]).endswith("/tmp/dc/config.yaml")
    assert args[1][0].path == ("observability", "destinations", 3, "enabled")
    assert args[1][0].value is True
    assert kwargs == {"data_dir": "/tmp/dc"}


def test_v8_remove_mutates_exact_source_index_and_rejects_connector_scope() -> None:
    result = V8PolicyWriteResult(True, "a" * 64, "b" * 64)
    with (
        patch(
            "defenseclaw.commands.cmd_setup_observability._v8_source_destination_index",
            return_value=1,
        ),
        patch(
            "defenseclaw.observability.v8_writer.mutate_v8_config",
            return_value=result,
        ) as mutate,
    ):
        _remove_v8_destination("/tmp/dc", "archive", "")
    mutation = mutate.call_args.args[1][0]
    assert mutation.path == ("observability", "destinations", 1)
    with pytest.raises(click.ClickException, match="process-wide"):
        _remove_v8_destination("/tmp/dc", "archive", "codex")


@pytest.mark.parametrize("emit_json", [False, True])
def test_v8_destination_list_exposes_signals_policy_and_unredacted_default(emit_json: bool) -> None:
    @click.command()
    def command() -> None:
        _print_v8_destination_list(_status(), emit_json=emit_json)

    result = CliRunner().invoke(command)
    assert result.exit_code == 0, result.output
    if emit_json:
        rows = json.loads(result.output)
        assert rows[1]["signals"] == ["logs", "traces", "metrics"]
        assert rows[1]["redaction"] == "unredacted (none)"
        assert rows[1]["bucket_count"] == 1
    else:
        assert "capability_default" in result.output
        assert "logs,traces,metrics" in result.output
        assert "unredacted (none)" in result.output
        assert "Retention: 90 days" in result.output


@pytest.mark.parametrize(
    ("preset_id", "inputs"),
    [
        ("splunk-o11y", {"realm": "us1"}),
        (
            "splunk-hec",
            {
                "host": "localhost",
                "port": "8088",
                "index": "defenseclaw",
                "source": "defenseclaw",
                "sourcetype": "_json",
            },
        ),
        (
            "splunk-enterprise",
            {
                "endpoint": "https://splunk.example.test:8088/services/collector/event",
                "index": "defenseclaw",
                "source": "defenseclaw",
                "sourcetype": "_json",
            },
        ),
        ("datadog", {"site": "us5"}),
        ("honeycomb", {"dataset": "defenseclaw"}),
        ("newrelic", {"region": "us"}),
        ("grafana-cloud", {"region": "prod-us-east-0"}),
        (
            "galileo",
            {
                "endpoint": "https://api.galileo.ai/otel/traces",
                "project": "defenseclaw",
                "logstream": "default",
            },
        ),
        ("local-otlp", {"endpoint": "127.0.0.1:4317"}),
        ("otlp", {"endpoint": "collector.example.test:4317", "protocol": "grpc"}),
        ("webhook", {"url": "https://example.test/events", "method": "POST"}),
    ],
)
def test_every_setup_preset_builds_a_schema_valid_v8_destination(
    preset_id: str,
    inputs: dict[str, str],
) -> None:
    destination = _build_v8_preset_destination(
        PRESETS[preset_id],
        inputs,
        name="target",
        enabled=True,
        signals=None,
        target=None,
    )
    validated = load_validate_v8(
        {
            "config_version": 8,
            "observability": {"destinations": [destination]},
        }
    ).source
    assert validated["observability"]["destinations"][0]["name"] == "target"


def test_v8_otlp_default_is_all_capabilities_unredacted_and_explicit_signals_narrow() -> None:
    preset = PRESETS["otlp"]
    default = _build_v8_preset_destination(
        preset,
        {"endpoint": "collector.example.test:4317", "protocol": "grpc"},
        name="all-signals",
        enabled=True,
        signals=None,
        target=None,
    )
    assert "send" not in default

    narrowed = _build_v8_preset_destination(
        preset,
        {"endpoint": "collector.example.test:4317", "protocol": "grpc"},
        name="logs-only",
        enabled=True,
        signals=("logs",),
        target=None,
    )
    assert narrowed["send"] == {
        "signals": ["logs"],
        "buckets": ["*"],
        "redaction_profile": "none",
    }


def test_v8_explicit_signal_update_removes_stale_signal_overrides() -> None:
    existing = {
        "name": "datadog",
        "kind": "otlp",
        "signal_overrides": {
            "logs": {"path": "/v1/logs"},
            "traces": {"path": "/v1/traces"},
            "metrics": {"path": "/v1/metrics"},
        },
    }
    narrowed = _build_v8_preset_destination(
        PRESETS["datadog"],
        {"site": "us5"},
        name="datadog",
        enabled=True,
        signals=("logs",),
        target=None,
    )
    mutations = _v8_destination_update_mutations(0, existing, narrowed)
    deleted = {mutation.path for mutation in mutations if mutation.value is DELETE}
    assert deleted == {
        ("observability", "destinations", 0, "signal_overrides", "traces"),
        ("observability", "destinations", 0, "signal_overrides", "metrics"),
    }


def test_v8_galileo_is_trace_only_and_uses_secret_reference() -> None:
    preset = PRESETS["galileo"]
    destination = _build_v8_preset_destination(
        preset,
        {
            "endpoint": "https://api.galileo.ai/otel/traces",
            "project": "project",
            "logstream": "stream",
        },
        name="galileo",
        enabled=True,
        signals=("traces",),
        target=None,
    )
    assert destination["preset"] == "galileo"
    assert destination["batch"] == {"scheduled_delay_ms": 1000}
    assert destination["headers"]["Galileo-API-Key"] == {"env": "GALILEO_API_KEY"}
    assert "send" not in destination
    with pytest.raises(ValueError, match="traces only"):
        _build_v8_preset_destination(
            preset,
            {
                "endpoint": "https://api.galileo.ai/otel/traces",
                "project": "project",
                "logstream": "stream",
            },
            name="galileo",
            enabled=True,
            signals=("logs",),
            target=None,
        )


def test_v8_galileo_update_deletes_only_prior_generated_concise_send() -> None:
    existing = {
        "name": "galileo",
        "kind": "otlp",
        "preset": "galileo",
        "send": {
            "signals": ["traces"],
            "buckets": ["*"],
            "redaction_profile": "none",
        },
    }
    desired = _build_v8_preset_destination(
        PRESETS["galileo"],
        {
            "endpoint": "https://api.galileo.ai/otel/traces",
            "project": "project",
            "logstream": "stream",
        },
        name="galileo",
        enabled=True,
        signals=("traces",),
        target=None,
    )

    mutations = _v8_destination_update_mutations(0, existing, desired)

    deleted = {mutation.path for mutation in mutations if mutation.value is DELETE}
    assert deleted == {("observability", "destinations", 0, "send")}


@pytest.mark.parametrize(
    "existing_policy",
    [
        {
            "send": {
                "signals": ["traces"],
                "buckets": ["security.enforcement"],
                "redaction_profile": "sensitive",
            }
        },
        {
            "routes": [
                {
                    "name": "selected-traces",
                    "action": "send",
                    "signals": ["traces"],
                    "selector": {"buckets": ["security.enforcement"]},
                    "redaction_profile": "sensitive",
                }
            ]
        },
    ],
)
def test_v8_galileo_update_preserves_operator_authored_policy(
    existing_policy: dict[str, object],
) -> None:
    existing = {
        "name": "galileo",
        "kind": "otlp",
        "preset": "galileo",
        **existing_policy,
    }
    desired = _build_v8_preset_destination(
        PRESETS["galileo"],
        {
            "endpoint": "https://api.galileo.ai/otel/traces",
            "project": "project",
            "logstream": "stream",
        },
        name="galileo",
        enabled=True,
        signals=("traces",),
        target=None,
    )

    mutations = _v8_destination_update_mutations(0, existing, desired)

    policy_paths = {mutation.path for mutation in mutations if mutation.path[3] in {"send", "routes"}}
    assert policy_paths == set()


def test_setup_v8_destination_test_uses_canonical_local_evidence_path() -> None:
    inspected = SimpleNamespace(
        effective={"destinations": []},
        source="/tmp/dc/config.yaml",
        data_dir="/tmp/dc",
    )
    result = SimpleNamespace(
        destination="collector",
        mode="write_probe",
        protocol="grpc",
        endpoint_count=1,
        probe_id="probe-123",
    )
    with (
        patch(
            "defenseclaw.config_inspect.inspect_v8_config",
            return_value=inspected,
        ),
        patch(
            "defenseclaw.observability.destination_test.canonical_local_compliance_recorder",
            return_value="recorder",
        ) as recorder,
        patch(
            "defenseclaw.observability.destination_test.run_destination_test",
            return_value=result,
        ) as run,
    ):
        _test_v8_destination("/tmp/dc", "collector", 3.0, write_probe=True)
    recorder.assert_called_once_with(
        config_path="/tmp/dc/config.yaml",
        data_dir="/tmp/dc",
    )
    assert run.call_args.kwargs["write_probe"] is True
    assert run.call_args.kwargs["compliance"] == "recorder"
