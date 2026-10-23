"""Predecessor Codex root migrations must precheck the selected root."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import click
import pytest
from click.testing import CliRunner
from defenseclaw import config_writer
from defenseclaw.commands import cmd_setup
from defenseclaw.context import AppContext
from defenseclaw.file_permissions import atomic_write_private_bytes

from tests.helpers import cleanup_app, make_app_context
from tests.permissions import set_known_windows_directory_acl


def _mkdir_owned(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        # Elevated Windows tokens can create scratch dirs under Administrators.
        set_known_windows_directory_acl(path)


def test_codex_rollback_does_not_rebase_a_populated_previous_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    old_home = tmp_path / "old-home"
    current_home = tmp_path / "current-home"
    old_path = old_home / ".codex" / "config.toml"
    _mkdir_owned(old_path.parent)
    _mkdir_owned(current_home / ".codex")
    (old_home / ".profile").write_text("kept", encoding="utf-8")
    installed = b"hooks = true\n"
    atomic_write_private_bytes(old_path, installed)
    atomic_write_private_bytes(current_home / ".codex" / "config.toml", installed)
    monkeypatch.setenv("HOME", str(current_home))
    monkeypatch.setenv("USERPROFILE", str(current_home))
    record = current_home / ".defenseclaw" / "connector_backups" / "codex" / "config.toml.json"
    assert cmd_setup._effective_codex_rollback_path(
        str(record), str(old_path), installed_sha256=hashlib.sha256(installed).hexdigest()
    ) == str(old_path)


def test_exact_runtime_rollback_reverses_codex_root_before_verification(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    profile_dir = tmp_path / "profile"
    _mkdir_owned(profile_dir)
    app, profile, db_path = make_app_context(str(profile_dir))
    try:
        old_root = tmp_path / "old-codex"
        new_root = tmp_path / "new-codex"
        _mkdir_owned(old_root)
        _mkdir_owned(new_root)
        old_path = old_root / "config.toml"
        new_path = new_root / "config.toml"
        backup_path = Path(app.cfg.data_dir) / "connector_backups" / "codex" / "config.toml.json"
        _mkdir_owned(backup_path.parent)
        lock_path = Path(app.cfg.data_dir) / "hook_contract_lock.json"

        def backup(path: Path) -> bytes:
            return json.dumps({
                "version": 1, "connector": "codex", "logical_name": "config.toml",
                "path": str(path), "existed": False, "pristine_sha256": "missing",
            }).encode()

        def lock(path: Path) -> bytes:
            return json.dumps({
                "version": 2,
                "connectors": {"codex": {"locations": {"hook_config_paths": [str(path)]}}},
            }).encode()

        old_backup = backup(old_path)
        old_lock = lock(old_path)
        atomic_write_private_bytes(old_path, b"old hooks")
        atomic_write_private_bytes(backup_path, old_backup)
        atomic_write_private_bytes(lock_path, old_lock)
        app.cfg.guardrail.connector = "codex"
        app.cfg.claw.mode = "codex"
        snapshot = cmd_setup._capture_setup_config_snapshot(app.cfg, capture_codex_backup=True)
        snapshot = replace(
            snapshot,
            applied_runtime=cmd_setup._SetupAppliedRuntimeEvidence("running", "before", ()),
        )
        atomic_write_private_bytes(old_path, b"old root without hooks")
        atomic_write_private_bytes(new_path, b"new hooks")
        atomic_write_private_bytes(backup_path, backup(new_path))
        atomic_write_private_bytes(lock_path, lock(new_path))
        monkeypatch.setenv("CODEX_HOME", str(new_root))
        monkeypatch.setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", str(new_root))
        monkeypatch.setattr(cmd_setup, "_capture_failed_setup_registration_locations", lambda _cfg: ())
        monkeypatch.setattr(cmd_setup, "_verify_restored_setup_runtime", lambda *_a: [])

        def restore_lifecycle(*_args: object) -> None:
            assert os.environ["CODEX_HOME"] == str(old_root)
            assert os.environ["DEFENSECLAW_EXPLICIT_CODEX_SETUP"] == str(old_root)
            atomic_write_private_bytes(old_path, b"old hooks")
            atomic_write_private_bytes(new_path, b"new root without hooks")
            atomic_write_private_bytes(backup_path, old_backup)
            atomic_write_private_bytes(lock_path, old_lock)

        monkeypatch.setattr(cmd_setup, "_restore_prior_setup_lifecycle", restore_lifecycle)
        with pytest.raises(click.ClickException, match="restored the prior connector configuration and runtime"):
            cmd_setup._rollback_failed_connector_application(app, snapshot, RuntimeError("peer failed readiness"))
        assert old_path.read_bytes() == b"old hooks"
        assert new_path.read_bytes() == b"new root without hooks"
        assert backup_path.read_bytes() == old_backup
        assert os.environ["CODEX_HOME"] == str(new_root)
        assert os.environ["DEFENSECLAW_EXPLICIT_CODEX_SETUP"] == str(new_root)
    finally:
        cleanup_app(app, db_path, profile)


@pytest.mark.parametrize("predecessor", ("1.0.2", "1.0.3"))
@pytest.mark.parametrize("rollback_republishes", (True, False))
def test_failed_batch_restores_previous_codex_root_and_backup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, predecessor: str, rollback_republishes: bool,
) -> None:
    profile_dir = tmp_path / "profile"
    _mkdir_owned(profile_dir)
    app, profile, db_path = make_app_context(str(profile_dir))
    try:
        old_root = tmp_path / "old-codex"
        new_root = tmp_path / "new-codex"
        _mkdir_owned(old_root)
        _mkdir_owned(new_root)
        old_path = old_root / "config.toml"
        new_path = new_root / "config.toml"
        fixture = (
            Path(__file__).resolve().parents[2]
            / "internal/gateway/connector/testdata/predecessor_1_0_2_1_0_3/codex.toml"
        ).read_text(encoding="utf-8")
        old_hooks = fixture.replace("{home}", str(tmp_path)).replace("{data_dir}", app.cfg.data_dir).encode()
        old_pristine = b'model = "sample"\n'
        new_pristine = b'model = "new sample"\n'
        new_hooks = new_pristine + b'\n[hooks]\n# DefenseClaw registration\n'
        atomic_write_private_bytes(old_path, old_hooks)
        atomic_write_private_bytes(new_path, new_pristine)
        backup_path = Path(app.cfg.data_dir) / "connector_backups" / "codex" / "config.toml.json"
        _mkdir_owned(backup_path.parent)

        def backup_for(path: Path, pristine: bytes, installed: bytes) -> bytes:
            return (json.dumps({
                "version": 1,
                "connector": "codex",
                "logical_name": "config.toml",
                "path": str(path),
                "existed": True,
                "mode": 384,
                "pristine_sha256": hashlib.sha256(pristine).hexdigest(),
                "pristine_bytes": base64.b64encode(pristine).decode("ascii"),
                "post_sha256": hashlib.sha256(installed).hexdigest(),
                "captured_at": f"{predecessor} predecessor",
            }) + "\n").encode()

        old_backup = backup_for(old_path, old_pristine, old_hooks)
        atomic_write_private_bytes(backup_path, old_backup)
        lock_path = Path(app.cfg.data_dir) / "hook_contract_lock.json"

        def publish_lock(path: Path) -> None:
            atomic_write_private_bytes(lock_path, json.dumps({
                "version": 2,
                "connectors": {"codex": {"locations": {"hook_config_paths": [str(path)]}}},
            }).encode())

        publish_lock(old_path)
        app.cfg.guardrail.connector = "codex"
        app.cfg.claw.mode = "codex"
        monkeypatch.setenv("CODEX_HOME", str(new_root))
        monkeypatch.setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", str(old_root))
        # The gateway lifecycle is simulated here; native Windows exact-runtime
        # reconciliation has its own tests with a real runtime evidence point.
        monkeypatch.setattr(cmd_setup, "_windows_runtime_rollback", lambda _restart: False)
        monkeypatch.setattr(cmd_setup, "_agent_settings_refusal", lambda *_a, **_k: "")
        monkeypatch.setattr(cmd_setup, "_check_connector_version_supported_for_setup", lambda *_a, **_k: True)
        monkeypatch.setattr(cmd_setup.agent_discovery, "discover_with_probes", lambda *_a, **_k: object())
        monkeypatch.setattr(cmd_setup.agent_discovery, "_write_cache", lambda *_a, **_k: True)
        monkeypatch.setattr(cmd_setup, "_record_windows_setup_agent_selections", lambda *_a, **_k: None)
        monkeypatch.setattr(cmd_setup, "_apply_hook_connector_setup", lambda *_a, **_k: True)
        monkeypatch.setattr(cmd_setup, "_echo_batch_setup_summary", lambda *_a, **_k: None)
        restarts = 0

        def restart(*_args: object, **_kwargs: object) -> None:
            nonlocal restarts
            restarts += 1
            marker = os.environ.get("DEFENSECLAW_EXPLICIT_CODEX_SETUP")
            selected = Path(os.environ["CODEX_HOME"])
            if marker != str(selected):
                selected = Path(json.loads(backup_path.read_bytes())["path"]).parent
            if restarts == 1:
                assert selected == new_root
                atomic_write_private_bytes(old_path, old_pristine)
                atomic_write_private_bytes(new_path, new_hooks)
                atomic_write_private_bytes(backup_path, backup_for(new_path, new_pristine, new_hooks))
                publish_lock(new_path)
                raise RuntimeError("another required connector failed readiness")
            assert selected == old_root, "rollback must restart against the previous Codex root"
            if not rollback_republishes:
                return
            atomic_write_private_bytes(new_path, new_pristine)
            atomic_write_private_bytes(old_path, old_hooks)
            atomic_write_private_bytes(backup_path, old_backup)
            publish_lock(old_path)

        monkeypatch.setattr(cmd_setup, "_restart_services", restart)
        result = CliRunner().invoke(
            cmd_setup.setup, ["-c", "codex", "-c", "cursor", "--yes"], obj=app,
            catch_exceptions=False,
        )
        assert result.exit_code == 1
        if rollback_republishes:
            assert "restored the prior connector configuration and runtime" in result.output
        else:
            assert "rollback was incomplete" in result.output
            assert "Codex managed backup still names the new root" in result.output

        assert restarts == 2
        if rollback_republishes:
            assert old_path.read_bytes() == old_hooks
            assert new_path.read_bytes() == new_pristine
            assert backup_path.read_bytes() == old_backup
            assert json.loads(lock_path.read_bytes())["connectors"]["codex"]["locations"]["hook_config_paths"] == [
                str(old_path)
            ]
        assert os.environ["CODEX_HOME"] == str(new_root)
        assert os.environ["DEFENSECLAW_EXPLICIT_CODEX_SETUP"] == str(old_root)
    finally:
        cleanup_app(app, db_path, profile)


@pytest.mark.parametrize("predecessor", ("1.0.2", "1.0.3"))
@pytest.mark.parametrize("old_home_state", ("removed", "empty", "unrelated", "empty-codex"))
@pytest.mark.parametrize("restore_receipts", (True, False))
def test_failed_batch_after_home_move_keeps_codex_hooks_in_current_home(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    predecessor: str,
    old_home_state: str,
    restore_receipts: bool,
) -> None:
    old_home = tmp_path / "old-home"
    current_home = tmp_path / "current-home"
    old_root = old_home / ".codex"
    _mkdir_owned(old_root)
    old_path = old_root / "config.toml"
    fixture = (
        Path(__file__).resolve().parents[2]
        / "internal/gateway/connector/testdata/predecessor_1_0_2_1_0_3/codex.toml"
    ).read_text(encoding="utf-8")
    old_hooks = fixture.replace("{home}", str(old_home)).replace("{data_dir}", str(old_home / ".defenseclaw")).encode()
    current_hooks = fixture.replace("{home}", str(current_home)).replace(
        "{data_dir}", str(current_home / ".defenseclaw")
    ).encode()
    original_pristine = b'model = "original"\n'
    atomic_write_private_bytes(old_path, old_hooks)
    data_dir = old_home / ".defenseclaw"
    _mkdir_owned(data_dir)
    backup_path = data_dir / "connector_backups" / "codex" / "config.toml.json"
    _mkdir_owned(backup_path.parent)
    lock_path = data_dir / "hook_contract_lock.json"

    def backup_for(path: Path, pristine: bytes, installed: bytes) -> bytes:
        return (json.dumps({
            "version": 1, "connector": "codex", "logical_name": "config.toml",
            "path": str(path), "existed": True, "mode": 384,
            "pristine_sha256": hashlib.sha256(pristine).hexdigest(),
            "pristine_bytes": base64.b64encode(pristine).decode("ascii"),
            "post_sha256": hashlib.sha256(installed).hexdigest(),
            "captured_at": f"{predecessor} predecessor",
        }) + "\n").encode()

    def lock_for(path: Path) -> bytes:
        return json.dumps({
            "version": 2,
            "connectors": {"codex": {"locations": {"hook_config_paths": [str(path)]}}},
        }).encode()

    atomic_write_private_bytes(backup_path, backup_for(old_path, original_pristine, old_hooks))
    atomic_write_private_bytes(lock_path, lock_for(old_path))
    old_home.rename(current_home)
    if old_home_state != "removed":
        _mkdir_owned(old_home)
    if old_home_state == "unrelated":
        (old_home / ".profile").write_text("retained", encoding="utf-8")
    if old_home_state == "empty-codex":
        _mkdir_owned(old_root)
    current_root = current_home / ".codex"
    current_path = current_root / "config.toml"
    next_root = tmp_path / "next-codex"
    _mkdir_owned(next_root)
    next_path = next_root / "config.toml"
    next_hooks = fixture.replace("{home}", str(tmp_path)).replace(
        "{data_dir}", str(current_home / ".defenseclaw")
    ).encode()
    atomic_write_private_bytes(current_path, current_hooks)
    atomic_write_private_bytes(
        current_home / ".defenseclaw" / "connector_backups" / "codex" / "config.toml.json",
        backup_for(old_path, original_pristine, current_hooks),
    )
    monkeypatch.setenv("HOME", str(current_home))
    monkeypatch.setenv("USERPROFILE", str(current_home))
    monkeypatch.setenv("CODEX_HOME", str(next_root))
    monkeypatch.setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", str(next_root))
    # The fixture is an isolated per-user install even on a managed CI host.
    monkeypatch.setattr(config_writer, "machine_managed_standalone", lambda: False)
    app, profile, db_path = make_app_context(str(current_home / ".defenseclaw"))
    try:
        app.cfg.guardrail.connector = "codex"
        app.cfg.claw.mode = "codex"
        app.cfg.save()
        backup_path = current_home / ".defenseclaw" / "connector_backups" / "codex" / "config.toml.json"
        lock_path = current_home / ".defenseclaw" / "hook_contract_lock.json"
        monkeypatch.setattr(cmd_setup, "_windows_runtime_rollback", lambda _restart: False)
        monkeypatch.setattr(cmd_setup, "_agent_settings_refusal", lambda *_a, **_k: "")
        monkeypatch.setattr(cmd_setup, "_check_connector_version_supported_for_setup", lambda *_a, **_k: True)
        monkeypatch.setattr(cmd_setup.agent_discovery, "discover_with_probes", lambda *_a, **_k: object())
        monkeypatch.setattr(cmd_setup.agent_discovery, "_write_cache", lambda *_a, **_k: True)
        monkeypatch.setattr(cmd_setup, "_record_windows_setup_agent_selections", lambda *_a, **_k: None)
        monkeypatch.setattr(cmd_setup, "_apply_hook_connector_setup", lambda *_a, **_k: True)
        monkeypatch.setattr(cmd_setup, "_echo_batch_setup_summary", lambda *_a, **_k: None)
        restarts = 0

        def restart(*_args: object, **_kwargs: object) -> None:
            nonlocal restarts
            restarts += 1
            selected_root = Path(os.environ["CODEX_HOME"])
            assert os.environ["DEFENSECLAW_EXPLICIT_CODEX_SETUP"] == str(selected_root)
            if restarts == 1:
                assert selected_root == next_root
                atomic_write_private_bytes(current_path, original_pristine)
                atomic_write_private_bytes(next_path, next_hooks)
                atomic_write_private_bytes(backup_path, backup_for(next_path, original_pristine, next_hooks))
                atomic_write_private_bytes(lock_path, lock_for(next_path))
                raise RuntimeError("another required connector failed readiness")
            if selected_root != current_root:
                # The Go migration tears down the repaired registration and
                # recreates it wherever the explicit rollback marker points.
                _mkdir_owned(selected_root)
                atomic_write_private_bytes(selected_root / "config.toml", old_hooks)
            else:
                atomic_write_private_bytes(current_path, current_hooks)
            atomic_write_private_bytes(next_path, original_pristine)
            if restore_receipts or selected_root != current_root:
                installed = old_hooks if selected_root != current_root else current_hooks
                atomic_write_private_bytes(backup_path, backup_for(selected_root / "config.toml", original_pristine, installed))
                atomic_write_private_bytes(lock_path, lock_for(selected_root / "config.toml"))
            else:
                # A successful hook restart must not hide receipts that Go
                # cannot resolve after a partly copied account home move.
                atomic_write_private_bytes(backup_path, backup_for(old_path, original_pristine, current_hooks))
                atomic_write_private_bytes(lock_path, lock_for(old_path))

        monkeypatch.setattr(cmd_setup, "_restart_services", restart)
        result = CliRunner().invoke(
            cmd_setup.setup, ["-c", "codex", "-c", "cursor", "--yes"], obj=app,
            catch_exceptions=False,
        )
        assert result.exit_code == 1
        unresolved_receipts = not restore_receipts and old_home_state in ("unrelated", "empty-codex")
        if unresolved_receipts:
            assert "rollback was incomplete" in result.output, result.output
            assert "Codex managed backup still names the new root" in result.output
        else:
            assert "restored the prior connector configuration and runtime" in result.output, result.output
            assert "rollback was incomplete" not in result.output
        assert restarts == 2
        assert current_path.read_bytes() == current_hooks
        assert next_path.read_bytes() == original_pristine
        expected_receipt = old_path if not restore_receipts else current_path
        assert json.loads(backup_path.read_bytes())["path"] == str(expected_receipt)
        assert json.loads(lock_path.read_bytes())["connectors"]["codex"]["locations"]["hook_config_paths"] == [
            str(expected_receipt)
        ]
        assert not old_path.exists()
    finally:
        cleanup_app(app, db_path, profile)


@pytest.mark.parametrize("predecessor", ("1.0.2", "1.0.3"))
@pytest.mark.parametrize("refusing_root", ("old", "new"))
def test_predecessor_codex_root_migration_checks_selected_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    predecessor: str,
    refusing_root: str,
) -> None:
    # The tagged 1.0.2 and 1.0.3 registrations have identical TOML bytes.
    fixture = (
        Path(__file__).resolve().parents[2]
        / "internal/gateway/connector/testdata/predecessor_1_0_2_1_0_3/codex.toml"
    ).read_text(encoding="utf-8")
    old_root = tmp_path / "old-codex"
    new_root = tmp_path / "new-codex"
    old_root.mkdir()
    new_root.mkdir()
    old_settings = fixture.replace("{home}", str(tmp_path)).replace("{data_dir}", str(tmp_path / "data"))
    if refusing_root == "old":
        old_settings += "\n[features]\nhooks = false\n"
    (old_root / "config.toml").write_text(old_settings, encoding="utf-8")
    (new_root / "config.toml").write_text(
        "[features]\nhooks = false\n" if refusing_root == "new" else "[features]\nhooks = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CODEX_HOME", str(new_root))
    monkeypatch.setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", str(old_root))
    monkeypatch.setattr(cmd_setup, "_gateway_lifecycle_executable", lambda: "/opt/dc/defenseclaw-gateway")
    touched: list[str] = []
    selected_roots: list[Path] = []

    def check(_argv: list[str], **kwargs: object) -> SimpleNamespace:
        env = kwargs["env"]
        assert isinstance(env, dict)
        # Existing Codex registrations pin the old root unless this child
        # receives the same explicit migration marker as the gateway restart.
        selected = (
            new_root
            if env.get("CODEX_HOME") == str(new_root)
            and env.get("DEFENSECLAW_EXPLICIT_CODEX_SETUP") == str(new_root)
            else old_root
        )
        selected_roots.append(selected)
        refused = "hooks = false" in (selected / "config.toml").read_text(encoding="utf-8")
        payload = {
            "connector": "codex",
            "action": "check-agent-settings",
            "refused": refused,
            "reason": f"Codex config {selected / 'config.toml'} turns hooks off" if refused else "",
        }
        return SimpleNamespace(returncode=1 if refused else 0, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(cmd_setup, "run_pinned_executable", check)
    monkeypatch.setattr(
        cmd_setup,
        "_check_connector_version_supported_for_setup",
        lambda *_args, **_kwargs: touched.append("version") or False,
    )
    monkeypatch.setattr(
        cmd_setup,
        "_capture_setup_config_snapshot",
        lambda *_args, **_kwargs: touched.append("snapshot"),
    )
    monkeypatch.setattr(cmd_setup, "_restart_services", lambda *_args, **_kwargs: touched.append("restart"))
    app = SimpleNamespace(cfg=SimpleNamespace(data_dir=str(tmp_path / "data")))
    assert not cmd_setup._apply_hook_connector_setup(app, connector="codex", mode="action", restart=True)
    assert selected_roots == [new_root]
    assert touched == ([] if refusing_root == "new" else ["version"])
    assert (old_root / "config.toml").read_text(encoding="utf-8") == old_settings


@pytest.mark.parametrize("predecessor", ("1.0.2", "1.0.3"))
@pytest.mark.parametrize("restart_fails", (False, True))
def test_batch_codex_root_upgrade_uses_selected_root_only_for_forward_restart(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    predecessor: str,
    restart_fails: bool,
) -> None:
    old_root = tmp_path / "old-codex"
    new_root = tmp_path / "new-codex"
    old_root.mkdir()
    new_root.mkdir()
    fixture = (
        Path(__file__).resolve().parents[2]
        / "internal/gateway/connector/testdata/predecessor_1_0_2_1_0_3/codex.toml"
    ).read_text(encoding="utf-8")
    (old_root / "config.toml").write_text(fixture, encoding="utf-8")
    (new_root / "config.toml").write_text("[features]\nhooks = true\n", encoding="utf-8")
    monkeypatch.setenv("CODEX_HOME", str(new_root))
    monkeypatch.setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", str(old_root))

    app = AppContext()
    app.cfg = SimpleNamespace(
        data_dir=str(tmp_path / "data"),
        gateway=SimpleNamespace(host="127.0.0.1", port=18970),
        active_connector=lambda: "codex",
    )
    ctx = click.Context(cmd_setup.setup, obj=app)
    ctx.meta[cmd_setup._SETUP_BATCH_READINESS_KEY] = ("codex",)
    ctx.meta[cmd_setup._SETUP_BATCH_REQUIRED_KEY] = ("codex",)
    ctx.meta[cmd_setup._SETUP_BATCH_AUDIT_KEY] = ()
    # Only the type gate is used because the rollback body is intercepted.
    ctx.meta[cmd_setup._SETUP_BATCH_ROLLBACK_KEY] = object.__new__(cmd_setup._SetupConfigSnapshot)
    forward: list[str | None] = []
    rollback: list[str | None] = []

    def restart(*_args: object, **_kwargs: object) -> None:
        forward.append(os.environ.get("DEFENSECLAW_EXPLICIT_CODEX_SETUP"))
        if restart_fails:
            raise RuntimeError("forward restart failed")

    def restore(*_args: object, **_kwargs: object) -> None:
        rollback.append(os.environ.get("DEFENSECLAW_EXPLICIT_CODEX_SETUP"))

    monkeypatch.setattr(cmd_setup, "_restart_services", restart)
    monkeypatch.setattr(cmd_setup, "_rollback_failed_connector_application", restore)
    with ctx:
        if restart_fails:
            with pytest.raises(RuntimeError, match="forward restart failed"):
                cmd_setup._auto_restart_sidecar_after_setup()
        else:
            cmd_setup._auto_restart_sidecar_after_setup()

    assert forward == [str(new_root)]
    assert rollback == ([None] if restart_fails else [])
    assert os.environ["DEFENSECLAW_EXPLICIT_CODEX_SETUP"] == str(old_root)


@pytest.mark.parametrize("predecessor", ("1.0.2", "1.0.3"))
def test_single_codex_root_upgrade_clears_selected_root_before_rollback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    predecessor: str,
) -> None:
    profile_dir = tmp_path / "profile"
    profile_dir.mkdir()
    if os.name == "nt":
        # Elevated Windows test tokens can create scratch directories owned
        # by Administrators instead of the current user.
        from tests.permissions import set_known_windows_directory_acl

        set_known_windows_directory_acl(profile_dir)
    app, profile, db_path = make_app_context(str(profile_dir))
    try:
        old_root = tmp_path / "old-codex"
        new_root = tmp_path / "new-codex"
        old_root.mkdir()
        new_root.mkdir()
        fixture = (
            Path(__file__).resolve().parents[2]
            / "internal/gateway/connector/testdata/predecessor_1_0_2_1_0_3/codex.toml"
        ).read_text(encoding="utf-8")
        (old_root / "config.toml").write_text(fixture, encoding="utf-8")
        (new_root / "config.toml").write_text("[features]\nhooks = true\n", encoding="utf-8")
        monkeypatch.setenv("CODEX_HOME", str(new_root))
        # An inherited marker matching the selected root must still be
        # removed while the prior gateway registration is restored.
        monkeypatch.setenv("DEFENSECLAW_EXPLICIT_CODEX_SETUP", str(new_root))
        app.cfg.guardrail.connector = "codex"
        app.cfg.claw.mode = "codex"
        forward: list[str | None] = []
        rollback: list[str | None] = []

        monkeypatch.setattr(cmd_setup, "_agent_settings_refusal", lambda *_args, **_kwargs: "")
        monkeypatch.setattr(cmd_setup, "_record_windows_setup_agent_selections", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(cmd_setup, "_maybe_bring_up_local_stack", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(app.cfg, "save", lambda: None)

        def restart(*_args: object, **_kwargs: object) -> None:
            forward.append(os.environ.get("DEFENSECLAW_EXPLICIT_CODEX_SETUP"))
            raise RuntimeError("forward restart failed")

        def restore(*_args: object, **_kwargs: object) -> None:
            rollback.append(os.environ.get("DEFENSECLAW_EXPLICIT_CODEX_SETUP"))
            raise RuntimeError("rollback reached")

        monkeypatch.setattr(cmd_setup, "_restart_services", restart)
        monkeypatch.setattr(cmd_setup, "_rollback_failed_connector_application", restore)
        with pytest.raises(RuntimeError, match="rollback reached"):
            cmd_setup._apply_hook_connector_setup(
                app, connector="codex", mode="observe", restart=True,
                allow_trusted_path_prompt=False, _version_preflighted=True,
            )
        assert forward == [str(new_root)]
        assert rollback == [None]
        assert os.environ["DEFENSECLAW_EXPLICIT_CODEX_SETUP"] == str(new_root)
    finally:
        cleanup_app(app, db_path, profile)
