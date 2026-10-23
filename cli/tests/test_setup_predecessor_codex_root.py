"""Predecessor Codex root migrations must precheck the selected root."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import click
import pytest
from defenseclaw.commands import cmd_setup
from defenseclaw.context import AppContext

from tests.helpers import cleanup_app, make_app_context


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
