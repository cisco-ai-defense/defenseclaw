"""GAP-0201: setup without --workspace keeps a pre-set workspace pin that is a folder."""

from types import SimpleNamespace

from defenseclaw.commands import cmd_setup


def _cfg(workspace_dir: str) -> SimpleNamespace:
    return SimpleNamespace(claw=SimpleNamespace(workspace_dir=workspace_dir))


def test_setup_without_workspace_keeps_a_pre_set_pin(tmp_path, capsys):
    pinned = tmp_path / "proj"
    pinned.mkdir()
    cfg = _cfg(str(pinned))
    assert cmd_setup._configure_connector_workspace(cfg, None) == str(pinned.resolve())
    assert cfg.claw.workspace_dir == str(pinned.resolve())
    assert cmd_setup._setup_workspace_for_check(cfg, None) == str(pinned.resolve())
    out = capsys.readouterr()
    text = out.out + out.err
    assert f"Keeping workspace pin {pinned.resolve()}" in text
    assert "defenseclaw config unset claw.workspace_dir" in text
    assert "cleared" not in text


def test_a_pin_that_is_not_a_folder_is_cleared_with_a_warning(tmp_path, capsys):
    gone = str(tmp_path / "gone")
    cfg = _cfg(gone)
    assert cmd_setup._setup_workspace_for_check(cfg, None) is None
    assert cmd_setup._configure_connector_workspace(cfg, None) == ""
    assert cfg.claw.workspace_dir == ""
    out = capsys.readouterr()
    assert f"Workspace pin {gone} cleared: it is not a folder" in out.out + out.err


def test_an_explicit_workspace_or_global_choice_wins(tmp_path, capsys):
    pinned = tmp_path / "proj"
    pinned.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    cfg = _cfg(str(pinned))
    assert cmd_setup._configure_connector_workspace(cfg, str(other)) == str(other.resolve())
    assert cfg.claw.workspace_dir == str(other.resolve())
    assert cmd_setup._configure_connector_workspace(cfg, "") == ""
    assert cfg.claw.workspace_dir == ""
    assert cmd_setup._configure_connector_workspace(cfg, None) == ""
    out = capsys.readouterr()
    assert "Keeping workspace pin" not in out.out + out.err
    assert "cleared" not in out.out + out.err
