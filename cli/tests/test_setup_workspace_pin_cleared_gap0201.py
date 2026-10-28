"""GAP-0201: setup without --workspace clears an earlier workspace pin and says so."""

from types import SimpleNamespace

from defenseclaw.commands import cmd_setup


def _cfg(workspace_dir: str) -> SimpleNamespace:
    return SimpleNamespace(claw=SimpleNamespace(workspace_dir=workspace_dir))


def test_setup_without_workspace_names_the_pin_it_clears(tmp_path, capsys):
    pinned = str(tmp_path / "proj")
    cfg = _cfg(pinned)
    assert cmd_setup._configure_connector_workspace(cfg, None) == ""
    assert cfg.claw.workspace_dir == ""
    out = capsys.readouterr()
    text = out.out + out.err
    assert f"Workspace pin {pinned} cleared" in text
    assert f"--workspace {pinned}" in text


def test_an_explicit_workspace_or_no_earlier_pin_is_quiet(tmp_path, capsys):
    pinned = str((tmp_path / "proj").resolve())
    cfg = _cfg("")
    assert cmd_setup._configure_connector_workspace(cfg, None) == ""
    cfg = _cfg(pinned)
    assert cmd_setup._configure_connector_workspace(cfg, pinned) == pinned
    assert cfg.claw.workspace_dir == pinned
    out = capsys.readouterr()
    assert "cleared" not in out.out + out.err
