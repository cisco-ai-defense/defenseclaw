# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""config set data_dir stores one clean absolute folder, so a later move remembers it and uninstall finds it."""

import os

import pytest
from click.testing import CliRunner
from defenseclaw import config as config_module
from defenseclaw.commands import cmd_config, cmd_uninstall
from defenseclaw.context import AppContext

from tests.test_config_data_dir_move import _install_home

pytestmark = pytest.mark.skipif(os.name == "nt", reason="needs symlink rights and POSIX modes")


def _set_data_dir(value):
    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "data_dir", str(value)], obj=AppContext())
    assert result.exit_code == 0, result.output
    return result


def _stored_data_dir(path):
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("data_dir:"):
            return line.split(":", 1)[1].strip()
    raise AssertionError("config.yaml names no data_dir")


def _link_before_dotdot(tmp_path):
    """tmp/lnk -> tmp/deep/inner, so tmp/lnk/.. is tmp as written and tmp/deep as the system reads it."""
    (tmp_path / "deep" / "inner").mkdir(parents=True)
    (tmp_path / "lnk").symlink_to(tmp_path / "deep" / "inner")
    return f"{tmp_path}/lnk/../state3"


def test_a_data_dir_typed_with_dotdot_is_stored_clean_and_remembered_by_the_next_move(tmp_path, monkeypatch):
    home, path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    (home / "agent_discovery.json").write_text('{"agents": {}}\n')
    typed = _link_before_dotdot(tmp_path)
    clean = tmp_path / "state3"

    _set_data_dir(tmp_path / "state")
    _set_data_dir(typed)

    assert _stored_data_dir(path) == str(clean)
    assert (clean / "agent_discovery.json").is_file(), "the records are carried to the folder the gateway uses"
    assert not (tmp_path / "deep" / "state3").exists(), "no folder is made where the system reads the typed path"

    (clean / "marker.txt").write_text("x\n")
    _set_data_dir(tmp_path / "state4")

    assert config_module.previous_store_dirs() == (str(tmp_path / "state"), str(clean))
    plan = cmd_uninstall.UninstallPlan(
        data_dir=str(home), store_dir=str(tmp_path / "state4"), previous_stores=config_module.previous_store_dirs()
    )
    assert str(clean) in plan.record_dirs


def test_a_config_written_with_a_dotdot_data_dir_is_remembered_by_the_next_move(tmp_path, monkeypatch):
    # A config.yaml an earlier release or a hand edit left with the typed spelling.
    home, path = _install_home(tmp_path, monkeypatch)
    monkeypatch.setattr(config_module, "_is_admin_process", lambda: False)
    typed = _link_before_dotdot(tmp_path)
    clean = tmp_path / "state3"
    clean.mkdir()
    (clean / "agent_discovery.json").write_text('{"agents": {}}\n')
    path.write_text(f"config_version: 9\ndata_dir: {typed}\nobservability: {{}}\n", encoding="utf-8")

    _set_data_dir(tmp_path / "state4")

    assert config_module.previous_store_dirs() == (str(clean),)
    assert (tmp_path / "state4" / "agent_discovery.json").is_file()


def test_a_clean_absolute_data_dir_is_stored_as_typed(tmp_path, monkeypatch):
    _home, path = _install_home(tmp_path, monkeypatch)

    _set_data_dir(tmp_path / "plain")

    assert _stored_data_dir(path) == str(tmp_path / "plain")


def test_a_dot_segment_and_a_doubled_slash_fold_to_the_clean_folder(tmp_path, monkeypatch):
    _home, path = _install_home(tmp_path, monkeypatch)

    _set_data_dir(f"{tmp_path}//a/./b/../plain")

    assert _stored_data_dir(path) == str(tmp_path / "a" / "plain")
