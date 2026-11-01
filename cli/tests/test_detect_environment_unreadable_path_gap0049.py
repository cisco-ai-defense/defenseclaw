"""GAP-0049: an unreadable PATH folder is skipped like a missing one when init looks for nvidia-smi."""

from __future__ import annotations

import os
import stat
import sys

import pytest
from defenseclaw import config


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs a folder this account cannot read")
def test_detect_environment_skips_an_unreadable_path_folder(tmp_path, monkeypatch):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        monkeypatch.setattr(config.platform, "system", lambda: "Linux")
        monkeypatch.setattr(config.Path, "exists", lambda self: False)
        monkeypatch.setenv("PATH", str(locked))
        assert config.detect_environment() == "linux"
    finally:
        locked.chmod(stat.S_IRWXU)


def test_detect_environment_treats_permission_denied_like_not_found(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise PermissionError(13, "Permission denied", "nvidia-smi")

    monkeypatch.setattr(config.platform, "system", lambda: "Linux")
    monkeypatch.setattr(config.Path, "exists", lambda self: False)
    monkeypatch.setattr(config.subprocess, "check_output", refuse)
    assert config.detect_environment() == "linux"
