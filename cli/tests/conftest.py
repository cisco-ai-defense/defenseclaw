"""Pytest compatibility for the Click versions DefenseClaw supports."""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest
from click.testing import CliRunner, Result

_ORIGINAL_ISOLATION = CliRunner.isolation
_ORIGINAL_STDERR_GETTER = Result.stderr.fget


@contextmanager
def _isolation_compat(self, *args, **kwargs):
    """Normalize Click 8.1's two-stream isolation tuple to Click 8.2+ shape."""
    with _ORIGINAL_ISOLATION(self, *args, **kwargs) as streams:
        if len(streams) == 2:
            out, err = streams
            yield out, err, None
        else:
            yield streams


def _stderr_compat(self):
    """Return an empty stderr string when Click mixed stderr into stdout."""
    try:
        return _ORIGINAL_STDERR_GETTER(self)
    except ValueError as exc:
        if "stderr not separately captured" not in str(exc):
            raise
        return ""


CliRunner.isolation = _isolation_compat
Result.stderr = property(_stderr_compat)

for _stream in (sys.stdout, sys.stderr):
    _reconfigure = getattr(_stream, "reconfigure", None)
    if _reconfigure is not None:
        _reconfigure(encoding="utf-8")


def _set_windows_identity(setenv, home: Path) -> None:
    """Point every Windows user-state root at one disposable home."""
    home.mkdir(parents=True, exist_ok=True)
    drive, tail = os.path.splitdrive(os.fspath(home))
    roots = {
        "HOME": home,
        "USERPROFILE": home,
        "HOMEDRIVE": drive,
        "HOMEPATH": tail or os.sep,
        "APPDATA": home / "AppData" / "Roaming",
        "LOCALAPPDATA": home / "AppData" / "Local",
        "XDG_CONFIG_HOME": home / ".config",
        "XDG_CACHE_HOME": home / ".cache",
        "XDG_DATA_HOME": home / ".local" / "share",
        "NPM_CONFIG_PREFIX": home / ".npm-global",
        "DEFENSECLAW_HOME": home / ".defenseclaw",
        "CODEX_HOME": home / ".codex",
        "CLAUDE_CONFIG_DIR": home / ".claude",
        "HERMES_HOME": home / "AppData" / "Local" / "hermes",
    }
    for name, value in roots.items():
        path = os.fspath(value)
        setenv(name, path)


@pytest.fixture(autouse=True)
def _isolated_windows_identity(tmp_path_factory, monkeypatch: pytest.MonkeyPatch):
    """Keep tests away from the developer's real Windows profile.

    Windows home discovery consults USERPROFILE and HOMEDRIVE/HOMEPATH rather
    than HOME.  A large part of this suite intentionally redirects HOME, so
    mirror those later redirects as well when they use pytest's monkeypatch.
    Tests that need a deliberately mixed identity can still set the individual
    variables after setting HOME.
    """
    if os.name != "nt":
        yield
        return

    original_setenv = monkeypatch.setenv
    _set_windows_identity(original_setenv, tmp_path_factory.mktemp("windows-identity"))

    def setenv(self, name: str, value: str, prepend: str | None = None) -> None:
        original_setenv(self, name, value, prepend=prepend)
        if name == "HOME":
            _set_windows_identity(
                lambda key, item: original_setenv(self, key, item),
                Path(value),
            )

    original_setenv = pytest.MonkeyPatch.setenv
    monkeypatch.setattr(pytest.MonkeyPatch, "setenv", setenv)
    yield


@pytest.fixture(autouse=True)
def _inject_supported_connector_host(request, monkeypatch: pytest.MonkeyPatch):
    """Run platform-neutral connector behavior tests on an explicit host."""
    if request.node.get_closest_marker("supported_connector_host") is None:
        return

    from defenseclaw import platform_support
    from defenseclaw.commands import cmd_setup

    monkeypatch.setattr(platform_support, "host_os", lambda: "linux")

    def expand_connector_choices(command) -> None:
        for parameter in getattr(command, "params", ()):
            if isinstance(getattr(parameter, "type", None), cmd_setup._PlatformConnectorChoice):
                monkeypatch.setattr(
                    parameter.type,
                    "choices",
                    list(cmd_setup._CONNECTOR_NAMES_FALLBACK),
                )
        for child in getattr(command, "commands", {}).values():
            expand_connector_choices(child)

    expand_connector_choices(cmd_setup.setup)
