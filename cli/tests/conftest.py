"""Pytest compatibility for the Click versions DefenseClaw supports."""

from __future__ import annotations

from contextlib import contextmanager

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
