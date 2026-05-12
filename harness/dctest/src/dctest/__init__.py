"""dctest — DefenseClaw manual testing harness.

An AI-agent-driven harness for exercising every advertised DefenseClaw feature
across the full provider × role × connector × scan-type × profile × fail-mode
matrix. Modeled on avarice's architecture: subprocess agent invocation,
render/execute/collect triple, filesystem-backed state, resumable runs.

The harness orchestrates and captures evidence. The agent makes pass/fail calls.
"""

from __future__ import annotations

from datetime import datetime, timezone

__version__ = "0.1.0"


def utc_now() -> datetime:
    """Return the current UTC time as a naive datetime.

    Wraps :func:`datetime.now` + :class:`timezone.utc` so the harness can
    serialize without surfacing tzinfo (Pydantic v2 will treat naive
    datetimes consistently across reads/writes). Centralized here so we
    never pull in ``datetime.utcnow()`` (deprecated in 3.12).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)
