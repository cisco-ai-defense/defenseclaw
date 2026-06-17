# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Shared safety primitives for untrusted-input handling.

The DefenseClaw threat model treats connector homes, workspace directories,
archives, registries, and remote endpoints as attacker-controlled. Several
code paths need the same three guards, so they live here once instead of
being re-implemented (and drifting) at each call site:

* :func:`reject_symlink` / :func:`is_symlink` — refuse to follow a symlink
  before reading or writing a path the operator did not author. Centralizes
  the ``os.path.islink`` checks already scattered across the package.
* :func:`assert_within_roots` / :func:`is_within_roots` — realpath-based
  containment so a connector-reported or symlinked path cannot escape the
  set of directories it is supposed to live under.
* :func:`sanitize_dotenv_value` — reject control characters that would let an
  untrusted token/path value inject extra ``KEY=VALUE`` lines into a dotenv
  file (which the config loader parses line-by-line).
* :func:`build_no_redirect_opener` — a urllib opener that refuses HTTP
  redirects so credential-bearing probes never replay auth headers to a
  redirect target.
"""

from __future__ import annotations

import os
import urllib.request

__all__ = [
    "SafetyError",
    "is_symlink",
    "reject_symlink",
    "is_within_roots",
    "assert_within_roots",
    "sanitize_dotenv_value",
    "DotenvValueError",
    "NoRedirectError",
    "build_no_redirect_opener",
]


class SafetyError(ValueError):
    """Base class for safety-guard violations.

    Subclasses ``ValueError`` so existing ``except ValueError`` handlers (the
    common shape in command code) keep catching these.
    """


# ---------------------------------------------------------------------------
# Symlink rejection
# ---------------------------------------------------------------------------


def is_symlink(path: str | os.PathLike[str]) -> bool:
    """Return True if *path* itself is a symlink.

    Unlike ``os.path.isfile``/``os.path.isdir`` (which follow symlinks),
    ``os.path.islink`` reports the link itself. ``False`` for a missing path.
    """
    try:
        return os.path.islink(path)
    except OSError:
        return False


def reject_symlink(path: str | os.PathLike[str], *, what: str = "path") -> str:
    """Raise :class:`SafetyError` if *path* is a symlink; else return it.

    Use immediately before opening an attacker-influenceable file so a
    pre-planted symlink cannot redirect the read/write to an arbitrary
    target. For atomic write paths prefer ``O_NOFOLLOW`` on the descriptor;
    this helper covers the read side and non-``os.open`` callers.
    """
    if is_symlink(path):
        raise SafetyError(f"refusing to follow symlinked {what}: {os.fspath(path)}")
    return os.fspath(path)


# ---------------------------------------------------------------------------
# Realpath containment
# ---------------------------------------------------------------------------


def _normalized_real(path: str | os.PathLike[str]) -> str:
    """Resolve symlinks and normalize; trailing separator stripped."""
    return os.path.realpath(os.fspath(path)).rstrip(os.sep) or os.sep


def is_within_roots(
    path: str | os.PathLike[str],
    roots: list[str] | tuple[str, ...] | str,
) -> bool:
    """Return True if *path*'s realpath is at or under any of *roots*.

    Both the candidate and the roots are passed through ``os.path.realpath``
    so a symlink in either cannot smuggle the candidate outside the allowed
    set. A candidate equal to a root counts as contained.
    """
    if isinstance(roots, (str, os.PathLike)):
        roots = [os.fspath(roots)]
    real = _normalized_real(path)
    for root in roots:
        if not root:
            continue
        real_root = _normalized_real(root)
        if real == real_root or real.startswith(real_root + os.sep):
            return True
    return False


def assert_within_roots(
    path: str | os.PathLike[str],
    roots: list[str] | tuple[str, ...] | str,
    *,
    what: str = "path",
) -> str:
    """Raise :class:`SafetyError` if *path* escapes *roots*; else return it.

    Returns the original (non-resolved) path so callers can keep using the
    value they already had once containment is established.
    """
    if not is_within_roots(path, roots):
        raise SafetyError(
            f"refusing to use {what} outside its allowed root(s): {os.fspath(path)}"
        )
    return os.fspath(path)


# ---------------------------------------------------------------------------
# Dotenv value sanitization
# ---------------------------------------------------------------------------


class DotenvValueError(SafetyError):
    """A value is unsafe to serialize into a dotenv file."""


# Control characters that break the one-KEY=VALUE-per-line dotenv format and
# would let an untrusted value inject additional environment entries.
_DOTENV_FORBIDDEN = ("\n", "\r", "\x00")


def sanitize_dotenv_value(value: str, *, key: str = "value") -> str:
    """Return *value* unchanged if safe to write to a dotenv file, else raise.

    The config loader parses ``~/.defenseclaw/.env`` line-by-line, splitting
    on the first ``=``. An embedded newline in a token/path value would
    therefore be read as a *second* ``KEY=VALUE`` assignment — letting an
    untrusted source (gateway/observability token, trusted-path name) inject
    arbitrary environment variables (e.g. disabling redaction). We reject
    such values outright rather than silently escaping, because a legitimate
    secret or filesystem path never contains a raw newline or NUL.
    """
    if not isinstance(value, str):
        value = str(value)
    for ch in _DOTENV_FORBIDDEN:
        if ch in value:
            raise DotenvValueError(
                f"refusing to write dotenv {key!r}: value contains a control "
                f"character ({ch!r}) that could inject extra environment entries"
            )
    return value


# ---------------------------------------------------------------------------
# No-redirect HTTP opener
# ---------------------------------------------------------------------------


class NoRedirectError(SafetyError):
    """An HTTP probe received a redirect that was refused for safety."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse 30x responses instead of transparently following them.

    Python's default ``HTTPRedirectHandler`` re-issues the request to the
    redirect target and copies caller-supplied headers (including
    ``Authorization`` / API-key headers) along with it. For credential-bearing
    probes that means a hostile or misconfigured endpoint can harvest the
    secret simply by returning a redirect. We turn every redirect into an
    error so the caller can warn instead of leaking.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise NoRedirectError(f"refusing to follow HTTP redirect ({code}) to {newurl}")


def build_no_redirect_opener(
    *handlers: urllib.request.BaseHandler,
) -> urllib.request.OpenerDirector:
    """Return a urllib opener that raises on redirects.

    Extra *handlers* (e.g. an ``HTTPSHandler`` with a custom SSL context) are
    appended after the no-redirect handler so callers can still control TLS
    verification.
    """
    return urllib.request.build_opener(_NoRedirectHandler(), *handlers)
