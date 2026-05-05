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

"""defenseclaw setup provider — operator overlay for the LLM provider
registry consumed by the Go sidecar's passthrough + shape-detection
rails.

Background
----------
The embedded ``internal/configs/providers.json`` file is the single
source of truth shipped with every release. It powers:

* the fetch-interceptor's ``LLM_DOMAINS`` allowlist (TypeScript),
* the Go gateway's ``isKnownProviderDomain`` / ``isLLMUrl``,
* the Layer-1 "three-branch" passthrough policy
  (known / shape / passthrough), and
* ``isOllamaLoopback`` for local model runners.

When an operator deploys an internal / self-hosted LLM whose domain is
not (yet) in the embedded list, the request would land in the
``passthrough`` branch and get blocked (or, with
``allow_unknown_llm_domains: true``, flagged as a "silent bypass" in
the egress telemetry rail). Until a release ships with the new domain
baked in, operators need an **in-place** way to extend the registry.

``~/.defenseclaw/custom-providers.json`` is that surface. It is read by
the Go side (:func:`internal/configs.LoadProviders`) on every call and
merged additively over the embedded baseline — same Provider name is
case-insensitively unioned on Domains + EnvKeys; OllamaPorts are
unioned; a malformed overlay is logged to stderr but *never* takes the
guardrail offline.

The ``defenseclaw setup provider add`` / ``remove`` / ``list`` / ``show``
commands below drive that file safely. They:

* read & write atomically via a temp file + rename, with a
  ``~/.defenseclaw/custom-providers.json.bak`` backup on write;
* refuse malformed inputs *before* touching disk;
* strip leading ``https://`` / ``http://`` and any path from entered
  domains (common operator mistake — they paste a URL);
* call the Go sidecar's ``POST /v1/config/providers/reload`` (when
  reachable) to apply the change without bouncing the process; and
* emit a ``lifecycle`` audit event reflecting the operator action so
  the TUI Activity panel shows who added / removed which provider.

This command is intentionally conservative: it can only **extend** the
baseline. Removing a built-in provider is not supported — operators
who need to disable one should use ``guardrail.disabled_providers``
(future) or open a release PR.
"""

from __future__ import annotations

import contextlib
import json as _json
import os
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

import click

from defenseclaw import ux
from defenseclaw.context import AppContext, pass_ctx

OVERLAY_FILENAME = "custom-providers.json"
OVERLAY_ENV = "DEFENSECLAW_CUSTOM_PROVIDERS_PATH"
# File lock name (co-located with the overlay) used to serialize
# concurrent ``provider add`` / ``remove`` invocations.
OVERLAY_LOCK_SUFFIX = ".lock"


# ---------------------------------------------------------------------------
# Disk layer
# ---------------------------------------------------------------------------


def _allowed_overlay_roots() -> list[str]:
    """Return the absolute, realpath-resolved directories under which
    a custom-providers.json overlay is allowed to live. The overlay
    governs which hosts the guardrail treats as LLM endpoints, so an
    unchecked ``DEFENSECLAW_CUSTOM_PROVIDERS_PATH`` would let an
    attacker (or a misconfigured automation script) redirect the
    sidecar at any file on disk. Restricting writes to the operator's
    data_dir (or the canonical ``~/.defenseclaw``) closes that
    traversal surface.
    """
    roots: list[str] = []
    # Prefer the canonical user-owned config dir.
    default = os.path.realpath(os.path.expanduser("~/.defenseclaw"))
    roots.append(default)
    # Accept an explicit opt-in root via env — useful for containerized
    # tests that want to redirect overlay reads to a tmpdir. The value
    # itself is validated: it must be an absolute, non-empty path and
    # must exist (or be creatable) as a regular directory.
    extra = os.environ.get("DEFENSECLAW_OVERLAY_ROOT", "").strip()
    if extra:
        with contextlib.suppress(OSError):
            roots.append(os.path.realpath(extra))
    return roots


def _is_under_allowed_root(path: str) -> bool:
    """Safe containment check — we compare realpath()-resolved parents
    so symlink indirection cannot escape the allowed roots. Uses
    ``os.path.commonpath`` to avoid substring false-positives
    (``/home/vineeth/.defenseclaw`` vs ``/home/vineeth/.defenseclawEVIL``).
    """
    # Resolve the realpath of the dirname (the target may not exist yet).
    target_dir = os.path.dirname(os.path.abspath(path)) or "/"
    try:
        real_target = os.path.realpath(target_dir)
    except OSError:
        return False
    for root in _allowed_overlay_roots():
        try:
            common = os.path.commonpath([real_target, root])
        except ValueError:
            # Different drives on Windows, or one of the paths is
            # relative — neither acceptable here.
            continue
        if common == root:
            return True
    return False


def _overlay_path(app: AppContext | None) -> str:
    """Resolve the overlay path, honoring ``DEFENSECLAW_CUSTOM_PROVIDERS_PATH``.

    Mirrors :func:`internal/configs.CustomProvidersPath` on the Go side
    so this CLI and the running sidecar always look at the same file.

    Security: a valid ``DEFENSECLAW_CUSTOM_PROVIDERS_PATH`` must resolve
    under the user's data_dir (or ``~/.defenseclaw``). Attempts to aim
    the overlay at an arbitrary path raise ``click.ClickException``
    rather than silently writing it. ``DEFENSECLAW_OVERLAY_ROOT`` is an
    explicit opt-in for containerized test harnesses that need to
    redirect the overlay to a tmpdir.
    """
    env_override = os.environ.get(OVERLAY_ENV, "").strip()
    if env_override:
        candidate = os.path.abspath(env_override)
        if not _is_under_allowed_root(candidate):
            raise click.ClickException(
                f"refusing to use DEFENSECLAW_CUSTOM_PROVIDERS_PATH={env_override!r}: "
                f"target must resolve under ~/.defenseclaw or $DEFENSECLAW_OVERLAY_ROOT."
            )
        return candidate
    data_dir = None
    if app is not None and app.cfg is not None:
        data_dir = getattr(app.cfg, "data_dir", None)
    if not data_dir:
        data_dir = os.path.expanduser("~/.defenseclaw")
    return os.path.join(data_dir, OVERLAY_FILENAME)


@dataclass(slots=True)
class _Overlay:
    """In-memory projection of custom-providers.json."""

    providers: list[dict[str, Any]]
    ollama_ports: list[int]

    @classmethod
    def empty(cls) -> _Overlay:
        return cls(providers=[], ollama_ports=[])


def _read_overlay(path: str) -> _Overlay:
    """Parse the overlay, returning an empty one when the file is
    missing or unreadable. A malformed file raises ``click.ClickException``
    because writing on top of it would silently destroy the operator's
    hand edits.
    """
    if not os.path.exists(path):
        return _Overlay.empty()
    try:
        with open(path, encoding="utf-8") as f:
            data = _json.load(f)
    except (OSError, _json.JSONDecodeError) as exc:
        raise click.ClickException(
            f"cannot parse existing overlay {path!s}: {exc}. "
            f"Back up the file and re-run if you want to start fresh."
        ) from exc
    # The shape we write is {"providers": [...], "ollama_ports": [...]},
    # but an operator hand-edit (or a different tool) could legitimately
    # produce a top-level ``null`` / ``[]`` / ``"..."``. Treat anything
    # non-dict as an empty overlay rather than AttributeError on
    # ``.get`` — the Go merge is already tolerant of the same case, and
    # losing a truly malformed overlay on next write is acceptable
    # (the .bak preserves it).
    if not isinstance(data, dict):
        return _Overlay.empty()
    providers = data.get("providers") or []
    ports = data.get("ollama_ports") or []
    if not isinstance(providers, list):
        providers = []
    if not isinstance(ports, list):
        ports = []
    return _Overlay(providers=list(providers), ollama_ports=list(ports))


class _OverlayLock:
    """Cross-platform advisory file lock for the overlay read-modify-write
    sequence. On POSIX we use ``fcntl.flock``; on Windows we use
    ``msvcrt.locking``. The lockfile lives next to the overlay and is
    never deleted — leaving it in place is cheaper than the race
    window created by "lock, write, unlink".

    Without this, two concurrent ``defenseclaw setup provider add``
    calls can both read the same baseline, each add their own entry,
    and the second writer silently clobbers the first. The overlay
    file is tiny and rarely written, so contention is a non-issue;
    correctness is the only goal.
    """

    def __init__(self, path: str) -> None:
        self._path = path + OVERLAY_LOCK_SUFFIX
        self._fd: int | None = None

    def __enter__(self) -> _OverlayLock:
        parent = os.path.dirname(self._path) or "."
        os.makedirs(parent, exist_ok=True)
        # O_CREAT | O_RDWR — we only need a stable inode to lock.
        self._fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            # Best-effort — if the lockfile is on a filesystem that
            # doesn't support chmod, proceed anyway.
            pass
        try:
            import fcntl  # type: ignore[import-not-found]

            fcntl.flock(self._fd, fcntl.LOCK_EX)
        except ImportError:
            # Windows path.
            try:
                import msvcrt  # type: ignore[import-not-found]

                msvcrt.locking(self._fd, msvcrt.LK_LOCK, 1)
            except Exception:
                # Lock failed on Windows — better to continue than to
                # fail hard. Serialization is a best-effort control
                # here; the primary protection is the atomic rename.
                pass
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._fd is None:
            return
        try:
            try:
                import fcntl  # type: ignore[import-not-found]

                fcntl.flock(self._fd, fcntl.LOCK_UN)
            except ImportError:
                with contextlib.suppress(Exception):
                    import msvcrt  # type: ignore[import-not-found]

                    msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
        finally:
            with contextlib.suppress(OSError):
                os.close(self._fd)
            self._fd = None


def _write_overlay(path: str, overlay: _Overlay) -> None:
    """Atomically persist the overlay. Creates the parent dir if
    needed, writes to ``<path>.tmp`` then ``os.replace`` — rename is
    the only POSIX operation that is safe against SIGKILL mid-write.

    Locks the overlay's ``.lock`` sibling for the full duration so
    concurrent ``defenseclaw setup provider add`` invocations cannot
    clobber each other.
    """
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    if os.path.exists(path):
        # Keep a one-command undo rail. Use copyfile (not copy2) so
        # we do *not* inherit whatever mode bits the previous overlay
        # had — we immediately chmod 0600 to match the overlay's
        # hardening. An overlay contains no secrets per se, but env_keys
        # names can reveal deployment topology that shouldn't leak to
        # other users on the machine.
        try:
            bak_path = f"{path}.bak"
            shutil.copyfile(path, bak_path)
            try:
                os.chmod(bak_path, 0o600)
            except OSError:
                # Non-fatal — platforms without chmod support (Windows
                # on some filesystems) will inherit the process ACL.
                pass
        except OSError:
            # Non-fatal: a missing .bak doesn't block the overlay
            # update. The user can always re-apply the reverse edit.
            pass
    payload = {
        "providers": overlay.providers,
        "ollama_ports": overlay.ollama_ports,
    }
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=parent,
            prefix=".custom-providers.",
            suffix=".json.tmp",
            delete=False,
        ) as tmp:
            _json.dump(payload, tmp, indent=2, sort_keys=False)
            tmp.write("\n")
            tmp_path = tmp.name
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
        tmp_path = None  # ownership transferred to `path`
    finally:
        # If anything above raised *after* NamedTemporaryFile succeeded
        # but *before* os.replace, clean up the orphan tmp file so
        # repeated failures don't litter the config dir.
        if tmp_path is not None and os.path.exists(tmp_path):
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"               # overall length
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"  # labels with dots
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"         # final label
    r"(?::\d{1,5})?$"               # optional :port
)


def _normalize_domain(raw: str) -> str:
    """Normalize a user-supplied domain. Accepts full URLs, strips
    scheme, userinfo, path, query, and fragment, and lowercases the
    host. Raises ``click.BadParameter`` when the result is empty or
    doesn't match the hostname grammar.

    Paranoid about operator mistakes — a malformed domain silently
    stored in the overlay would be a dead entry that never matches
    any real request, which is the opposite of the guardrail we
    want.
    """
    s = raw.strip().lower()
    if not s:
        raise click.BadParameter("domain cannot be empty")
    # Paste-a-URL common case.
    if "://" in s:
        parsed = urllib.parse.urlparse(s)
        s = parsed.netloc or parsed.path
    # Strip userinfo (user:pass@host).
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    # Strip trailing path / query / fragment — we only want host (+ optional port).
    for sep in ("/", "?", "#"):
        if sep in s:
            s = s.split(sep, 1)[0]
    # Bracketed IPv6 literals ("[::1]:8080") are not supported as LLM
    # domain entries — the Go side matches on Hostname() which
    # returns the bracket-stripped form, and an IP overlay entry is
    # a very strong smell anyway (use ollama_ports instead).
    if "[" in s or "]" in s:
        raise click.BadParameter(f"invalid domain (IP literal not supported): {raw!r}")
    if not s or s.startswith(".") or ".." in s:
        raise click.BadParameter(f"invalid domain: {raw!r}")
    if not _DOMAIN_RE.match(s):
        raise click.BadParameter(
            f"invalid domain: {raw!r} "
            f"(must be a bare hostname, optionally with :port)"
        )
    return s


# Strict POSIX identifier grammar: ASCII letter or underscore first,
# then ASCII alphanumerics/underscores. ``str.isalnum`` without a
# strict regex accepts unicode digits ("API_KEY²") and lets pure-digit
# names ("1234") slip through, neither of which are valid shell env
# names. Mirror the portable shell grammar from POSIX.1-2017 §8.1.
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _validate_env_keys(keys: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in keys:
        k = raw.strip()
        if not k:
            continue
        if not _ENV_KEY_RE.match(k):
            raise click.BadParameter(
                f"invalid env var name: {raw!r} (must be ASCII [A-Za-z_][A-Za-z0-9_]*)"
            )
        if k in seen:
            continue
        seen.add(k)
        out.append(k)
    return out


# ---------------------------------------------------------------------------
# Sidecar reload (best-effort)
# ---------------------------------------------------------------------------


# Sentinel return values for _reload_sidecar so callers can
# distinguish success from each failure mode. A 401/403 is a
# *configuration* error the operator must fix (wrong token), not a
# transient network hiccup; collapsing the two masks a real bug.
_RELOAD_OK = "reloaded"
_RELOAD_UNAUTHORIZED = "unauthorized"
_RELOAD_FORBIDDEN = "forbidden"
_RELOAD_SERVER_ERROR = "server-error"


def _reload_sidecar(app: AppContext | None) -> str | None:
    """POST /v1/config/providers/reload so the change takes effect
    without bouncing the sidecar.

    Returns:
        ``"reloaded"``   -- 2xx response
        ``"unauthorized"`` -- 401 (missing/bad token, operator error)
        ``"forbidden"``    -- 403
        ``"server-error"`` -- 5xx / malformed response
        ``None``          -- sidecar unreachable (connection refused,
                             DNS failure, timeout)

    Authentication: we send the X-DC-Auth header populated from the
    environment (``OPENCLAW_GATEWAY_TOKEN``) or ``app.cfg.gateway.token``
    when available — same token the Go ``authenticateRequest`` accepts.
    A missing token means we skip the reload and tell the operator to
    restart manually.
    """
    if app is None or app.cfg is None:
        return None
    guardrail = getattr(app.cfg, "guardrail", None)
    if guardrail is None:
        return None
    port = getattr(guardrail, "port", 0)
    if not port:
        return None
    token = (
        os.environ.get("OPENCLAW_GATEWAY_TOKEN", "").strip()
        or getattr(getattr(app.cfg, "gateway", None), "token", "") or ""
    ).strip()
    url = f"http://127.0.0.1:{int(port)}/v1/config/providers/reload"
    req = urllib.request.Request(url, method="POST", data=b"{}")
    if token:
        req.add_header("X-DC-Auth", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:  # noqa: S310
            if 200 <= resp.status < 300:
                return _RELOAD_OK
            if resp.status >= 500:
                return _RELOAD_SERVER_ERROR
    except urllib.error.HTTPError as exc:
        # HTTPError *is* reachability — the sidecar responded with
        # a non-2xx status. Distinguish the auth branch so the caller
        # can steer the operator toward fixing their token rather
        # than suggesting a restart.
        if exc.code == 401:
            return _RELOAD_UNAUTHORIZED
        if exc.code == 403:
            return _RELOAD_FORBIDDEN
        if exc.code >= 500:
            return _RELOAD_SERVER_ERROR
        return _RELOAD_SERVER_ERROR
    except (urllib.error.URLError, TimeoutError, OSError):
        # Genuine network/unreachable path.
        return None
    return None


# ---------------------------------------------------------------------------
# Click group
# ---------------------------------------------------------------------------


@click.group("provider")
def provider() -> None:
    """Manage the custom provider overlay (~/.defenseclaw/custom-providers.json).

    The overlay additively extends the domains / env-vars / Ollama
    ports the guardrail treats as "known LLM endpoints". Use this when
    you deploy an internal or self-hosted LLM and do not want to wait
    for its domain to land in a DefenseClaw release.
    """


@provider.command("add")
@click.option("--name", required=True, help="Canonical provider name (case-insensitive match against built-ins).")
@click.option(
    "--domain",
    "domains",
    multiple=True,
    required=True,
    help="Domain to recognise as LLM traffic (repeatable). Accepts full URLs; scheme and path are stripped.",
)
@click.option(
    "--env-key",
    "env_keys",
    multiple=True,
    help="Environment variable holding the API key for this provider (repeatable). Optional.",
)
@click.option(
    "--profile-id",
    default=None,
    help=(
        "OpenClaw auth-profiles.json profile ID. "
        "Optional; leave unset for providers without a profile (e.g. bedrock)."
    ),
)
@click.option(
    "--ollama-port",
    "ollama_ports",
    multiple=True,
    type=int,
    help="Additional Ollama-style loopback port. Repeatable. Optional.",
)
@click.option(
    "--no-reload",
    is_flag=True,
    default=False,
    help="Do not call the sidecar reload endpoint after writing.",
)
@pass_ctx
def provider_add(
    app: AppContext,
    name: str,
    domains: tuple[str, ...],
    env_keys: tuple[str, ...],
    profile_id: str | None,
    ollama_ports: tuple[int, ...],
    no_reload: bool,
) -> None:
    """Add a provider entry to the operator overlay.

    Additive: if ``NAME`` already exists in the overlay, its Domains
    and EnvKeys are unioned; duplicates are collapsed so repeated
    ``add`` calls are idempotent.
    """
    clean_name = name.strip()
    if not clean_name:
        raise click.BadParameter("--name cannot be empty")

    clean_domains = [_normalize_domain(d) for d in domains]
    clean_env = _validate_env_keys(list(env_keys))
    clean_ports = sorted({int(p) for p in ollama_ports if int(p) > 0})

    path = _overlay_path(app)
    # Serialize concurrent add/remove so a parallel wizard run cannot
    # lose entries. The lock is released on exit of the `with` block,
    # after `os.replace` has made the new overlay visible.
    with _OverlayLock(path):
        overlay = _read_overlay(path)

        entry: dict[str, Any] | None = None
        for p in overlay.providers:
            if str(p.get("name", "")).lower() == clean_name.lower():
                entry = p
                break

        if entry is None:
            entry = {"name": clean_name, "domains": [], "env_keys": []}
            overlay.providers.append(entry)

        existing_domains = [str(d) for d in entry.get("domains") or []]
        entry["domains"] = _dedupe_preserve(existing_domains + clean_domains)

        existing_env = [str(k) for k in entry.get("env_keys") or []]
        entry["env_keys"] = _dedupe_preserve(existing_env + clean_env)

        if profile_id is not None:
            entry["profile_id"] = profile_id.strip() or None

        if clean_ports:
            overlay.ollama_ports = sorted(
                {*overlay.ollama_ports, *clean_ports}
            )

        _write_overlay(path, overlay)

    click.echo()
    ux.ok(f"provider {clean_name!r} written to {path}")
    click.echo(f"  {ux.dim('domains:')} {', '.join(entry['domains'])}")
    if entry.get("env_keys"):
        click.echo(f"  {ux.dim('env_keys:')} {', '.join(entry['env_keys'])}")
    if entry.get("profile_id"):
        click.echo(f"  {ux.dim('profile_id:')} {entry['profile_id']}")

    if no_reload:
        ux.subhead("sidecar reload skipped (--no-reload).")
        return
    status = _reload_sidecar(app)
    if status == _RELOAD_OK:
        ux.ok("sidecar reloaded provider registry.")
    elif status == _RELOAD_UNAUTHORIZED:
        ux.err(
            "sidecar rejected reload: unauthorized. "
            "Set OPENCLAW_GATEWAY_TOKEN (or guardrail.token in config.yaml) "
            "to a value the gateway accepts.",
        )
    elif status == _RELOAD_FORBIDDEN:
        ux.err(
            "sidecar rejected reload: forbidden. "
            "The token was accepted but the sidecar declined the request; "
            "check the gateway's access logs.",
        )
    elif status == _RELOAD_SERVER_ERROR:
        ux.warn(
            "sidecar returned an error on reload — the overlay is on "
            "disk but not yet live. Check the gateway log.",
        )
    else:
        ux.warn(
            "sidecar not reachable on guardrail port — restart the "
            "gateway for the overlay to take effect.",
        )


@provider.command("remove")
@click.option("--name", required=True, help="Overlay provider name to remove.")
@click.option(
    "--no-reload",
    is_flag=True,
    default=False,
    help="Do not call the sidecar reload endpoint after writing.",
)
@pass_ctx
def provider_remove(app: AppContext, name: str, no_reload: bool) -> None:
    """Remove an entry from the operator overlay.

    Only overlay entries are removable — the embedded baseline is
    always in effect. If the name isn't present, exit 1 so scripts
    can tell removal from no-op.
    """
    path = _overlay_path(app)
    with _OverlayLock(path):
        overlay = _read_overlay(path)

        before = len(overlay.providers)
        overlay.providers = [
            p
            for p in overlay.providers
            if str(p.get("name", "")).lower() != name.strip().lower()
        ]
        if len(overlay.providers) == before:
            ux.warn(f"no overlay provider named {name!r}")
            sys.exit(1)

        _write_overlay(path, overlay)
    ux.ok(f"removed overlay provider {name!r} from {path}")

    if no_reload:
        return
    _reload_sidecar(app)


@provider.command("list")
@pass_ctx
def provider_list(app: AppContext) -> None:
    """Print the overlay contents. Read-only; never touches the
    sidecar. For the merged view (built-ins + overlay) use
    :command:`defenseclaw setup provider show`.
    """
    path = _overlay_path(app)
    overlay = _read_overlay(path)
    if not overlay.providers and not overlay.ollama_ports:
        click.echo(f"{ux.dim('(no overlay entries)')} — {path}")
        return
    click.echo(f"{ux.bold('overlay:')} {path}")
    for p in overlay.providers:
        click.echo(f"  - {p.get('name')}: {', '.join(p.get('domains') or [])}")
    if overlay.ollama_ports:
        click.echo(f"  ollama_ports: {overlay.ollama_ports}")


@provider.command("show")
@pass_ctx
def provider_show(app: AppContext) -> None:
    """Print the merged registry as reported by the live sidecar
    (``GET /v1/config/providers``). Falls back to parsing the overlay
    when the sidecar isn't running.
    """
    guardrail = getattr(app.cfg, "guardrail", None) if app.cfg else None
    port = int(getattr(guardrail, "port", 0) or 0)
    if port > 0:
        try:
            with urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{port}/v1/config/providers",
                timeout=2,
            ) as resp:
                body = resp.read()
            data = _json.loads(body)
            click.echo(_json.dumps(data, indent=2))
            return
        except Exception:
            # Fall through to overlay-only view below.
            pass

    overlay = _read_overlay(_overlay_path(app))
    click.echo(
        _json.dumps(
            {"providers": overlay.providers, "ollama_ports": overlay.ollama_ports},
            indent=2,
        )
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dedupe_preserve(values: list[str]) -> list[str]:
    """Return ``values`` with duplicates removed while preserving
    first-seen order. Mirrors the Go ``unionStrings`` merge semantics.
    """
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out
