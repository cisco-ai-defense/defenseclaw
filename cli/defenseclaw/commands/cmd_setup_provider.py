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
import urllib.parse
from dataclasses import dataclass
from typing import Any

import click
import requests

from defenseclaw import connector_paths, platform_support, ux
from defenseclaw.context import AppContext, pass_ctx
from defenseclaw.gateway import OrchestratorClient, gateway_api_client_host

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
            f"cannot parse existing overlay {path!s}: {exc}. Back up the file and re-run if you want to start fresh."
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
    r"^(?=.{1,253}$)"  # overall length
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"  # labels with dots
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"  # final label
    r"(?::\d{1,5})?$"  # optional :port
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
        raise click.BadParameter(f"invalid domain: {raw!r} (must be a bare hostname, optionally with :port)")
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
            raise click.BadParameter(f"invalid env var name: {raw!r} (must be ASCII [A-Za-z_][A-Za-z0-9_]*)")
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
_RELOAD_MALFORMED = "malformed-response"


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

    The client uses cfg.gateway.api_bind/api_port, normalizes wildcard binds
    to loopback, and resolves the same gateway token precedence as the running
    sidecar.
    """
    if app is None or app.cfg is None:
        return None
    gateway = getattr(app.cfg, "gateway", None)
    if gateway is None:
        return None
    port = int(getattr(gateway, "api_port", 0) or 0)
    if port <= 0:
        return None
    resolver = getattr(gateway, "resolved_token", None)
    token = resolver() if callable(resolver) else str(getattr(gateway, "token", "") or "")
    client = OrchestratorClient(
        host=gateway_api_client_host(app.cfg),
        port=port,
        token=token.strip(),
        timeout=2,
    )
    try:
        client.reload_provider_registry()
        return _RELOAD_OK
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 0
        if status == 401:
            return _RELOAD_UNAUTHORIZED
        if status == 403:
            return _RELOAD_FORBIDDEN
        return _RELOAD_SERVER_ERROR
    except (requests.ConnectionError, requests.Timeout, OSError):
        return None
    except (ValueError, _json.JSONDecodeError):
        return _RELOAD_MALFORMED


def _report_reload_outcome(app: AppContext | None, persisted_action: str) -> None:
    """Report disk/runtime split outcomes and fail automation honestly."""
    status = _reload_sidecar(app)
    if status == _RELOAD_OK:
        ux.ok("sidecar reloaded provider registry; disk and live state match.")
        return

    if status == _RELOAD_UNAUTHORIZED:
        reason = "sidecar authentication failed (missing or invalid gateway token)"
    elif status == _RELOAD_FORBIDDEN:
        reason = "sidecar refused the authenticated reload"
    elif status == _RELOAD_SERVER_ERROR:
        reason = "sidecar returned an error while reloading"
    elif status == _RELOAD_MALFORMED:
        reason = "sidecar returned a malformed reload response"
    else:
        reason = "sidecar management API is unreachable"
    ux.err(f"{persisted_action} persisted successfully on disk, but live reload failed: {reason}.")
    ux.subhead("The running registry may differ from custom-providers.json; no disk change was rolled back.")
    click.get_current_context().exit(1)


def _provider_registry(app: AppContext) -> tuple[dict[str, Any], str | None]:
    """Return live registry first, or an explicitly labeled disk fallback."""
    gateway = getattr(app.cfg, "gateway", None) if app.cfg else None
    live_error: str | None = None
    if gateway is not None and int(getattr(gateway, "api_port", 0) or 0) > 0:
        resolver = getattr(gateway, "resolved_token", None)
        token = resolver() if callable(resolver) else str(getattr(gateway, "token", "") or "")
        client = OrchestratorClient(
            host=gateway_api_client_host(app.cfg),
            port=int(gateway.api_port),
            token=token.strip(),
            timeout=2,
        )
        try:
            data = client.provider_registry()
            return {**data, "source": "live-sidecar", "live": True}, None
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            live_error = "authentication failed" if status in {401, 403} else f"HTTP {status or 'error'}"
        except (ValueError, _json.JSONDecodeError):
            live_error = "malformed response"
        except (requests.ConnectionError, requests.Timeout, OSError):
            live_error = "management API unavailable"

    overlay = _read_overlay(_overlay_path(app))
    fallback = {
        "providers": overlay.providers,
        "ollama_ports": overlay.ollama_ports,
        "source": "disk-fallback",
        "live": False,
        "warning": "disk fallback may not match the running sidecar registry",
    }
    if live_error:
        fallback["live_error"] = live_error
    return fallback, live_error


def _display_provider_registry(app: AppContext, as_json: bool) -> None:
    data, live_error = _provider_registry(app)
    if as_json:
        click.echo(_json.dumps(data, indent=2))
    else:
        if data["live"]:
            ux.ok("source: live sidecar registry")
        else:
            ux.warn("DISK FALLBACK — this may not match the running sidecar registry.")
            if live_error:
                click.echo(f"  live query: {live_error}")
        for item in data.get("providers", []):
            click.echo(f"  - {item.get('name')}: {', '.join(item.get('domains') or [])}")
        if data.get("ollama_ports"):
            click.echo(f"  ollama_ports: {data['ollama_ports']}")
        _echo_provider_enforcement_legend(app)
    if live_error in {"authentication failed", "malformed response"}:
        click.get_current_context().exit(1)


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


_ALLOWED_BASE_PROVIDER_TYPES = (
    "openai",
    "anthropic",
    "bedrock",
    "azure",
    "vertex_ai",
    "gemini",
    "gemini-openai",
    "groq",
    "mistral",
    "cohere",
    "deepseek",
    "xai",
    "fireworks_ai",
    "perplexity",
    "huggingface",
    "replicate",
    "openrouter",
    "together_ai",
    "cerebras",
    "ollama",
    "vllm",
    "lm_studio",
)

_ALLOWED_REQUEST_TYPES = (
    "chat",
    "completion",
    "embedding",
    "rerank",
    "image",
    "audio",
    "responses",
)


def _validate_request_path_override(raw: str) -> tuple[str, str]:
    """Parse ``--request-path-override key=value``.

    ``key`` is one of :data:`_ALLOWED_REQUEST_TYPES`; ``value`` is a
    relative URL path that begins with ``/``.
    """
    if "=" not in raw:
        raise click.BadParameter(f"--request-path-override expects ``key=value`` (got {raw!r})")
    key, _, value = raw.partition("=")
    key = key.strip().lower()
    value = value.strip()
    if key not in _ALLOWED_REQUEST_TYPES:
        raise click.BadParameter(f"--request-path-override key {key!r} not one of {list(_ALLOWED_REQUEST_TYPES)}")
    if not value:
        raise click.BadParameter(f"--request-path-override value cannot be empty (key={key!r})")
    if not value.startswith("/"):
        raise click.BadParameter(f"--request-path-override {key!r} value must start with '/' (got {value!r})")
    return (key, value)


# Allowed enum values for each provider family's auth_mode. Mirrored
# from ``setup llm`` (cli/defenseclaw/commands/cmd_setup.py) so the
# overlay never carries a value the role-side wizard would reject.
_BEDROCK_AUTH_MODES = ("api_key", "iam_credentials", "profile", "instance_role")
_VERTEX_AUTH_MODES = ("service_account", "adc", "workload_identity")
_AZURE_AUTH_MODES = ("api_key", "managed_identity")


def _parse_alias_pairs(raw: tuple[str, ...], flag_name: str) -> dict[str, str]:
    """Parse repeatable ``alias=value`` (or ``model=deployment``) pairs
    into a dict. Used by ``--bedrock-deployment`` and
    ``--azure-deployment-alias`` so the wizard and the Click flags
    write identical overlay shapes.
    """
    out: dict[str, str] = {}
    for entry in raw:
        if "=" not in entry:
            raise click.BadParameter(f"{flag_name} expects ``alias=value`` (got {entry!r})")
        k, _, v = entry.partition("=")
        k, v = k.strip(), v.strip()
        if not k or not v:
            raise click.BadParameter(f"{flag_name} both sides of ``=`` must be non-empty (got {entry!r})")
        out[k] = v
    return out


def _validate_family_match(
    base_provider_type: str | None,
    bedrock_set: bool,
    vertex_set: bool,
    azure_set: bool,
) -> None:
    """Refuse to write an overlay whose sub-block disagrees with its
    ``base_provider_type``.

    The data resolver tolerates a mismatch (it just ignores the
    foreign sub-block), but writing one means the operator's
    ``--bedrock-region`` will silently never apply when
    ``--base-provider-type openai``. Failing loudly here is the
    less-surprising option.

    An empty ``base_provider_type`` is allowed — the resolver picks
    the family from the model prefix or from inference, and at that
    point any of the sub-blocks could be the correct one. Only a
    contradiction is rejected.
    """
    if not base_provider_type:
        return
    bpt = base_provider_type.strip().lower()
    if bedrock_set and bpt != "bedrock":
        raise click.BadParameter(f"--bedrock-* flags require --base-provider-type bedrock (got {bpt!r})")
    if vertex_set and bpt != "vertex_ai":
        raise click.BadParameter(f"--vertex-* flags require --base-provider-type vertex_ai (got {bpt!r})")
    if azure_set and bpt != "azure":
        raise click.BadParameter(f"--azure-* flags require --base-provider-type azure (got {bpt!r})")


def _build_bedrock_block(
    region: str | None,
    auth_mode: str | None,
    access_key_env: str | None,
    secret_key_env: str | None,
    session_token_env: str | None,
    profile_name: str | None,
    inference_profile: str | None,
    deployment_aliases: dict[str, str],
) -> dict[str, Any]:
    """Project supplied bedrock fields onto an overlay dict. Empty
    fields are omitted so the JSON stays compact and the resolver
    can distinguish "operator left it blank" from "operator set the
    empty string".
    """
    block: dict[str, Any] = {}
    if region:
        block["region"] = region.strip()
    if auth_mode:
        block["auth_mode"] = auth_mode.strip().lower()
    if access_key_env:
        block["access_key_env"] = access_key_env.strip()
    if secret_key_env:
        block["secret_key_env"] = secret_key_env.strip()
    if session_token_env:
        block["session_token_env"] = session_token_env.strip()
    if profile_name:
        block["profile_name"] = profile_name.strip()
    if inference_profile:
        block["inference_profile"] = inference_profile.strip()
    if deployment_aliases:
        block["deployment_aliases"] = dict(deployment_aliases)
    return block


def _build_vertex_block(
    project_id: str | None,
    region: str | None,
    auth_mode: str | None,
    service_account_json_env: str | None,
) -> dict[str, Any]:
    block: dict[str, Any] = {}
    if project_id:
        block["project_id"] = project_id.strip()
    if region:
        block["region"] = region.strip()
    if auth_mode:
        block["auth_mode"] = auth_mode.strip().lower()
    if service_account_json_env:
        block["service_account_json_env"] = service_account_json_env.strip()
    return block


def _build_azure_block(
    endpoint: str | None,
    api_version: str | None,
    auth_mode: str | None,
    deployment_aliases: dict[str, str],
) -> dict[str, Any]:
    block: dict[str, Any] = {}
    if endpoint:
        block["endpoint"] = endpoint.strip()
    if api_version:
        block["api_version"] = api_version.strip()
    if auth_mode:
        block["auth_mode"] = auth_mode.strip().lower()
    if deployment_aliases:
        block["deployment_aliases"] = dict(deployment_aliases)
    return block


def _read_ca_cert_file(path: str) -> str:
    """Read a PEM-encoded CA bundle from disk.

    Performs minimal validation so a typo (passing the private key by
    mistake) surfaces immediately rather than at gateway boot.
    """
    if not path:
        return ""
    if not os.path.isfile(path):
        raise click.BadParameter(f"--ca-cert-file: not found: {path!r}")
    try:
        with open(path, encoding="utf-8") as f:
            data = f.read()
    except OSError as exc:
        raise click.BadParameter(f"--ca-cert-file: cannot read {path!r}: {exc}") from exc
    head = data.strip().splitlines()[0] if data.strip() else ""
    if "BEGIN CERTIFICATE" not in head:
        raise click.BadParameter(
            f"--ca-cert-file: {path!r} does not start with a -----BEGIN CERTIFICATE----- block (saw {head!r})"
        )
    return data


_NAME_VALIDATION_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _provider_add_interactive() -> dict[str, Any]:
    """Walk the operator through a single ``provider add`` entry.

    Returns a dict whose keys mirror the CLI flag names. The caller
    merges the dict with any flag values supplied alongside the
    wizard (flag values always win) before writing the overlay.
    """
    click.echo()
    ux.section("Add a custom LLM provider")
    ux.subhead(
        "This walkthrough writes a new entry to "
        "~/.defenseclaw/custom-providers.json. Every prompt accepts a "
        "blank line to skip optional fields."
    )
    click.echo()

    while True:
        raw_name = click.prompt(
            "  Provider name (alphanumerics, ``_``/``-``)",
        ).strip()
        if _NAME_VALIDATION_RE.match(raw_name):
            break
        click.echo("    Invalid name — use only A-Z a-z 0-9 _ -")

    base_provider_type = (
        click.prompt(
            "  Base provider type (which Bifrost adapter to use)",
            type=click.Choice(_ALLOWED_BASE_PROVIDER_TYPES, case_sensitive=False),
            default="openai",
            show_default=True,
        )
        .strip()
        .lower()
    )

    while True:
        base_url = click.prompt(
            "  Base URL (https://internal.example/v1)",
            default="",
            show_default=False,
        ).strip()
        if not base_url:
            break
        if "://" in base_url:
            break
        click.echo("    Base URL must include a scheme (https://...).")

    click.echo()
    click.echo("  Allowed request types (default: chat completions):")
    for r in _ALLOWED_REQUEST_TYPES:
        click.echo(f"    - {r}")
    raw_allowed = click.prompt(
        "  Comma-separated list (blank = allow all)",
        default="",
        show_default=False,
    ).strip()
    allowed_requests: list[str] = []
    if raw_allowed:
        for tok in raw_allowed.split(","):
            tok = tok.strip().lower()
            if tok and tok in _ALLOWED_REQUEST_TYPES:
                allowed_requests.append(tok)

    available_models: list[str] = []
    click.echo()
    ux.subhead("Available models (blank line ends the loop):")
    while True:
        m = click.prompt("  Model id", default="", show_default=False).strip()
        if not m:
            break
        available_models.append(m)

    request_path_overrides: list[str] = []
    click.echo()
    ux.subhead("Request-path overrides (key=value, blank ends):")
    while True:
        rpo = click.prompt(
            "  key=value (e.g. chat=/openai/v1/chat/completions)",
            default="",
            show_default=False,
        ).strip()
        if not rpo:
            break
        if "=" not in rpo:
            click.echo("    Expected key=value — skipping.")
            continue
        request_path_overrides.append(rpo)

    click.echo()
    ux.subhead("TLS overrides (optional):")
    ca_cert_file = ""
    insecure_skip_verify = False
    tls_choice = (
        click.prompt(
            "  TLS mode  [n]one / [c]a-cert-file / [s]kip-verify (lab-only)",
            type=click.Choice(["n", "c", "s"]),
            default="n",
            show_default=True,
        )
        .strip()
        .lower()
    )
    if tls_choice == "c":
        ca_cert_file = click.prompt(
            "  Path to PEM CA bundle",
        ).strip()
    elif tls_choice == "s":
        ux.warn("Setting insecure_skip_verify=true means the gateway will trust ANY certificate from this endpoint.")
        insecure_skip_verify = click.confirm("  Confirm insecure skip-verify?", default=False)

    # Provider-typed sub-block. Branch on base_provider_type so the
    # operator only sees the prompts that match their backend.
    # Bedrock / Vertex / Azure each carry a distinct shape; the
    # remaining providers (openai-compatible, ollama, vllm, ...) do
    # not need a sub-block — their config is covered by base_url +
    # env_keys above.
    bedrock_region = vertex_project_id = vertex_region = ""
    bedrock_auth_mode = vertex_auth_mode = azure_auth_mode = ""
    bedrock_access_key_env = bedrock_secret_key_env = ""
    bedrock_session_token_env = bedrock_profile_name = ""
    bedrock_inference_profile = ""
    bedrock_deployment_aliases: dict[str, str] = {}
    vertex_service_account_json_env = ""
    azure_endpoint = azure_api_version = ""
    azure_deployment_aliases: dict[str, str] = {}

    if base_provider_type == "bedrock":
        click.echo()
        ux.subhead("Bedrock backend (blank to skip a field):")
        bedrock_region = click.prompt("  AWS region (e.g. us-east-1)", default="", show_default=False).strip()
        bedrock_auth_mode = (
            click.prompt(
                "  Auth mode",
                type=click.Choice(list(_BEDROCK_AUTH_MODES)),
                default="api_key",
                show_default=True,
            )
            .strip()
            .lower()
        )
        if bedrock_auth_mode == "iam_credentials":
            bedrock_access_key_env = click.prompt(
                "  AWS_ACCESS_KEY_ID env var name",
                default="",
                show_default=False,
            ).strip()
            bedrock_secret_key_env = click.prompt(
                "  AWS_SECRET_ACCESS_KEY env var name",
                default="",
                show_default=False,
            ).strip()
            bedrock_session_token_env = click.prompt(
                "  AWS_SESSION_TOKEN env var (optional)",
                default="",
                show_default=False,
            ).strip()
        elif bedrock_auth_mode == "profile":
            bedrock_profile_name = click.prompt(
                "  AWS profile name (from ~/.aws/credentials)",
                default="",
                show_default=False,
            ).strip()
        bedrock_inference_profile = click.prompt(
            "  Inference-profile prefix (e.g. 'us.', blank to skip)",
            default="",
            show_default=False,
        ).strip()
        click.echo()
        ux.subhead("Bedrock model aliases (alias=model-id, blank ends):")
        while True:
            entry = click.prompt("  alias=model-id", default="", show_default=False).strip()
            if not entry:
                break
            if "=" not in entry:
                click.echo("    Expected alias=model-id — skipping.")
                continue
            k, _, v = entry.partition("=")
            k, v = k.strip(), v.strip()
            if k and v:
                bedrock_deployment_aliases[k] = v
    elif base_provider_type == "vertex_ai":
        click.echo()
        ux.subhead("Vertex AI backend (blank to skip a field):")
        vertex_project_id = click.prompt("  GCP project id", default="", show_default=False).strip()
        vertex_region = click.prompt("  GCP region/location (e.g. us-central1)", default="", show_default=False).strip()
        vertex_auth_mode = (
            click.prompt(
                "  Auth mode",
                type=click.Choice(list(_VERTEX_AUTH_MODES)),
                default="service_account",
                show_default=True,
            )
            .strip()
            .lower()
        )
        if vertex_auth_mode == "service_account":
            vertex_service_account_json_env = click.prompt(
                "  Service-account JSON env var",
                default="GOOGLE_APPLICATION_CREDENTIALS",
                show_default=True,
            ).strip()
    elif base_provider_type == "azure":
        click.echo()
        ux.subhead("Azure OpenAI backend (blank to skip a field):")
        azure_endpoint = click.prompt(
            "  Endpoint (e.g. https://name.openai.azure.com)",
            default="",
            show_default=False,
        ).strip()
        azure_api_version = click.prompt("  API version (e.g. 2024-10-21)", default="", show_default=False).strip()
        azure_auth_mode = (
            click.prompt(
                "  Auth mode",
                type=click.Choice(list(_AZURE_AUTH_MODES)),
                default="api_key",
                show_default=True,
            )
            .strip()
            .lower()
        )
        click.echo()
        ux.subhead("Azure deployment aliases (model=deployment, blank ends):")
        while True:
            entry = click.prompt("  model=deployment", default="", show_default=False).strip()
            if not entry:
                break
            if "=" not in entry:
                click.echo("    Expected model=deployment — skipping.")
                continue
            k, _, v = entry.partition("=")
            k, v = k.strip(), v.strip()
            if k and v:
                azure_deployment_aliases[k] = v

    env_keys: list[str] = []
    click.echo()
    ux.subhead("API-key env vars (blank ends):")
    while True:
        e = click.prompt("  Env var name", default="", show_default=False).strip()
        if not e:
            break
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", e):
            click.echo("    Invalid env var name — skipping.")
            continue
        env_keys.append(e)

    domains: list[str] = []
    click.echo()
    ux.subhead("Additional traffic-match domains (optional, blank ends):")
    while True:
        d = click.prompt("  Domain", default="", show_default=False).strip()
        if not d:
            break
        domains.append(d)

    profile_id = click.prompt(
        "  Auth profile id (optional, leave blank to skip)",
        default="",
        show_default=False,
    ).strip()

    ollama_ports: list[int] = []
    click.echo()
    raw_ports = click.prompt(
        "  Ollama loopback ports (comma-separated ints, optional)",
        default="",
        show_default=False,
    ).strip()
    if raw_ports:
        for tok in raw_ports.split(","):
            try:
                ollama_ports.append(int(tok.strip()))
            except ValueError:
                continue

    # Summary + confirm.
    click.echo()
    ux.section("Confirm")
    rows = [
        ("name", raw_name),
        ("base_provider_type", base_provider_type),
        ("base_url", base_url or "(none)"),
        ("allowed_requests", ", ".join(allowed_requests) or "(all)"),
        ("available_models", ", ".join(available_models) or "(none)"),
        ("request_path_overrides", ", ".join(request_path_overrides) or "(none)"),
        ("env_keys", ", ".join(env_keys) or "(none)"),
        ("domains", ", ".join(domains) or "(none)"),
        ("ollama_ports", ", ".join(str(p) for p in ollama_ports) or "(none)"),
        ("profile_id", profile_id or "(none)"),
        ("tls.ca_cert_file", ca_cert_file or "(none)"),
        ("tls.insecure_skip_verify", str(insecure_skip_verify).lower()),
    ]
    if base_provider_type == "bedrock":
        rows.append(("bedrock.region", bedrock_region or "(none)"))
        rows.append(("bedrock.auth_mode", bedrock_auth_mode or "(none)"))
        if bedrock_access_key_env or bedrock_secret_key_env:
            rows.append(
                ("bedrock.creds", f"{bedrock_access_key_env or '?'}/{bedrock_secret_key_env or '?'}"),
            )
        if bedrock_profile_name:
            rows.append(("bedrock.profile_name", bedrock_profile_name))
        if bedrock_inference_profile:
            rows.append(("bedrock.inference_profile", bedrock_inference_profile))
        if bedrock_deployment_aliases:
            rows.append(
                (
                    "bedrock.deployment_aliases",
                    ", ".join(f"{k}={v}" for k, v in bedrock_deployment_aliases.items()),
                )
            )
    elif base_provider_type == "vertex_ai":
        rows.append(("vertex.project_id", vertex_project_id or "(none)"))
        rows.append(("vertex.region", vertex_region or "(none)"))
        rows.append(("vertex.auth_mode", vertex_auth_mode or "(none)"))
        if vertex_service_account_json_env:
            rows.append(("vertex.sa_json_env", vertex_service_account_json_env))
    elif base_provider_type == "azure":
        rows.append(("azure.endpoint", azure_endpoint or "(none)"))
        rows.append(("azure.api_version", azure_api_version or "(none)"))
        rows.append(("azure.auth_mode", azure_auth_mode or "(none)"))
        if azure_deployment_aliases:
            rows.append(
                (
                    "azure.deployment_aliases",
                    ", ".join(f"{k}={v}" for k, v in azure_deployment_aliases.items()),
                )
            )
    width = max(len(k) for k, _ in rows)
    for k, v in rows:
        click.echo(f"    {k + ':':<{width + 1}} {v}")
    click.echo()
    if not click.confirm("  Write provider entry?", default=True):
        raise click.Abort()

    return {
        "name": raw_name,
        "domains": domains,
        "env_keys": env_keys,
        "profile_id": profile_id,
        "ollama_ports": ollama_ports,
        "base_provider_type": base_provider_type,
        "base_url": base_url,
        "allowed_requests": allowed_requests,
        "available_models": available_models,
        "request_path_overrides": request_path_overrides,
        "ca_cert_file": ca_cert_file,
        "insecure_skip_verify": insecure_skip_verify,
        "bedrock_region": bedrock_region,
        "bedrock_auth_mode": bedrock_auth_mode,
        "bedrock_access_key_env": bedrock_access_key_env,
        "bedrock_secret_key_env": bedrock_secret_key_env,
        "bedrock_session_token_env": bedrock_session_token_env,
        "bedrock_profile_name": bedrock_profile_name,
        "bedrock_inference_profile": bedrock_inference_profile,
        "bedrock_deployment_aliases": bedrock_deployment_aliases,
        "vertex_project_id": vertex_project_id,
        "vertex_region": vertex_region,
        "vertex_auth_mode": vertex_auth_mode,
        "vertex_service_account_json_env": vertex_service_account_json_env,
        "azure_endpoint": azure_endpoint,
        "azure_api_version": azure_api_version,
        "azure_auth_mode": azure_auth_mode,
        "azure_deployment_aliases": azure_deployment_aliases,
    }


@provider.command("add")
@click.option(
    "--name",
    default=None,
    help=(
        "Canonical provider name (case-insensitive match against built-ins). "
        "When omitted and stdin is a tty, an interactive wizard prompts for "
        "every field. Under --non-interactive this becomes a hard error."
    ),
)
@click.option(
    "--domain",
    "domains",
    multiple=True,
    help=(
        "Domain to recognise as LLM traffic (repeatable). Accepts full URLs; "
        "scheme and path are stripped. Optional when --base-url is set."
    ),
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
        "OpenClaw auth-profiles.json profile ID. Optional; leave unset for providers without a profile (e.g. bedrock)."
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
    "--base-provider-type",
    "base_provider_type",
    default=None,
    type=click.Choice(_ALLOWED_BASE_PROVIDER_TYPES, case_sensitive=False),
    help=(
        "Upstream provider family this instance speaks "
        "(openai / bedrock / vertex_ai / azure / ollama / ...). "
        "Routes the gateway to the matching Bifrost adapter."
    ),
)
@click.option(
    "--base-url",
    "base_url",
    default=None,
    help="HTTP(S) base URL for the custom endpoint (e.g. https://llm.internal:8443).",
)
@click.option(
    "--allowed-request",
    "allowed_requests",
    multiple=True,
    type=click.Choice(_ALLOWED_REQUEST_TYPES, case_sensitive=False),
    help="Restrict the instance to listed request types (repeatable). Empty = allow all.",
)
@click.option(
    "--available-model",
    "available_models",
    multiple=True,
    help="Model id served by this instance (repeatable). Used by the wizard's model picker.",
)
@click.option(
    "--request-path-override",
    "request_path_overrides",
    multiple=True,
    help=("Per-route path override formatted ``key=value`` (e.g. chat=/openai/v1/chat/completions). Repeatable."),
)
@click.option(
    "--ca-cert-file",
    "ca_cert_file",
    default=None,
    type=click.Path(exists=False, dir_okay=False),
    help="Path to a PEM-encoded CA bundle for self-signed instance certs.",
)
@click.option(
    "--insecure-skip-verify",
    "insecure_skip_verify",
    is_flag=True,
    default=False,
    help="Disable TLS verification for this instance. Use only in trusted labs.",
)
@click.option(
    "--bedrock-region",
    "bedrock_region",
    default=None,
    help=("AWS region for an overlay-managed Bedrock instance (requires --base-provider-type bedrock)."),
)
@click.option(
    "--bedrock-auth-mode",
    "bedrock_auth_mode",
    default=None,
    type=click.Choice(_BEDROCK_AUTH_MODES, case_sensitive=False),
    help="Bedrock authentication scheme (api_key/iam_credentials/profile/instance_role).",
)
@click.option(
    "--bedrock-access-key-env",
    "bedrock_access_key_env",
    default=None,
    help="Env var name holding AWS_ACCESS_KEY_ID for this instance.",
)
@click.option(
    "--bedrock-secret-key-env",
    "bedrock_secret_key_env",
    default=None,
    help="Env var name holding AWS_SECRET_ACCESS_KEY for this instance.",
)
@click.option(
    "--bedrock-session-token-env",
    "bedrock_session_token_env",
    default=None,
    help="Env var name holding AWS_SESSION_TOKEN for short-lived STS credentials.",
)
@click.option(
    "--bedrock-profile-name",
    "bedrock_profile_name",
    default=None,
    help=("AWS shared-config profile name (from ~/.aws/credentials). Applied process-wide on the gateway side."),
)
@click.option(
    "--bedrock-inference-profile",
    "bedrock_inference_profile",
    default=None,
    help=("Inference-profile prefix (e.g. 'us.') prepended to the model id before dispatch."),
)
@click.option(
    "--bedrock-deployment",
    "bedrock_deployment_aliases",
    multiple=True,
    help=(
        "alias=model-id mapping for Bedrock model aliases (repeatable). "
        "Honored by the gateway when resolving a model id."
    ),
)
@click.option(
    "--vertex-project-id",
    "vertex_project_id",
    default=None,
    help="GCP project id for an overlay-managed Vertex AI instance.",
)
@click.option(
    "--vertex-region",
    "vertex_region",
    default=None,
    help="GCP region/location for Vertex AI (e.g. us-central1).",
)
@click.option(
    "--vertex-auth-mode",
    "vertex_auth_mode",
    default=None,
    type=click.Choice(_VERTEX_AUTH_MODES, case_sensitive=False),
    help="Vertex AI authentication scheme (service_account/adc/workload_identity).",
)
@click.option(
    "--vertex-service-account-json-env",
    "vertex_service_account_json_env",
    default=None,
    help="Env var name holding the GCP service-account JSON.",
)
@click.option(
    "--azure-endpoint",
    "azure_endpoint",
    default=None,
    help="Azure OpenAI endpoint (e.g. https://name.openai.azure.com).",
)
@click.option(
    "--azure-api-version",
    "azure_api_version",
    default=None,
    help="Azure OpenAI API version (e.g. 2024-10-21).",
)
@click.option(
    "--azure-auth-mode",
    "azure_auth_mode",
    default=None,
    type=click.Choice(_AZURE_AUTH_MODES, case_sensitive=False),
    help="Azure OpenAI authentication scheme (api_key/managed_identity).",
)
@click.option(
    "--azure-deployment-alias",
    "azure_deployment_aliases",
    multiple=True,
    help=(
        "model=deployment mapping for Azure deployments (repeatable). Honored by the gateway when resolving a model id."
    ),
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
    name: str | None,
    domains: tuple[str, ...],
    env_keys: tuple[str, ...],
    profile_id: str | None,
    ollama_ports: tuple[int, ...],
    base_provider_type: str | None,
    base_url: str | None,
    allowed_requests: tuple[str, ...],
    available_models: tuple[str, ...],
    request_path_overrides: tuple[str, ...],
    ca_cert_file: str | None,
    insecure_skip_verify: bool,
    bedrock_region: str | None,
    bedrock_auth_mode: str | None,
    bedrock_access_key_env: str | None,
    bedrock_secret_key_env: str | None,
    bedrock_session_token_env: str | None,
    bedrock_profile_name: str | None,
    bedrock_inference_profile: str | None,
    bedrock_deployment_aliases: tuple[str, ...],
    vertex_project_id: str | None,
    vertex_region: str | None,
    vertex_auth_mode: str | None,
    vertex_service_account_json_env: str | None,
    azure_endpoint: str | None,
    azure_api_version: str | None,
    azure_auth_mode: str | None,
    azure_deployment_aliases: tuple[str, ...],
    no_reload: bool,
) -> None:
    """Add a provider entry to the operator overlay.

    Additive: if ``NAME`` already exists in the overlay, its Domains
    and EnvKeys are unioned; duplicates are collapsed so repeated
    ``add`` calls are idempotent.
    """
    if not name:
        # When stdin is a tty and no --name was supplied, walk the
        # operator through every overlay field. Scripts that forget
        # --name still fail loudly because click.prompt aborts on a
        # closed stdin.
        wiz = _provider_add_interactive()
        name = wiz["name"]
        if not domains:
            domains = tuple(wiz["domains"])
        if not env_keys:
            env_keys = tuple(wiz["env_keys"])
        if profile_id is None:
            profile_id = wiz["profile_id"] or None
        if not ollama_ports:
            ollama_ports = tuple(wiz["ollama_ports"])
        if not base_provider_type:
            base_provider_type = wiz["base_provider_type"] or None
        if not base_url:
            base_url = wiz["base_url"] or None
        if not allowed_requests:
            allowed_requests = tuple(wiz["allowed_requests"])
        if not available_models:
            available_models = tuple(wiz["available_models"])
        if not request_path_overrides:
            request_path_overrides = tuple(wiz["request_path_overrides"])
        if not ca_cert_file:
            ca_cert_file = wiz["ca_cert_file"] or None
        if not insecure_skip_verify:
            insecure_skip_verify = wiz["insecure_skip_verify"]
        if bedrock_region is None:
            bedrock_region = wiz.get("bedrock_region") or None
        if bedrock_auth_mode is None:
            bedrock_auth_mode = wiz.get("bedrock_auth_mode") or None
        if bedrock_access_key_env is None:
            bedrock_access_key_env = wiz.get("bedrock_access_key_env") or None
        if bedrock_secret_key_env is None:
            bedrock_secret_key_env = wiz.get("bedrock_secret_key_env") or None
        if bedrock_session_token_env is None:
            bedrock_session_token_env = wiz.get("bedrock_session_token_env") or None
        if bedrock_profile_name is None:
            bedrock_profile_name = wiz.get("bedrock_profile_name") or None
        if bedrock_inference_profile is None:
            bedrock_inference_profile = wiz.get("bedrock_inference_profile") or None
        if not bedrock_deployment_aliases:
            bedrock_deployment_aliases = tuple(
                f"{k}={v}" for k, v in (wiz.get("bedrock_deployment_aliases") or {}).items()
            )
        if vertex_project_id is None:
            vertex_project_id = wiz.get("vertex_project_id") or None
        if vertex_region is None:
            vertex_region = wiz.get("vertex_region") or None
        if vertex_auth_mode is None:
            vertex_auth_mode = wiz.get("vertex_auth_mode") or None
        if vertex_service_account_json_env is None:
            vertex_service_account_json_env = wiz.get("vertex_service_account_json_env") or None
        if azure_endpoint is None:
            azure_endpoint = wiz.get("azure_endpoint") or None
        if azure_api_version is None:
            azure_api_version = wiz.get("azure_api_version") or None
        if azure_auth_mode is None:
            azure_auth_mode = wiz.get("azure_auth_mode") or None
        if not azure_deployment_aliases:
            azure_deployment_aliases = tuple(f"{k}={v}" for k, v in (wiz.get("azure_deployment_aliases") or {}).items())

    clean_name = (name or "").strip()
    if not clean_name:
        raise click.BadParameter("--name cannot be empty")

    if not domains and not (base_url or "").strip():
        raise click.BadParameter(
            "supply at least one --domain (LLM allow-list entry) or --base-url "
            "(custom-provider endpoint). Without either, the gateway has no "
            "host to match against."
        )

    clean_domains = [_normalize_domain(d) for d in domains]
    clean_env = _validate_env_keys(list(env_keys))
    clean_ports = sorted({int(p) for p in ollama_ports if int(p) > 0})

    clean_base_url = (base_url or "").strip()
    if clean_base_url and "://" not in clean_base_url:
        raise click.BadParameter(f"--base-url must include scheme (e.g. https://) — got {clean_base_url!r}")

    clean_allowed = sorted({a.lower() for a in allowed_requests if a})
    clean_models = _dedupe_preserve([m.strip() for m in available_models if m and m.strip()])
    clean_path_overrides: dict[str, str] = {}
    for raw in request_path_overrides:
        key, val = _validate_request_path_override(raw)
        clean_path_overrides[key] = val

    tls_block: dict[str, Any] = {}
    if insecure_skip_verify and ca_cert_file:
        raise click.BadParameter("--insecure-skip-verify and --ca-cert-file are mutually exclusive.")
    if ca_cert_file:
        tls_block["ca_cert_pem"] = _read_ca_cert_file(ca_cert_file)
        # A CA pin replaces any prior skip-verify on this provider (F-0141).
        tls_block["insecure_skip_verify"] = False
    if insecure_skip_verify:
        tls_block["insecure_skip_verify"] = True
        if app and getattr(app, "logger", None):
            try:
                app.logger.log_action(
                    "setup-provider",
                    "warning",
                    f"insecure_skip_verify=true for {clean_name!r}",
                )
            except Exception:
                pass
        ux.warn(
            f"--insecure-skip-verify enabled for {clean_name!r}; the gateway "
            "will accept ANY certificate from this endpoint. Use only in trusted labs."
        )

    if base_provider_type:
        base_provider_type = base_provider_type.strip().lower()

    bedrock_alias_map = _parse_alias_pairs(tuple(bedrock_deployment_aliases), "--bedrock-deployment")
    azure_alias_map = _parse_alias_pairs(tuple(azure_deployment_aliases), "--azure-deployment-alias")

    bedrock_block = _build_bedrock_block(
        region=bedrock_region,
        auth_mode=bedrock_auth_mode,
        access_key_env=bedrock_access_key_env,
        secret_key_env=bedrock_secret_key_env,
        session_token_env=bedrock_session_token_env,
        profile_name=bedrock_profile_name,
        inference_profile=bedrock_inference_profile,
        deployment_aliases=bedrock_alias_map,
    )
    vertex_block = _build_vertex_block(
        project_id=vertex_project_id,
        region=vertex_region,
        auth_mode=vertex_auth_mode,
        service_account_json_env=vertex_service_account_json_env,
    )
    azure_block = _build_azure_block(
        endpoint=azure_endpoint,
        api_version=azure_api_version,
        auth_mode=azure_auth_mode,
        deployment_aliases=azure_alias_map,
    )

    _validate_family_match(
        base_provider_type,
        bool(bedrock_block),
        bool(vertex_block),
        bool(azure_block),
    )

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

        if base_provider_type:
            entry["base_provider_type"] = base_provider_type
        if clean_base_url:
            entry["base_url"] = clean_base_url
        if clean_allowed:
            entry["allowed_requests"] = clean_allowed
        if clean_models:
            existing_models = [str(m) for m in entry.get("available_models") or []]
            entry["available_models"] = _dedupe_preserve(existing_models + clean_models)
        if clean_path_overrides:
            existing_overrides: dict[str, str] = {
                str(k): str(v) for k, v in (entry.get("request_path_overrides") or {}).items()
            }
            existing_overrides.update(clean_path_overrides)
            entry["request_path_overrides"] = existing_overrides
        if tls_block:
            merged_tls: dict[str, Any] = dict(entry.get("tls") or {})
            merged_tls.update(tls_block)
            entry["tls"] = merged_tls

        # Provider-typed sub-blocks. Each one shallow-merges into the
        # existing overlay entry: scalar fields are last-write-wins;
        # deployment_aliases maps are unioned so repeated ``add`` calls
        # can grow the alias table.
        def _merge_subblock(name_: str, new_block: dict[str, Any]) -> None:
            if not new_block:
                return
            current: dict[str, Any] = dict(entry.get(name_) or {})
            existing_aliases = dict(current.get("deployment_aliases") or {})
            new_aliases = dict(new_block.get("deployment_aliases") or {})
            current.update(new_block)
            if existing_aliases or new_aliases:
                merged = dict(existing_aliases)
                merged.update(new_aliases)
                current["deployment_aliases"] = merged
            entry[name_] = current

        _merge_subblock("bedrock", bedrock_block)
        _merge_subblock("vertex", vertex_block)
        _merge_subblock("azure", azure_block)

        if clean_ports:
            overlay.ollama_ports = sorted({*overlay.ollama_ports, *clean_ports})

        _write_overlay(path, overlay)

    click.echo()
    ux.ok(f"provider {clean_name!r} written to {path}")
    if entry.get("domains"):
        click.echo(f"  {ux.dim('domains:')} {', '.join(entry['domains'])}")
    if entry.get("env_keys"):
        click.echo(f"  {ux.dim('env_keys:')} {', '.join(entry['env_keys'])}")
    if entry.get("profile_id"):
        click.echo(f"  {ux.dim('profile_id:')} {entry['profile_id']}")
    if entry.get("base_provider_type"):
        click.echo(f"  {ux.dim('base_provider_type:')} {entry['base_provider_type']}")
    if entry.get("base_url"):
        click.echo(f"  {ux.dim('base_url:')} {entry['base_url']}")
    if entry.get("allowed_requests"):
        click.echo(f"  {ux.dim('allowed_requests:')} {', '.join(entry['allowed_requests'])}")
    if entry.get("available_models"):
        click.echo(f"  {ux.dim('available_models:')} {', '.join(entry['available_models'])}")
    if entry.get("request_path_overrides"):
        click.echo(
            f"  {ux.dim('request_path_overrides:')} "
            f"{', '.join(f'{k}={v}' for k, v in entry['request_path_overrides'].items())}"
        )
    if entry.get("tls"):
        tls_info = entry["tls"]
        bits: list[str] = []
        if tls_info.get("ca_cert_pem"):
            bits.append("ca_cert_pem=<inline>")
        if tls_info.get("insecure_skip_verify"):
            bits.append("insecure_skip_verify=true")
        if bits:
            click.echo(f"  {ux.dim('tls:')} {', '.join(bits)}")
    if entry.get("bedrock"):
        bedrock_info = entry["bedrock"]
        bits = []
        if bedrock_info.get("region"):
            bits.append(f"region={bedrock_info['region']}")
        if bedrock_info.get("auth_mode"):
            bits.append(f"auth_mode={bedrock_info['auth_mode']}")
        if bedrock_info.get("profile_name"):
            bits.append(f"profile={bedrock_info['profile_name']}")
        if bedrock_info.get("inference_profile"):
            bits.append(f"inference_profile={bedrock_info['inference_profile']}")
        if bedrock_info.get("deployment_aliases"):
            bits.append(f"aliases={len(bedrock_info['deployment_aliases'])}")
        if bits:
            click.echo(f"  {ux.dim('bedrock:')} {', '.join(bits)}")
    if entry.get("vertex"):
        vertex_info = entry["vertex"]
        bits = []
        if vertex_info.get("project_id"):
            bits.append(f"project_id={vertex_info['project_id']}")
        if vertex_info.get("region"):
            bits.append(f"region={vertex_info['region']}")
        if vertex_info.get("auth_mode"):
            bits.append(f"auth_mode={vertex_info['auth_mode']}")
        if bits:
            click.echo(f"  {ux.dim('vertex:')} {', '.join(bits)}")
    if entry.get("azure"):
        azure_info = entry["azure"]
        bits = []
        if azure_info.get("endpoint"):
            bits.append(f"endpoint={azure_info['endpoint']}")
        if azure_info.get("api_version"):
            bits.append(f"api_version={azure_info['api_version']}")
        if azure_info.get("auth_mode"):
            bits.append(f"auth_mode={azure_info['auth_mode']}")
        if azure_info.get("deployment_aliases"):
            bits.append(f"deployments={len(azure_info['deployment_aliases'])}")
        if bits:
            click.echo(f"  {ux.dim('azure:')} {', '.join(bits)}")

    if no_reload:
        ux.subhead("disk-only operation (--no-reload): running sidecar registry was not changed.")
        return
    _report_reload_outcome(app, f"provider {clean_name!r}")


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
        overlay.providers = [p for p in overlay.providers if str(p.get("name", "")).lower() != name.strip().lower()]
        if len(overlay.providers) == before:
            ux.warn(f"no overlay provider named {name!r}")
            sys.exit(1)

        _write_overlay(path, overlay)
    ux.ok(f"removed overlay provider {name!r} from {path}")

    if no_reload:
        ux.subhead("disk-only operation (--no-reload): running sidecar registry was not changed.")
        return
    _report_reload_outcome(app, f"removal of provider {name!r}")


@provider.command("list")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@pass_ctx
def provider_list(app: AppContext, as_json: bool) -> None:
    """Print the live merged registry, with a labeled disk fallback."""
    _display_provider_registry(app, as_json)


def _echo_provider_enforcement_legend(app: AppContext) -> None:
    """Explain what binding any of these custom providers actually does,
    keyed on the active connector's LLM traffic mode.

    The overlay is global, but its *effect* is per-connector: a custom
    provider is enforced on the agent's own model traffic only for the
    proxy connectors (OpenClaw, ZeptoClaw); for every hook connector it
    configures DefenseClaw's judge/aux model only.
    """
    guardrail = getattr(app.cfg, "guardrail", None) if app.cfg else None
    connector = connector_paths.normalize(getattr(guardrail, "connector", "") or "openclaw")
    click.echo()
    if platform_support.is_proxy_connector(connector):
        click.echo(
            ux.dim(
                f"  Active connector {connector!r} is a proxy connector: a bound "
                "custom provider is enforced on the agent's model traffic "
                "(agent upstream, judge, or both).",
            )
        )
    else:
        click.echo(
            ux.dim(
                f"  Active connector {connector!r} is a hook connector: a bound "
                "custom provider configures DefenseClaw's judge/aux model only — "
                "the agent's own model calls are not inspected. Only the proxy "
                "connectors (openclaw, zeptoclaw) enforce it on agent traffic.",
            )
        )


@provider.command("show")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@pass_ctx
def provider_show(app: AppContext, as_json: bool) -> None:
    """Print the merged registry as reported by the live sidecar
    (``GET /v1/config/providers``). Any disk fallback is explicitly
    labeled because it may not match the running process.
    """
    _display_provider_registry(app, as_json)


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
