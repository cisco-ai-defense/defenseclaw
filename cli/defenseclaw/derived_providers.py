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

"""custom-providers.json is derived from config.yaml ``llm_providers``.

The gateway builds its provider registry from config. The overlay file is
rendered from ``llm_providers`` for the Python readers that still read it
(``resolve_llm``, the credential and model pickers) and carries
``_derived_from``: the digest of what it renders. A file without that key is
a legacy operator overlay that config has not absorbed yet; a derived file
whose content no longer matches its digest was edited by hand and is never
read back as input.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import os
import tempfile
from typing import Any

OVERLAY_FILENAME = "custom-providers.json"
DERIVED_FROM_KEY = "_derived_from"

# overlay_state results
STATE_ABSENT = "absent"  # no file and nothing to render
STATE_LEGACY = "legacy"  # operator-authored overlay, not yet in config
STATE_FRESH = "fresh"  # derived and matches config
STATE_EDITED = "edited"  # derived file edited by hand
STATE_STALE = "stale"  # derived from an older llm_providers (or missing)


def overlay_path(cfg) -> str:
    data_dir = getattr(cfg, "data_dir", "") or os.path.expanduser("~/.defenseclaw")
    return os.path.join(data_dir, OVERLAY_FILENAME)


def _compact(value: Any) -> Any:
    """Drop empty values so the rendered shape matches the Go omitempty one."""
    if isinstance(value, dict):
        out = {k: _compact(v) for k, v in value.items()}
        return {k: v for k, v in out.items() if v not in (None, "", [], {}, False)}
    if isinstance(value, list):
        return [_compact(v) for v in value]
    return value


def _read_pem(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def render(cfg) -> dict[str, Any]:
    """The overlay payload ``llm_providers`` renders to (without the digest)."""
    llm_providers = getattr(cfg, "llm_providers", None)
    providers: list[dict[str, Any]] = []
    for entry in getattr(llm_providers, "custom", None) or []:
        raw = dataclasses.asdict(entry)
        tls = raw.pop("tls", None) or None
        out = _compact(raw)
        out.setdefault("domains", [])
        out.setdefault("env_keys", [])
        if tls:
            rendered_tls: dict[str, Any] = {}
            if tls.get("ca_cert_file"):
                rendered_tls["ca_cert_pem"] = _read_pem(tls["ca_cert_file"])
            if tls.get("insecure_skip_verify"):
                rendered_tls["insecure_skip_verify"] = True
            if rendered_tls:
                out["tls"] = rendered_tls
        providers.append(out)
    ports = list(getattr(llm_providers, "ollama_ports", None) or [])
    return {"providers": providers, "ollama_ports": ports}


def digest(payload: dict[str, Any]) -> str:
    body = {k: v for k, v in payload.items() if k != DERIVED_FROM_KEY}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _read(path: str) -> dict[str, Any] | None:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def overlay_state(cfg, path: str | None = None) -> tuple[str, str]:
    """Return (state, path) for the overlay file against config."""
    path = path or overlay_path(cfg)
    expected = render(cfg)
    current = _read(path) if os.path.exists(path) else None
    if current is None:
        if os.path.exists(path):
            return STATE_EDITED, path
        return (STATE_ABSENT if not expected["providers"] and not expected["ollama_ports"] else STATE_STALE), path
    recorded = current.get(DERIVED_FROM_KEY)
    if not recorded:
        return STATE_LEGACY, path
    if recorded != digest(current):
        return STATE_EDITED, path
    if recorded != digest(expected):
        return STATE_STALE, path
    return STATE_FRESH, path


def configured_providers(cfg, path: str | None = None) -> list[dict[str, Any]]:
    """The provider entries Python resolves against, in the overlay shape.

    ``llm_providers`` rendered from config, whichever writer put it there; a
    legacy operator overlay (no ``_derived_from``) only while config declares
    no providers. A derived file is output and is never read back.
    """
    payload = render(cfg)
    if payload["providers"] or payload["ollama_ports"]:
        return payload["providers"]
    current = _read(path or overlay_path(cfg))
    if current is None or current.get(DERIVED_FROM_KEY):
        return []
    providers = current.get("providers")
    return [p for p in providers if isinstance(p, dict)] if isinstance(providers, list) else []


def refresh(cfg, path: str | None = None) -> bool:
    """Re-render the overlay after a config write when it no longer matches
    ``llm_providers`` (the writer's post-commit step). A hand-edited or
    legacy overlay is left for doctor to report. Returns whether it wrote."""
    state, path = overlay_state(cfg, path)
    if state != STATE_STALE:
        return False
    write(cfg, path)
    return True


def legacy_request_override_providers(path: str) -> list[str]:
    """Names of the providers that set ``request_overrides`` in a legacy
    (unmarked) overlay at *path*. ``llm_providers`` cannot hold those
    overrides, so such a file stays a live input the gateway merges."""
    current = _read(path) if os.path.exists(path) else None
    if current is None or current.get(DERIVED_FROM_KEY):
        return []
    providers = current.get("providers")
    if not isinstance(providers, list):
        return []
    return [
        str(p.get("name") or "")
        for p in providers
        if isinstance(p, dict) and isinstance(p.get("request_overrides"), dict) and p["request_overrides"]
    ]


def write(cfg, path: str | None = None) -> str:
    """Render ``llm_providers`` to the overlay file (0600, atomic) and return
    its path. A legacy operator overlay is left alone while config has no
    ``llm_providers`` yet, so nothing it declares is lost, and always when it
    sets ``request_overrides``: that file stays a live input (GAP-0500)."""
    path = path or overlay_path(cfg)
    payload = render(cfg)
    current = _read(path) if os.path.exists(path) else None
    if current is not None and not current.get(DERIVED_FROM_KEY):
        if not payload["providers"] and not payload["ollama_ports"]:
            return path
        if legacy_request_override_providers(path):
            return path
    document = {DERIVED_FROM_KEY: digest(payload), **payload}
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".custom-providers.", suffix=".json.tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(document, f, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        tmp = ""
    finally:
        if tmp:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
    return path
