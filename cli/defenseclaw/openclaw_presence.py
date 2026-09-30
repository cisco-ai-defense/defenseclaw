# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Whether an OpenClaw connector implied by ``claw.mode`` has an OpenClaw behind it.

``claw.mode`` defaults to ``openclaw`` (init writes it, and the loader uses it
when config.yaml has no claw block), so a sandbox-only or hook-only install
that never picked a connector still names OpenClaw. The gateway used to dial
the OpenClaw fleet port for such an install forever. It now reports the fleet
uplink off with "OpenClaw is not installed" when nothing on the machine is
OpenClaw (``internal/gateway/fleet_openclaw_presence.go``).

This module mirrors that rule so the CLI surfaces that read the same state
(doctor's gateway rows, the OpenClaw gateway token requirement behind the TUI
Keys pill, ``defenseclaw version``) agree with the gateway. Keep both sides in
sync: the configuration checks, the openclaw.json candidates and the binary
locations.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
from pathlib import Path
from typing import Any

# Published by the gateway in /health.gateway.details (reason, summary) when the
# fleet uplink is off because OpenClaw is not installed.
OPENCLAW_NOT_INSTALLED_REASON = "openclaw_not_installed"
OPENCLAW_NOT_INSTALLED_SUMMARY = "OpenClaw gateway off (OpenClaw is not installed)"
OPENCLAW_NOT_INSTALLED_DETAIL = "off (OpenClaw is not installed)"

_DEFAULT_OPENCLAW_CONFIG = "~/.openclaw/openclaw.json"


def _expand(path: str) -> str:
    """Expand a leading ``~/`` only, as ``expandPath`` in internal/config/claw.go does."""
    return os.path.expanduser(path) if path.startswith("~/") else path


def _is_loopback_gateway_host(host: object) -> bool:
    """Mirror ``isLoopbackGatewayHost`` in internal/gateway/sidecar.go."""
    h = str(host or "").strip().lower()
    if not h or h == "localhost":
        return True
    if len(h) >= 2 and h[0] == "[" and h[-1] == "]":
        h = h[1:-1]
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def openclaw_config_candidates(cfg: Any) -> list[str]:
    """Return the openclaw.json paths that mark OpenClaw as set up.

    Mirrors ``Config.OpenClawConfigCandidates`` in internal/config/claw.go:
    ``claw.config_file`` and ``<claw.home_dir>/openclaw.json``, expanded and
    deduplicated, with ``~/.openclaw/openclaw.json`` when both are empty.
    """
    claw = getattr(cfg, "claw", None)
    config_file = str(getattr(claw, "config_file", "") or "").strip()
    home_dir = str(getattr(claw, "home_dir", "") or "").strip()
    if not config_file and not home_dir:
        config_file = _DEFAULT_OPENCLAW_CONFIG
    raw = [config_file]
    if home_dir:
        raw.append(os.path.join(_expand(home_dir), "openclaw.json"))
    out: list[str] = []
    for candidate in raw:
        if not candidate:
            continue
        normalized = os.path.normpath(_expand(candidate))
        if normalized not in out:
            out.append(normalized)
    return out


def _openclaw_config_present(cfg: Any) -> bool:
    for path in openclaw_config_candidates(cfg):
        try:
            os.stat(path)
        except FileNotFoundError:
            continue
        except OSError:
            # An OpenClaw home we cannot inspect counts as present, as in Go.
            return True
        return True
    return False


def _openclaw_binary_fallbacks() -> list[Path]:
    paths = [Path("/usr/local/bin/openclaw"), Path("/opt/homebrew/bin/openclaw")]
    try:
        home = Path.home()
    except (KeyError, RuntimeError):
        return paths
    paths.extend([home / ".npm-global" / "bin" / "openclaw", home / ".local" / "bin" / "openclaw"])
    return paths


def openclaw_binary_installed() -> bool:
    """Mirror ``openClawBinaryInstalled`` in the gateway: PATH, then npm/Homebrew.

    A probe that fails outright counts as installed, keeping the OpenClaw
    behaviour instead of guessing.
    """
    try:
        if shutil.which("openclaw"):
            return True
        return any(path.is_file() for path in _openclaw_binary_fallbacks())
    except Exception:  # noqa: BLE001 - an unusable probe keeps the old behaviour.
        return True


def openclaw_implied_but_not_installed(cfg: Any) -> bool:
    """True when the gateway reports the OpenClaw fleet off as "not installed".

    Mirrors ``openClawImpliedButNotInstalled`` in the gateway. All of:

    * ``gateway.fleet_mode`` is unset (``""`` or ``"auto"``),
    * ``gateway.host`` is loopback,
    * ``guardrail.connector`` is empty and ``guardrail.connectors`` has no
      openclaw entry, so only ``claw.mode`` names OpenClaw, and
    * no openclaw.json candidate exists and no openclaw binary is found.

    Anything else, including an installed or configured OpenClaw, keeps the
    previous behaviour. Returns False when *cfg* lacks the expected sections.
    """
    if cfg is None:
        return False
    gateway = getattr(cfg, "gateway", None)
    guardrail = getattr(cfg, "guardrail", None)
    claw = getattr(cfg, "claw", None)
    if gateway is None or claw is None:
        return False
    if str(getattr(gateway, "fleet_mode", "") or "").strip().lower() not in {"", "auto"}:
        return False
    if not _is_loopback_gateway_host(getattr(gateway, "host", "")):
        return False
    if str(getattr(guardrail, "connector", "") or "").strip():
        return False
    connectors = getattr(guardrail, "connectors", None) or {}
    if isinstance(connectors, dict) and any(str(name).strip().lower() == "openclaw" for name in connectors):
        return False
    if str(getattr(claw, "mode", "") or "").strip().lower() != "openclaw":
        return False
    return not _openclaw_config_present(cfg) and not openclaw_binary_installed()
