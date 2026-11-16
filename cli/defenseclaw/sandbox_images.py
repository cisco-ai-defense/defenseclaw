"""Harness image records the OpenShell sandbox builder keeps.

Companion to ``internal/gateway/hook_contract_sandbox_evidence.go`` (#1069).

In the layout the sandbox documentation recommends - no agent installed on the
host, the agent inside the harness image - the host has no agent version to
probe, so the hook-contract gate has nothing to resolve and refuses action
mode. The host does hold stronger evidence: DefenseClaw built the harness
image, pinned a harness version into it, and ``image.Builder.VerifyHooks`` set
``hook_fire_verified`` only after a probe proved that a denied tool call does
not run.

Two callers must agree on what that evidence is worth:

* the Go gateway's admission (``hook_contract_sandbox_evidence.go``), which is
  authoritative: it renders the exact build context a sandbox would run now
  (``image.Store.Current``) and asks Docker that the tag still names the
  verified image, and
* the setup gate (``cmd_setup._check_connector_version_supported_for_setup``),
  which refuses before writing config and restarting services.

This side cannot render the build context, so it applies every rule it can
check and is never more permissive than the gateway: the image must be the
newest one this store recorded for the connector, this host user, this
DefenseClaw release and the configured harness pin, base image and ingress
port; its hooks must be fire-verified (and, built for the MicroVM driver, its
MicroVM scenario must have passed); and its harness version must resolve to a
Known contract under the *sandbox* (Linux) contract table. A newer record that
is not verified (a rebuild) refuses the older one.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from defenseclaw import __version__
from defenseclaw.config import default_data_path
from defenseclaw.connector_contracts import (
    STATUS_KNOWN,
    normalize_connector,
    resolve_connector_contract,
)

# Mirrors internal/openshell/image: the store lives at
# <data_dir>/sandboxes/images.json and is bounded.
IMAGE_STORE_RELATIVE = Path("sandboxes") / "images.json"
MAX_IMAGE_STORE_BYTES = 4 << 20

# Connectors whose sandbox contracts exist only in the Go tables
# (internal/gateway/connector/<name>_sandbox.go) and not in the packaged
# hook_contracts.json manifest. The setup gate cannot resolve their sandbox
# contract, so it keeps its host-based verdict rather than accepting evidence
# the gateway might refuse.
SANDBOX_ONLY_CONTRACT_CONNECTORS = frozenset({"kiro"})

# Sandbox hooks always fail closed (connector.SandboxFailMode).
SANDBOX_FAIL_MODE = "closed"

# Mirrors openshell.DefaultBaseImage (internal/openshell/version.go): the base
# image.NewContext builds on when openshell.image.base is empty (GAP-0450).
# cli/tests/test_sandbox_images.py ties the two together.
DEFAULT_BASE_IMAGE = (
    "ghcr.io/nvidia/openshell-community/sandboxes/base"
    "@sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"
)

_IMAGE_VERSION_UNSAFE = re.compile(r"[^A-Za-z0-9.+_-]+")


@dataclass(frozen=True)
class HarnessImageEvidence:
    """The verified harness image a sandbox-only host can act on."""

    tag: str
    connector: str
    harness_version: str
    contract_id: str
    hook_fire_verified_at: str
    defenseclaw_version: str
    microvm: bool = False


@dataclass(frozen=True)
class SandboxImageSettings:
    """The config inputs of the image a sandbox would run (Go BuildSpec)."""

    harness_pin: str = ""
    base_image: str = ""
    ingress_port: int = 0
    driver: str = ""


def image_store_path(data_dir: str | os.PathLike[str] | None = None) -> Path:
    """Return the image store path for ``data_dir`` (or the default data dir)."""
    root = Path(data_dir) if data_dir else default_data_path()
    return root / IMAGE_STORE_RELATIVE


def image_version(release: str) -> str:
    """The release as the image records carry it (Go manager.ImageVersion)."""
    value = _IMAGE_VERSION_UNSAFE.sub("-", (release or "").strip()).strip(".+_-")
    value = value[:64]
    return value or "dev"


def image_kinds(platform_name: str, driver: str) -> tuple[bool, ...]:
    """Which images (MicroVM or not) a sandbox on this platform can run.

    Mirrors Go sandboxEvidenceTargets: the docker driver runs no MicroVM
    image; on Linux an unset, vm or auto driver may run either (GAP-0451).
    """
    docker = (driver or "").strip().lower() == "docker"
    if platform_name == "darwin":
        return (False,) if docker else (True,)
    if platform_name.startswith("linux"):
        return (False,) if docker else (False, True)
    return ()


def verified_harness_contract(
    data_dir: str | os.PathLike[str] | None = None,
    connector: str = "",
    *,
    release: str | None = None,
    settings: SandboxImageSettings | None = None,
    uid: int | None = None,
    platform_name: str | None = None,
) -> HarnessImageEvidence | None:
    """Return the current verified harness image for ``connector``, or ``None``.

    ``None`` means "no evidence": a missing or unreadable store or config, no
    record, a newest record whose hooks were not proven to fire, a record for
    another connector, host user, release, harness pin, base image or ingress
    port, or a harness version whose sandbox contract is not Known. The caller
    keeps its host-based verdict.
    """
    name = normalize_connector(connector)
    if not name or name in SANDBOX_ONLY_CONTRACT_CONNECTORS:
        return None
    if settings is None:
        settings = _load_settings(data_dir, name)
        if settings is None:
            return None
    if uid is None:
        getuid = getattr(os, "getuid", None)
        if getuid is None:
            return None
        uid = getuid()
    kinds = image_kinds(platform_name or sys.platform, settings.driver)
    if not kinds:
        return None
    want_release = image_version(__version__ if release is None else release)
    owner, records = _read_store(data_dir)
    for microvm in kinds:
        newest: tuple[datetime, dict] | None = None
        for record in records:
            if bool(record.get("microvm")) != microvm:
                continue
            if not _same_inputs(record, name, uid, owner, want_release, settings):
                continue
            built_at = _parse_timestamp(str(record.get("built_at", "") or ""))
            if newest is None or built_at >= newest[0]:
                newest = (built_at, record)
        if newest is None:
            continue
        evidence = _evidence(newest[1], name, microvm)
        if evidence is not None:
            return evidence
    return None


def _same_inputs(
    record: dict,
    name: str,
    uid: int,
    owner: str,
    release: str,
    settings: SandboxImageSettings,
) -> bool:
    if normalize_connector(str(record.get("connector", "") or "")) != name:
        return False
    if record.get("uid") != uid:
        return False
    if str(record.get("owner", "") or "") != owner:
        return False
    # A record that names no release cannot be shown to be this release's
    # evidence, so it is refused like a record from another release.
    if str(record.get("defenseclaw_version", "") or "").strip() != release:
        return False
    if str(record.get("fail_mode", "") or "") != SANDBOX_FAIL_MODE:
        return False
    if settings.harness_pin and str(record.get("harness_version", "") or "").strip() != settings.harness_pin:
        return False
    # An empty setting builds on the default base, as image.NewContext does.
    if str(record.get("base_image", "") or "") != (settings.base_image or DEFAULT_BASE_IMAGE):
        return False
    if settings.ingress_port and record.get("ingress_port") != settings.ingress_port:
        return False
    return True


def _evidence(record: dict, name: str, microvm: bool) -> HarnessImageEvidence | None:
    if record.get("hook_fire_verified") is not True:
        return None
    if microvm and record.get("microvm_verified") is not True:
        return None
    harness_version = str(record.get("harness_version", "") or "").strip()
    if not harness_version:
        return None
    compatibility = resolve_connector_contract(name, harness_version, platform_name="linux")
    if compatibility.status != STATUS_KNOWN or compatibility.contract is None:
        return None
    return HarnessImageEvidence(
        tag=str(record.get("tag", "") or ""),
        connector=name,
        harness_version=harness_version,
        contract_id=compatibility.contract.contract_id,
        hook_fire_verified_at=str(record.get("hook_fire_verified_at", "") or ""),
        defenseclaw_version=str(record.get("defenseclaw_version", "") or ""),
        microvm=microvm,
    )


def _load_settings(data_dir: str | os.PathLike[str] | None, name: str) -> SandboxImageSettings | None:
    """Read the image inputs from config.yaml; ``None`` when it cannot be read."""
    try:
        from defenseclaw import config as dc_config

        cfg = dc_config.load(data_dir=data_dir, without_guardrail_profiles=True)
        image = cfg.openshell.image
        return SandboxImageSettings(
            harness_pin=str((image.harness_versions or {}).get(name, "") or "").strip(),
            base_image=str(image.base or "").strip(),
            ingress_port=cfg.openshell.effective_ingress_port(cfg.gateway.api_port),
            driver=str(cfg.enterprise_openshell.driver or ""),
        )
    except Exception:  # noqa: BLE001 - no readable config means no evidence
        return None


def _read_store(data_dir: str | os.PathLike[str] | None) -> tuple[str, list[dict]]:
    path = image_store_path(data_dir)
    try:
        if path.stat().st_size > MAX_IMAGE_STORE_BYTES:
            return "", []
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return "", []
    try:
        doc = json.loads(raw)
    except ValueError:
        return "", []
    if not isinstance(doc, dict) or doc.get("version") != 1:
        return "", []
    records = doc.get("images")
    if not isinstance(records, list):
        return "", []
    owner = str(doc.get("owner", "") or "")
    return owner, [record for record in records if isinstance(record, dict)]


def _parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # Go writes nanoseconds; datetime.fromisoformat takes at most microseconds.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
