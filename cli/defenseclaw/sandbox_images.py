"""Harness image records the OpenShell sandbox builder keeps.

Companion to ``internal/gateway/hook_contract_sandbox_evidence.go``.

In the layout the sandbox documentation recommends - no agent installed on the
host, the agent inside the harness image - the host has no agent version to
probe, so the hook-contract gate has nothing to resolve and refuses action
mode. The host does hold stronger evidence: DefenseClaw built the harness
image, pinned a harness version into it, and ``image.Builder.VerifyHooks`` set
``hook_fire_verified`` only after a probe proved that a denied tool call does
not run.

Two callers must agree on what that evidence is worth:

* the Go gateway's admission (``hook_contract_sandbox_evidence.go``), and
* the setup gate (``cmd_setup._check_connector_version_supported_for_setup``),
  which refuses before writing config and restarting services.

Keep the acceptance rules here in step with the Go side: a fire-verified record
only, a connector match, a harness version that resolves to a Known contract
under the *sandbox* (Linux) contract table, and an image this same DefenseClaw
release built.
"""

from __future__ import annotations

import json
import os
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
SANDBOX_ONLY_CONTRACT_CONNECTORS = frozenset({"kiro", "omnigent"})


@dataclass(frozen=True)
class HarnessImageEvidence:
    """The verified harness image a sandbox-only host can act on."""

    tag: str
    connector: str
    harness_version: str
    contract_id: str
    hook_fire_verified_at: str
    defenseclaw_version: str


def image_store_path(data_dir: str | os.PathLike[str] | None = None) -> Path:
    """Return the image store path for ``data_dir`` (or the default data dir)."""
    root = Path(data_dir) if data_dir else default_data_path()
    return root / IMAGE_STORE_RELATIVE


def verified_harness_contract(
    data_dir: str | os.PathLike[str] | None = None,
    connector: str = "",
    *,
    release: str | None = None,
) -> HarnessImageEvidence | None:
    """Return the newest verified harness image for ``connector``, or ``None``.

    ``None`` means "no evidence": a missing or unreadable store, no record, a
    record whose hooks were never proven to fire, a record for another
    connector, an image another release built, or a harness version whose
    sandbox contract is not Known. The caller keeps its host-based verdict.
    """
    name = normalize_connector(connector)
    if not name or name in SANDBOX_ONLY_CONTRACT_CONNECTORS:
        return None
    want_release = __version__ if release is None else release
    best: tuple[datetime, HarnessImageEvidence] | None = None
    for record in _read_records(data_dir):
        if not record.get("hook_fire_verified"):
            continue
        if normalize_connector(str(record.get("connector", "") or "")) != name:
            continue
        harness_version = str(record.get("harness_version", "") or "").strip()
        if not harness_version:
            continue
        image_release = str(record.get("defenseclaw_version", "") or "").strip()
        if want_release and image_release and image_release != want_release:
            continue
        compatibility = resolve_connector_contract(name, harness_version, platform_name="linux")
        if compatibility.status != STATUS_KNOWN or compatibility.contract is None:
            continue
        evidence = HarnessImageEvidence(
            tag=str(record.get("tag", "") or ""),
            connector=name,
            harness_version=harness_version,
            contract_id=compatibility.contract.contract_id,
            hook_fire_verified_at=str(record.get("hook_fire_verified_at", "") or ""),
            defenseclaw_version=image_release,
        )
        built_at = _parse_timestamp(str(record.get("built_at", "") or ""))
        if best is None or built_at >= best[0]:
            best = (built_at, evidence)
    return best[1] if best is not None else None


def _read_records(data_dir: str | os.PathLike[str] | None) -> list[dict]:
    path = image_store_path(data_dir)
    try:
        if path.stat().st_size > MAX_IMAGE_STORE_BYTES:
            return []
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        doc = json.loads(raw)
    except ValueError:
        return []
    records = doc.get("images") if isinstance(doc, dict) else None
    if not isinstance(records, list):
        return []
    return [record for record in records if isinstance(record, dict)]


def _parse_timestamp(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
