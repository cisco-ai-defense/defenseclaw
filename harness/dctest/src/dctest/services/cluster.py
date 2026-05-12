"""Group failed CaseResult records by a normalized stderr fingerprint.

Used by ``dctest cluster <run-id>`` and the ``Root-cause clusters`` section
of the markdown report. The goal is to reduce 65+ fail records into ~12-18
clusters, each representing a single underlying bug or environment issue.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel

from dctest.config import get_settings
from dctest.models import CaseResult, Verdict
from dctest.services import run_store

_PATH_RE = re.compile(r"\b/[\w./\-]+\b")
_HEX_RE = re.compile(r"\b[0-9a-f]{8,}\b")
_NUM_RE = re.compile(r"\d+")
_QUOTE_RE = re.compile(r'(["\'])[^"\']*\1')


def fingerprint(stderr: str, exit_code: int) -> str:
    """Compute a stable signature for a (stderr, exit_code) pair.

    The signature normalizes paths, hex hashes, integer values, and quoted
    arguments so that "FileNotFoundError: /tmp/xxx-12345" and
    "FileNotFoundError: /tmp/yyy-67890" collapse to the same cluster.
    """
    first_line = (stderr.strip().splitlines() or [""])[0][:200]
    norm = _PATH_RE.sub("<path>", first_line)
    norm = _HEX_RE.sub("<hex>", norm)
    norm = _NUM_RE.sub("<n>", norm)
    norm = _QUOTE_RE.sub('"<arg>"', norm)
    digest = hashlib.sha1(norm.encode("utf-8")).hexdigest()[:10]  # noqa: S324
    return f"{exit_code}::{digest}"


@dataclass
class ClusterMember:
    cell_id: str
    case_id: str
    verdict: str
    expected_to_fail_at: list[str] = field(default_factory=list)
    stdout_path: str = ""
    stderr_path: str = ""


@dataclass
class Cluster:
    fingerprint: str
    sample_line: str  # the canonical first-line of stderr (un-normalized)
    exit_code: int
    members: list[ClusterMember] = field(default_factory=list)
    all_expected: bool = False

    def to_summary(self) -> ClusterSummary:
        return ClusterSummary(
            fingerprint=self.fingerprint,
            sample_line=self.sample_line,
            exit_code=self.exit_code,
            member_count=len(self.members),
            all_expected=self.all_expected,
            members=[ClusterMemberRecord(**vars(m)) for m in self.members],
        )


class ClusterMemberRecord(BaseModel):
    cell_id: str
    case_id: str
    verdict: str
    expected_to_fail_at: list[str] = []
    stdout_path: str = ""
    stderr_path: str = ""


class ClusterSummary(BaseModel):
    fingerprint: str
    sample_line: str
    exit_code: int
    member_count: int
    all_expected: bool
    members: list[ClusterMemberRecord] = []


def _read_case_results(run_id: str) -> list[CaseResult]:
    settings = get_settings()
    cells = run_store.list_cells(settings.runs_root, run_id)
    results: list[CaseResult] = []
    for cell in cells:
        case_root = run_store.cell_dir(settings.runs_root, run_id, cell.id) / "cases"
        if not case_root.exists():
            continue
        for case_dir in sorted(case_root.iterdir()):
            r_path = case_dir / "result.json"
            if not r_path.exists():
                continue
            try:
                results.append(
                    CaseResult.model_validate_json(r_path.read_text(encoding="utf-8"))
                )
            except Exception:  # noqa: BLE001 - tolerate corrupt files
                continue
    return results


def _expected_map() -> dict[str, list[str]]:
    """Build a map of case_id -> expected_to_fail_at by reloading case YAMLs.

    Avoids a hard dependency on case_loader at import-time since
    cluster.py is sometimes invoked from contexts that don't want to
    eagerly parse 44 YAMLs.
    """
    from dctest.services import case_loader

    out: dict[str, list[str]] = {}
    for case in case_loader.load_all_cases():
        out[case.id] = list(case.expected_to_fail_at)
    return out


def cluster_run(run_id: str) -> list[Cluster]:
    """Build clusters from all failed/blocked case results in ``run_id``."""
    results = _read_case_results(run_id)
    expected = _expected_map()

    grouped: dict[str, Cluster] = {}
    for r in results:
        if r.verdict not in (Verdict.FAIL, Verdict.BLOCKED):
            continue
        stderr_text = _read_text(r.stderr_path)
        sample_line = (
            (stderr_text.strip().splitlines() or [""])[0][:200].strip()
            or f"exit_code={r.exit_code}, no stderr"
        )
        fp = fingerprint(stderr_text, r.exit_code)
        cluster = grouped.get(fp)
        if cluster is None:
            cluster = Cluster(
                fingerprint=fp, sample_line=sample_line, exit_code=r.exit_code
            )
            grouped[fp] = cluster
        cluster.members.append(
            ClusterMember(
                cell_id=r.cell_id,
                case_id=r.case_id,
                verdict=r.verdict.value,
                expected_to_fail_at=expected.get(r.case_id, []),
                stdout_path=str(r.stdout_path),
                stderr_path=str(r.stderr_path),
            )
        )

    # Mark a cluster ``all_expected`` if every member has any non-empty
    # expected_to_fail_at value. That's the signal the cluster is a
    # known-bug bucket rather than a fresh regression.
    for cluster in grouped.values():
        cluster.all_expected = all(
            bool(m.expected_to_fail_at) for m in cluster.members
        )

    # Stable order: largest first, then by fingerprint.
    return sorted(
        grouped.values(),
        key=lambda c: (-len(c.members), c.fingerprint),
    )


def save_clusters(run_id: str, clusters: list[Cluster]) -> Path:
    """Persist clusters to ``runs/<run_id>/clusters.json``."""
    settings = get_settings()
    out_path = settings.runs_root / run_id / "clusters.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [c.to_summary().model_dump() for c in clusters]
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out_path


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
