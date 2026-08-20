#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
#
# Connector live-E2E reporter / regression radar (alert-only).
#
# Reads the per-cell result JSONL files produced by lib/common.sh
# (dc_record_result) — one JSON object per line:
#
#     {"connector","os","event","status","version","detail"}
#
# and:
#   1. Renders a connector x os x event matrix to the GitHub job summary.
#   2. Records the resolved upstream version per connector x os.
#   3. On candidate-regression classified failures, builds a regression issue
#      body and (when --open-issue is passed and gh is authenticated) opens or
#      updates a GitHub issue labeled `connector-regression`.
#   4. Exits non-zero when failures exist so the report job is red — but it
#      NEVER edits validated_versions.json or hook_contracts.json. Bumping a
#      validated/approved version is a deliberate human action.

from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

ISSUE_LABEL = "connector-regression"
ISSUE_TITLE = "Connector live E2E regression"
RADAR_ARTIFACT_PREFIX = "connector-version-radar-"
RADAR_DETECTION_ARTIFACT = f"{RADAR_ARTIFACT_PREFIX}detection"
LAB_FAILURE_ACTIONS = {
    "auth_failure": "Refresh the connector login, then rerun the known-good baseline.",
    "baseline_failure": "Repair or revalidate the known-good baseline before testing a candidate.",
    "infrastructure_failure": "Repair the connector lab infrastructure, then rerun the comparison.",
}
LAB_FAILURE_CLASSIFICATIONS = frozenset(LAB_FAILURE_ACTIONS)
KNOWN_CLASSIFICATIONS = LAB_FAILURE_CLASSIFICATIONS | {
    "candidate_regression",
    "pass",
}
RESULT_ROW_STRING_FIELDS = (
    "connector",
    "os",
    "event",
    "status",
    "version",
    "detail",
)


@dataclasses.dataclass(frozen=True)
class Classification:
    root: Path
    connector: str
    classification: str
    baseline_version: str
    candidate_version: str
    baseline_status: str
    candidate_status: str
    evidence_error: str = ""
    result_rows: tuple[dict, ...] = dataclasses.field(
        default=(), repr=False, compare=False
    )

    @property
    def is_failure(self) -> bool:
        return bool(self.evidence_error) or self.classification != "pass"

    @property
    def is_candidate_regression(self) -> bool:
        return self.classification == "candidate_regression" and not self.evidence_error

    @property
    def is_lab_failure(self) -> bool:
        return bool(self.evidence_error) or self.classification in LAB_FAILURE_CLASSIFICATIONS


def _path_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _is_result_row(row: object) -> bool:
    return isinstance(row, dict) and all(
        isinstance(row.get(field), str) for field in RESULT_ROW_STRING_FIELDS
    )


def _load_results_with_integrity(
    results_dir: Path, *, roots: list[Path] | None = None
) -> tuple[list[dict], bool]:
    rows: list[dict] = []
    evidence_error = False
    for path in sorted(results_dir.rglob("*.jsonl")):
        if roots is not None and not any(_path_under(path, root) for root in roots):
            continue
        try:
            with path.open(encoding="utf-8") as f:
                for line_number, raw_line in enumerate(f, start=1):
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError:
                        evidence_error = True
                        print(
                            f"[report] ignored malformed JSON result row in {path}:{line_number}.",
                            file=sys.stderr,
                        )
                        continue
                    if _is_result_row(row):
                        rows.append(row)
                    else:
                        evidence_error = True
                        print(
                            f"[report] ignored structurally invalid result row in {path}:{line_number}.",
                            file=sys.stderr,
                        )
        except (OSError, UnicodeError) as exc:
            evidence_error = True
            print(f"[report] could not read result file {path}: {exc}", file=sys.stderr)
            continue
    return rows, evidence_error


def load_results(results_dir: Path, *, roots: list[Path] | None = None) -> list[dict]:
    rows, _evidence_error = _load_results_with_integrity(results_dir, roots=roots)
    return rows


def classification_paths(results_dir: Path) -> list[Path]:
    return sorted(results_dir.rglob("classification.json"))


def radar_artifact_roots(results_dir: Path) -> list[Path]:
    roots = {path.parent for path in classification_paths(results_dir)}
    candidates = [results_dir, *results_dir.rglob(f"{RADAR_ARTIFACT_PREFIX}*")]
    roots.update(
        path
        for path in candidates
        if path.is_dir()
        and path.name.startswith(RADAR_ARTIFACT_PREFIX)
        and path.name != RADAR_DETECTION_ARTIFACT
    )
    return sorted(roots)


def _matches_candidate_failure(row: dict, item: Classification) -> bool:
    return (
        row.get("connector") == item.connector
        and row.get("status") == "fail"
        and str(row.get("event", "")).startswith("candidate-")
        and str(row.get("version") or "unknown") == item.candidate_version
    )


def _contradicts_candidate_regression(row: dict) -> bool:
    return row.get("status") == "fail" and str(row.get("event", "")).startswith(
        "baseline"
    )


def load_classifications(results_dir: Path) -> list[Classification]:
    classifications: list[Classification] = []
    paths_by_root = {path.parent: path for path in classification_paths(results_dir)}
    for root in radar_artifact_roots(results_dir):
        path = paths_by_root.get(root)
        if path is None:
            result_rows = tuple(load_results(root))
            connectors = {
                connector.strip()
                for row in result_rows
                if isinstance((connector := row.get("connector")), str)
                and connector.strip()
                and connector.strip() != "unknown"
            }
            connector = next(iter(connectors)) if len(connectors) == 1 else root.name
            classifications.append(
                Classification(
                    root=root,
                    connector=connector,
                    classification="invalid_classification",
                    baseline_version="unknown",
                    candidate_version="unknown",
                    baseline_status="unknown",
                    candidate_status="unknown",
                    evidence_error="classification evidence is missing",
                    result_rows=result_rows,
                )
            )
            continue

        evidence_error = ""
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            loaded = {}
            evidence_error = "classification evidence is unreadable or malformed"

        if not isinstance(loaded, dict):
            payload: dict = {}
            evidence_error = evidence_error or "classification evidence is not a JSON object"
        else:
            payload = loaded

        classification = payload.get("classification")
        if not isinstance(classification, str) or classification not in KNOWN_CLASSIFICATIONS:
            classification = "invalid_classification"
            evidence_error = evidence_error or "classification evidence has an unknown outcome"

        connector = payload.get("connector")
        if not isinstance(connector, str) or not connector.strip():
            connector = path.parent.name
        else:
            connector = connector.strip()

        baseline_version = str(payload.get("baseline_version") or "unknown")
        candidate_version = str(payload.get("candidate_version") or "unknown")
        baseline_status = str(payload.get("baseline_status") or "unknown")
        candidate_status = str(payload.get("candidate_status") or "unknown")

        # A candidate regression is the only classification that may promote
        # raw JSONL failures into regression issue content. Require the
        # harness's proof that the baseline passed and the candidate failed;
        # stale or contradictory metadata must fail closed as a lab problem.
        if classification == "candidate_regression" and (
            baseline_status != "pass" or candidate_status != "fail" or candidate_version == "unknown"
        ):
            evidence_error = "candidate-regression evidence contradicts the harness contract"
        if classification == "candidate_regression" and not evidence_error:
            expected_artifact = (
                f"{RADAR_ARTIFACT_PREFIX}{connector}-{candidate_version}"
            )
            if root.name != expected_artifact:
                evidence_error = (
                    "candidate-regression evidence does not match its artifact identity"
                )

        result_rows: tuple[dict, ...] = ()
        if not evidence_error:
            loaded_rows, result_evidence_error = _load_results_with_integrity(path.parent)
            if classification == "candidate_regression":
                result_rows = tuple(loaded_rows)
            if result_evidence_error:
                kind = (
                    "candidate-regression"
                    if classification == "candidate_regression"
                    else "classified radar"
                )
                evidence_error = f"{kind} result evidence is unreadable or malformed"

        item = Classification(
            root=path.parent,
            connector=connector,
            classification=classification,
            baseline_version=baseline_version,
            candidate_version=candidate_version,
            baseline_status=baseline_status,
            candidate_status=candidate_status,
            evidence_error=evidence_error,
            result_rows=result_rows,
        )
        if (
            item.classification == "candidate_regression"
            and not item.evidence_error
            and any(_contradicts_candidate_regression(row) for row in item.result_rows)
        ):
            item = dataclasses.replace(
                item,
                evidence_error="candidate-regression evidence contains a failed baseline row",
            )
        if (
            item.classification == "candidate_regression"
            and not item.evidence_error
            and not any(_matches_candidate_failure(row, item) for row in item.result_rows)
        ):
            item = dataclasses.replace(
                item,
                evidence_error="candidate-regression evidence has no matching failed candidate row",
            )
        classifications.append(item)
    return classifications


def candidate_regression_roots(results_dir: Path) -> list[Path]:
    return [item.root for item in load_classifications(results_dir) if item.is_candidate_regression]


def load_candidate_regression_results(classifications: list[Classification]) -> list[dict]:
    rows: list[dict] = []
    for item in classifications:
        if not item.is_candidate_regression:
            continue
        # Classification metadata and row evidence must agree before a
        # failure can enter candidate-regression content.
        rows.extend(row for row in item.result_rows if _matches_candidate_failure(row, item))
    return rows


def summarize(rows: list[dict]):
    """Return (cells, versions, failures).

    cells:    {(connector, os): {event: status}}
    versions: {(connector, os): version}
    failures: list[(connector, os, event, detail)]
    """
    cells: dict[tuple[str, str], dict[str, str]] = collections.defaultdict(dict)
    versions: dict[tuple[str, str], str] = {}
    failures: list[tuple[str, str, str, str]] = []
    for r in rows:
        key = (r.get("connector", "?"), r.get("os", "?"))
        event = r.get("event", "?")
        status = r.get("status", "?")
        cells[key][event] = status
        v = r.get("version") or ""
        if v and v != "unknown":
            # Upgrade-regression artifacts contain the passing baseline first.
            # Prefer the candidate phase so regression issues name the release
            # that actually failed instead of the known-good baseline.
            if str(event).startswith("candidate-"):
                versions[key] = v
            else:
                versions.setdefault(key, v)
        if status == "fail":
            failures.append((key[0], key[1], event, r.get("detail", "")))
    return cells, versions, failures


def _markdown_cell(value: object) -> str:
    return str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def _render_lab_failures(classifications: list[Classification]) -> list[str]:
    lab_failures = [item for item in classifications if item.is_lab_failure]
    if not lab_failures:
        return []

    lines = [
        "## Operational lab failures (not candidate regressions)",
        "",
        "| Connector | Classification | Baseline | Candidate | Required action |",
        "|---|---|---|---|---|",
    ]
    for item in sorted(lab_failures, key=lambda value: (value.connector, value.root)):
        if item.evidence_error:
            classification = f"{item.classification} (invalid evidence)"
            action = item.evidence_error
        else:
            classification = item.classification
            action = LAB_FAILURE_ACTIONS[item.classification]
        connector = _markdown_cell(item.connector)
        classification = _markdown_cell(classification)
        baseline = _markdown_cell(item.baseline_version)
        candidate = _markdown_cell(item.candidate_version)
        action = _markdown_cell(action)
        lines.append(f"| {connector} | {classification} | {baseline} | {candidate} | {action} |")
    lines.append("")
    return lines


def render_summary(
    cells,
    versions,
    *,
    classifications: list[Classification] | None = None,
    candidate_failures: list[tuple[str, str, str, str]] | None = None,
) -> str:
    lines = ["# Connector live E2E results", ""]
    lines.append("| Connector | OS | Version | Result | Events (pass/fail/skip) |")
    lines.append("|---|---|---|---|---|")
    for (connector, os_), events in sorted(cells.items()):
        n_pass = sum(1 for s in events.values() if s == "pass")
        n_fail = sum(1 for s in events.values() if s == "fail")
        n_skip = sum(1 for s in events.values() if s == "skip")
        verdict = "FAIL" if n_fail else ("PASS" if n_pass else "SKIP")
        version = versions.get((connector, os_), "unknown")
        lines.append(
            f"| {connector} | {os_} | {version} | {verdict} | "
            f"{n_pass}/{n_fail}/{n_skip} |"
        )
    lines.append("")
    failing_events = {(c, o, e) for (c, o), events in cells.items() for e, s in events.items() if s == "fail"}
    if classifications is None:
        if failing_events:
            lines.append("## Failing events")
            lines.append("")
            for c, o, e in sorted(failing_events):
                lines.append(f"- `{c}` / `{o}` / `{e}`")
            lines.append("")
        return "\n".join(lines)

    lines.extend(_render_lab_failures(classifications))
    candidate_events = {(connector, os_, event) for connector, os_, event, _detail in (candidate_failures or [])}
    lab_events = failing_events - candidate_events
    if lab_events:
        lines.append("## Lab failure events (not candidate regressions)")
        lines.append("")
        for connector, os_, event in sorted(lab_events):
            lines.append(f"- `{connector}` / `{os_}` / `{event}`")
        lines.append("")
    if candidate_events:
        lines.append("## Candidate regression events")
        lines.append("")
        for connector, os_, event in sorted(candidate_events):
            lines.append(f"- `{connector}` / `{os_}` / `{event}`")
        lines.append("")
    return "\n".join(lines)


def build_issue_body(failures, versions, run_url: str) -> str:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    lines = [
        "A live connector hook E2E cell that previously passed is now failing "
        "against the latest upstream agent release.",
        "",
        f"- Detected: {now}",
        f"- Run: {run_url or 'n/a'}",
        "",
        "## Failing cells",
        "",
        "| Connector | OS | Event | Version | Detail |",
        "|---|---|---|---|---|",
    ]
    for connector, os_, event, detail in sorted(failures):
        version = versions.get((connector, os_), "unknown")
        safe_detail = (detail or "").replace("|", "\\|")
        lines.append(f"| {connector} | {os_} | {event} | {version} | {safe_detail} |")
    lines += [
        "",
        "## Next steps (alert-only — no automatic version bump)",
        "",
        "1. Triage whether DefenseClaw's decode/map/respond needs a fix, or the "
        "upstream agent changed its hook contract.",
        "2. If DefenseClaw must drop support for the new version, set "
        "`max_exclusive` (or raise `min_inclusive`) in "
        "`cli/defenseclaw/inventory/hook_contracts.json` and "
        "`internal/gateway/connector/hook_contract.go`.",
        "3. Once green again, update `last_validated_version` in "
        "`cli/defenseclaw/inventory/validated_versions.json`.",
    ]
    return "\n".join(lines)


def gh(*args: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["gh", *args],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode, (proc.stdout + proc.stderr)
    except FileNotFoundError:
        return 127, "gh CLI not found"


def open_or_update_issue(body: str, run_url: str) -> None:
    """Open a new connector-regression issue or comment on the existing one."""
    rc, out = gh(
        "issue", "list",
        "--label", ISSUE_LABEL,
        "--state", "open",
        "--json", "number",
        "--limit", "1",
    )
    if rc != 0:
        print(f"[report] could not list issues (gh rc={rc}): {out}", file=sys.stderr)
        return
    try:
        existing = json.loads(out or "[]")
    except json.JSONDecodeError:
        existing = []
    if existing:
        number = str(existing[0]["number"])
        rc, out = gh("issue", "comment", number, "--body", body)
        print(f"[report] commented on issue #{number} (rc={rc})")
    else:
        rc, out = gh(
            "issue", "create",
            "--title", f"{ISSUE_TITLE} ({datetime.date.today().isoformat()})",
            "--label", ISSUE_LABEL,
            "--body", body,
        )
        print(f"[report] created regression issue (rc={rc}): {out.strip()}")


def main() -> int:
    # This module documents itself with leading "#" comments, not a string
    # literal, so __doc__ is None — guard against it instead of crashing the
    # whole report job on startup with AttributeError before any cell result is
    # ever read.
    description = (
        __doc__ or "Connector live-E2E reporter / regression radar (alert-only)."
    ).strip().splitlines()[0]
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--results-dir", type=Path, required=True,
                        help="Directory of per-cell *.jsonl result files (artifacts).")
    parser.add_argument("--summary-file", type=Path,
                        default=Path(os.environ["GITHUB_STEP_SUMMARY"])
                        if os.environ.get("GITHUB_STEP_SUMMARY") else None,
                        help="Markdown summary output (default: $GITHUB_STEP_SUMMARY).")
    parser.add_argument("--open-issue", action="store_true",
                        help="Open/update a connector-regression issue on failure.")
    parser.add_argument("--run-url", default=os.environ.get("RUN_URL", ""))
    args = parser.parse_args()

    if not args.results_dir.exists():
        print(f"[report] results dir {args.results_dir} missing — no cells ran?",
              file=sys.stderr)
        return 0

    radar_roots = radar_artifact_roots(args.results_dir)
    classifications = load_classifications(args.results_dir) if radar_roots else []
    rows = load_results(args.results_dir)
    if not rows and not radar_roots:
        print("[report] no result rows found; nothing to report.", file=sys.stderr)
        return 0

    cells, versions, failures = summarize(rows)
    issue_failures = failures
    issue_versions = versions
    if radar_roots:
        issue_rows = load_candidate_regression_results(classifications)
        _issue_cells, issue_versions, issue_failures = summarize(issue_rows)
    summary = render_summary(
        cells,
        versions,
        classifications=classifications if radar_roots else None,
        candidate_failures=issue_failures if radar_roots else None,
    )
    print(summary)
    if args.summary_file:
        try:
            with args.summary_file.open("a", encoding="utf-8") as f:
                f.write(summary + "\n")
        except OSError as exc:
            print(f"[report] could not write summary: {exc}", file=sys.stderr)

    classification_failures = [item for item in classifications if item.is_failure]
    if failures or classification_failures:
        if issue_failures:
            body = build_issue_body(issue_failures, issue_versions, args.run_url)
            print("\n----- regression issue body -----\n" + body, file=sys.stderr)
            if args.open_issue:
                open_or_update_issue(body, args.run_url)
        elif radar_roots:
            action = "file" if args.open_issue else "report"
            print(
                f"[report] no candidate-regression failures to {action}.",
                file=sys.stderr,
            )
        return 1

    print("[report] all cells green.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
