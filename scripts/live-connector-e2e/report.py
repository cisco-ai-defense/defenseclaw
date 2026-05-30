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
#   3. On ANY failing cell, builds a regression issue body and (when
#      --open-issue is passed and gh is authenticated) opens or updates a
#      GitHub issue labeled `connector-regression`.
#   4. Exits non-zero when failures exist so the report job is red — but it
#      NEVER edits validated_versions.json or hook_contracts.json. Bumping a
#      validated/approved version is a deliberate human action.

from __future__ import annotations

import argparse
import collections
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

ISSUE_LABEL = "connector-regression"
ISSUE_TITLE = "Connector live E2E regression"


def load_results(results_dir: Path) -> list[dict]:
    rows: list[dict] = []
    for path in sorted(results_dir.rglob("*.jsonl")):
        try:
            with path.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
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
            versions.setdefault(key, v)
        if status == "fail":
            failures.append((key[0], key[1], event, r.get("detail", "")))
    return cells, versions, failures


def render_summary(cells, versions) -> str:
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
    failing_events = [
        (c, o, e)
        for (c, o), events in cells.items()
        for e, s in events.items()
        if s == "fail"
    ]
    if failing_events:
        lines.append("## Failing events")
        lines.append("")
        for c, o, e in sorted(failing_events):
            lines.append(f"- `{c}` / `{o}` / `{e}`")
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
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
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

    rows = load_results(args.results_dir)
    if not rows:
        print("[report] no result rows found; nothing to report.", file=sys.stderr)
        return 0

    cells, versions, failures = summarize(rows)
    summary = render_summary(cells, versions)
    print(summary)
    if args.summary_file:
        try:
            with args.summary_file.open("a", encoding="utf-8") as f:
                f.write(summary + "\n")
        except OSError as exc:
            print(f"[report] could not write summary: {exc}", file=sys.stderr)

    if failures:
        body = build_issue_body(failures, versions, args.run_url)
        print("\n----- regression issue body -----\n" + body, file=sys.stderr)
        if args.open_issue:
            open_or_update_issue(body, args.run_url)
        return 1

    print("[report] all cells green.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
