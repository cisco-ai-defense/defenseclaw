"""Append ``expected_to_fail_at: [cli-registry]`` to every case the linter flagged.

Run:

    .venv/bin/python scripts/mark_expected_cli_registry.py

The script discovers the set of affected case ids by invoking
``dctest lint-cases --json``, then walks every YAML under
``src/dctest/cases/`` and patches the matching case in-place with
``ruamel.yaml`` to preserve comments and formatting.

Idempotent: re-running adds the marker only if not already present.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from ruamel.yaml import YAML

HARNESS = Path(__file__).resolve().parents[1]
CASES_DIR = HARNESS / "src" / "dctest" / "cases"
DCTEST = HARNESS / ".venv" / "bin" / "dctest"


def affected_case_ids() -> set[str]:
    proc = subprocess.run(
        [str(DCTEST), "lint-cases", "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        sys.exit(proc.returncode)
    data = json.loads(proc.stdout)
    return {f["case_id"] for f in data.get("unexpected", [])}


def main() -> int:
    affected = affected_case_ids()
    print(f"Linter flagged {len(affected)} unique case ids.")
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)

    edits = 0
    files_changed: set[Path] = set()
    for path in sorted(CASES_DIR.rglob("*.yaml")):
        with path.open("r", encoding="utf-8") as f:
            doc = yaml.load(f)
        if not doc or "cases" not in doc:
            continue
        changed = False
        for case in doc["cases"]:
            cid = case.get("id")
            if cid in affected:
                existing = case.get("expected_to_fail_at") or []
                if "cli-registry" not in existing:
                    case["expected_to_fail_at"] = ["cli-registry"]
                    edits += 1
                    changed = True
        if changed:
            with path.open("w", encoding="utf-8") as f:
                yaml.dump(doc, f)
            files_changed.add(path)
    print(f"Edited {edits} case entries across {len(files_changed)} files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
