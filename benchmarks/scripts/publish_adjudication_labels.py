"""Publish the S2 disagreement adjudication to the existing private HF label repo.

Extends `Vineethsain/defenseclaw-toolcall-security-labels-v1` with a new subdirectory rather
than creating a second repo: both artifacts are the same genre (grade-C labels from
`openai.gpt-oss-120b-1:0` on the Bedrock batch API, private, evaluation-only, never-train)
and they are governed by the same benchmarks/system_one/hf-data-policy.json. One private
evidence repo is easier to keep consistent than two.

What is withheld and why
------------------------
Every one of the 2,133 queue cases comes from a source manifest marked
`redistribution: download-only`, so no source payload is published - only the benchmark's own
opaque case ids, the four backends' value-free actions, and the adjudicator's structured
labels. The policy's `forbidden_artifacts` also names `free_form_provider_rationales`, so the
adjudicator's REASON line and its APPARENT_TASK line (a free-form paraphrase derived from a
download-only payload) stay local and are dropped here. The aggregate report is published
with its reply-text examples stripped for the same reason.

No mcptox case appears in this queue (that corpus is `aggregate-only` and disabled in
datasets.lock.json); the check is asserted rather than assumed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

WITHHELD_LABEL_FIELDS = ("reason", "apparent_task")
WITHHELD_REPORT_KEYS = ("unparsed_examples", "error_examples")
FORBIDDEN_SOURCE_SUBSTRINGS = ("mcptox",)

README_SECTION = """
## S2 backend-disagreement adjudication v1 (`data/s2-disagreement-adjudication-v1/`)

**Independent adjudication, not ground truth.** Grade C (model-adjudicated).

At S2 the three System One backends disagree on 49.87% of cases (2,133 of 4,277), rising to
55.51% once the Go deterministic tier votes as a fourth. The published card named a
human-adjudicated sample of that queue as the highest-value labelling investment available,
and noted that no blinded review had been done. A 49.87% disagreement rate also means no
single backend's number can serve as ground truth for the others.

Human adjudication was unavailable, so the **entire** queue (a census, not a sample) was
adjudicated by `openai.gpt-oss-120b-1:0` on the Amazon Bedrock batch API - a different
architecture and vendor from all three disputants and from the Go rule engine. The prompt is
**blinded**: it never reveals what any disputant decided. It uses the benchmark's own
three-way allow/confirm/block scale with the I3 policy text and Q2/Q0 criteria copied
verbatim, and asks separately for intrinsic danger and task alignment, mirroring the Q4 split
that is the architecture under test.

This is one model's opinion. It may share biases with the disputants. It is a tiebreaker that
makes the queue actionable; it does not establish accuracy.

### Fields

| field | meaning |
|---|---|
| `case_id` | System One S2 case id |
| `truth_grade` | A/B/C/D per `benchmark_inventory_system_one_sources.truth_grade` |
| `surface` | `action` or `stateful` |
| `pattern` / `pattern_class` | the disagreement shape, `openjev|diffgemma|gemma4` |
| `openjev`, `diffgemma`, `gemma4`, `deterministic` | each voter's action on this case |
| `adjudicated_disposition` | `allow` / `confirm` / `block` |
| `adjudicated_intrinsic` | true = harmful regardless of what was asked for |
| `adjudicated_serves_task` | does every call advance the inferred task |
| `adjudicated_confidence` | `high` / `medium` / `low` |

### Withheld

Source payloads (every case is `redistribution: download-only`), and the adjudicator's
free-form `REASON` and `APPARENT_TASK` lines, which
`benchmarks/system_one/hf-data-policy.json` classes as
`free_form_provider_rationales`. Labels, ids and aggregate metrics only.
"""


def sanitize_report(report: dict[str, Any]) -> dict[str, Any]:
    out = json.loads(json.dumps(report))
    parse = out.get("parse")
    if isinstance(parse, dict):
        for key in WITHHELD_REPORT_KEYS:
            if key in parse:
                parse[key] = f"withheld: {len(parse[key])} item(s); free-form provider text"
    return out


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--labels", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--queue", type=Path, required=True)
    p.add_argument("--repo", default="Vineethsain/defenseclaw-toolcall-security-labels-v1")
    p.add_argument("--stage", type=Path, required=True)
    p.add_argument("--subdir", default="s2-disagreement-adjudication-v1")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    from huggingface_hub import HfApi

    api = HfApi()

    # --- privacy verification BEFORE any upload -------------------------------------
    before = api.repo_info(args.repo, repo_type="dataset")
    if not before.private:
        raise SystemExit(f"ABORT: {args.repo} is public; refusing to upload evaluation-only labels")

    # --- redistribution guard ------------------------------------------------------
    for line in args.queue.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        blob = (row.get("dataset", "") + " " + row.get("case_id", "")).lower()
        for banned in FORBIDDEN_SOURCE_SUBSTRINGS:
            if banned in blob:
                raise SystemExit(f"ABORT: {banned} case {row['case_id']} must not be published")

    # --- stage sanitized artifacts -------------------------------------------------
    data_dir = args.stage / "data" / args.subdir
    man_dir = args.stage / "manifests"
    data_dir.mkdir(parents=True, exist_ok=True)
    man_dir.mkdir(parents=True, exist_ok=True)

    kept = 0
    labels_path = data_dir / "labels.jsonl"
    with labels_path.open("w", encoding="utf-8") as out:
        for line in args.labels.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            for field in WITHHELD_LABEL_FIELDS:
                row.pop(field, None)
            out.write(json.dumps(row, sort_keys=True) + "\n")
            kept += 1

    report = json.loads(args.report.read_text(encoding="utf-8"))
    (man_dir / f"{args.subdir}-report.json").write_text(
        json.dumps(sanitize_report(report), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    (man_dir / f"{args.subdir}-batch-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    checks = {
        "rows": kept,
        "withheld_label_fields": list(WITHHELD_LABEL_FIELDS),
        "labels_sha256": hashlib.sha256(labels_path.read_bytes()).hexdigest(),
        "repo_private_before": bool(before.private),
        "parent_revision": before.sha,
    }
    leaked = [f for f in WITHHELD_LABEL_FIELDS
              if f'"{f}"' in labels_path.read_text(encoding="utf-8")]
    if leaked:
        raise SystemExit(f"ABORT: withheld field(s) present in staged labels: {leaked}")

    if args.dry_run:
        print(json.dumps({"dry_run": True, **checks}, indent=2, sort_keys=True))
        return 0

    # --- README: append our section, never rewrite the existing card ---------------
    readme_local = args.stage / "README.md"
    existing = api.hf_hub_download(args.repo, "README.md", repo_type="dataset")
    text = Path(existing).read_text(encoding="utf-8")
    if "S2 backend-disagreement adjudication v1" not in text:
        text = text.rstrip() + "\n" + README_SECTION
    readme_local.write_text(text, encoding="utf-8")

    commit = api.upload_folder(
        repo_id=args.repo,
        repo_type="dataset",
        folder_path=str(args.stage),
        commit_message="Add S2 backend-disagreement independent adjudication v1 (2,133-case census)",
    )
    after = api.repo_info(args.repo, repo_type="dataset")
    if not after.private:
        raise SystemExit("ABORT: repo is public AFTER upload; make it private immediately")

    result = {
        **checks,
        "commit_oid": getattr(commit, "oid", None),
        "commit_url": getattr(commit, "commit_url", None),
        "revision_sha_after": after.sha,
        "repo_private_after": bool(after.private),
        "files_after": sorted(s.rfilename for s in after.siblings),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
