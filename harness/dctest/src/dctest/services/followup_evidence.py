"""Gather followup evidence after a TestCase command runs.

Followup evidence is extra context the classify-prompt agent can quote
deterministically: file contents, file diffs, JSONPath evaluations, exit
code chains, and JSON Schema validation. The output is a list of small
artifact files written under the case directory plus a human-readable
summary that the prompt template injects.
"""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dctest.models.case import FollowupEvidenceSpec, TestCase


@dataclass
class CollectedEvidence:
    """A single followup-evidence artifact ready to surface in the prompt."""

    label: str
    kind: str
    ok: bool
    summary: str
    artifact_path: Path | None = None


def collect_followup_evidence(
    case: TestCase,
    *,
    stdout_path: Path,
    case_dir: Path,
    fixtures_root: Path | None = None,
) -> list[CollectedEvidence]:
    """Return the evidence artifacts produced by ``case.followup_evidence``.

    All artifacts are persisted under ``case_dir / "evidence" / <slug>.txt``
    so the agent and the report can reference them by path. JSON schema
    files are resolved relative to ``fixtures_root`` when provided.
    """
    if not case.followup_evidence and not case.expect_json_path and not case.expect_jsonschema:
        return []

    out_dir = case_dir / "evidence"
    out_dir.mkdir(parents=True, exist_ok=True)
    collected: list[CollectedEvidence] = []

    for spec in case.followup_evidence:
        collected.append(_collect_one(spec, stdout_path=stdout_path, out_dir=out_dir))

    if case.expect_json_path:
        collected.append(
            _collect_jsonpath_batch(
                expressions=case.expect_json_path,
                stdout_path=stdout_path,
                out_dir=out_dir,
            )
        )

    if case.expect_jsonschema:
        collected.append(
            _collect_jsonschema(
                schema_path=case.expect_jsonschema,
                stdout_path=stdout_path,
                out_dir=out_dir,
                fixtures_root=fixtures_root,
            )
        )

    return collected


def _collect_one(
    spec: FollowupEvidenceSpec, *, stdout_path: Path, out_dir: Path
) -> CollectedEvidence:
    slug = _slug(spec.label)
    artifact = out_dir / f"{slug}.txt"
    if spec.kind == "file_content":
        return _emit_file_content(spec, artifact)
    if spec.kind == "file_diff":
        return _emit_file_diff(spec, artifact)
    if spec.kind == "jsonpath":
        return _emit_jsonpath(spec, stdout_path=stdout_path, artifact=artifact)
    if spec.kind == "exit_code_chain":
        return _emit_exit_code_chain(spec, artifact)
    if spec.kind == "stdout_jsonschema":
        return _emit_stdout_jsonschema(spec, stdout_path=stdout_path, artifact=artifact)
    return CollectedEvidence(
        label=spec.label,
        kind=spec.kind,
        ok=False,
        summary=f"Unknown evidence kind: {spec.kind!r}",
    )


def _emit_file_content(
    spec: FollowupEvidenceSpec, artifact: Path
) -> CollectedEvidence:
    if not spec.path:
        return CollectedEvidence(
            label=spec.label,
            kind=spec.kind,
            ok=False,
            summary="file_content evidence missing 'path'",
        )
    p = Path(spec.path).expanduser()
    if not p.exists():
        msg = f"file not found: {p}"
        artifact.write_text(msg + "\n", encoding="utf-8")
        return CollectedEvidence(
            label=spec.label, kind=spec.kind, ok=False, summary=msg, artifact_path=artifact
        )
    body = p.read_text(encoding="utf-8", errors="replace")
    artifact.write_text(body, encoding="utf-8")
    return CollectedEvidence(
        label=spec.label,
        kind=spec.kind,
        ok=True,
        summary=f"captured {len(body)} bytes from {p}",
        artifact_path=artifact,
    )


def _emit_file_diff(spec: FollowupEvidenceSpec, artifact: Path) -> CollectedEvidence:
    if not spec.a or not spec.b:
        return CollectedEvidence(
            label=spec.label,
            kind=spec.kind,
            ok=False,
            summary="file_diff evidence missing 'a' or 'b'",
        )
    pa, pb = Path(spec.a).expanduser(), Path(spec.b).expanduser()
    if not pa.exists() or not pb.exists():
        msg = f"missing input: a_exists={pa.exists()}, b_exists={pb.exists()}"
        artifact.write_text(msg + "\n", encoding="utf-8")
        return CollectedEvidence(
            label=spec.label,
            kind=spec.kind,
            ok=False,
            summary=msg,
            artifact_path=artifact,
        )
    da = pa.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    db = pb.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    diff_lines = list(
        difflib.unified_diff(
            da, db, fromfile=str(pa), tofile=str(pb), n=3
        )
    )
    artifact.write_text("".join(diff_lines), encoding="utf-8")
    return CollectedEvidence(
        label=spec.label,
        kind=spec.kind,
        ok=True,
        summary=(
            f"{len(diff_lines)} diff lines between {pa.name} and {pb.name}"
            if diff_lines
            else f"files are identical: {pa.name} == {pb.name}"
        ),
        artifact_path=artifact,
    )


def _emit_jsonpath(
    spec: FollowupEvidenceSpec, *, stdout_path: Path, artifact: Path
) -> CollectedEvidence:
    if not spec.expression:
        return CollectedEvidence(
            label=spec.label,
            kind=spec.kind,
            ok=False,
            summary="jsonpath evidence missing 'expression'",
        )
    parsed, parse_err = _safe_parse_json(stdout_path)
    if parse_err:
        artifact.write_text(parse_err, encoding="utf-8")
        return CollectedEvidence(
            label=spec.label,
            kind=spec.kind,
            ok=False,
            summary=parse_err,
            artifact_path=artifact,
        )
    value, found = _eval_jsonpath(parsed, spec.expression)
    body = json.dumps(
        {"expression": spec.expression, "found": found, "value": value},
        indent=2,
        default=str,
    )
    artifact.write_text(body, encoding="utf-8")
    return CollectedEvidence(
        label=spec.label,
        kind=spec.kind,
        ok=found,
        summary=f"jsonpath {spec.expression!r} -> found={found}",
        artifact_path=artifact,
    )


def _emit_exit_code_chain(
    spec: FollowupEvidenceSpec, artifact: Path
) -> CollectedEvidence:
    if not spec.path:
        return CollectedEvidence(
            label=spec.label,
            kind=spec.kind,
            ok=False,
            summary="exit_code_chain evidence missing 'path'",
        )
    p = Path(spec.path).expanduser()
    if not p.exists():
        msg = f"no exit-code-chain file at {p}"
        artifact.write_text(msg + "\n", encoding="utf-8")
        return CollectedEvidence(
            label=spec.label,
            kind=spec.kind,
            ok=False,
            summary=msg,
            artifact_path=artifact,
        )
    raw = p.read_text(encoding="utf-8", errors="replace")
    codes: list[int] = []
    bad: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            codes.append(int(line))
        except ValueError:
            bad.append(line)
    artifact.write_text(
        json.dumps({"codes": codes, "non_integer_lines": bad}, indent=2),
        encoding="utf-8",
    )
    return CollectedEvidence(
        label=spec.label,
        kind=spec.kind,
        ok=not bad and bool(codes),
        summary=f"captured {len(codes)} exit codes; non_integer_lines={len(bad)}",
        artifact_path=artifact,
    )


def _emit_stdout_jsonschema(
    spec: FollowupEvidenceSpec, *, stdout_path: Path, artifact: Path
) -> CollectedEvidence:
    if not spec.schema_path:
        return CollectedEvidence(
            label=spec.label,
            kind=spec.kind,
            ok=False,
            summary="stdout_jsonschema evidence missing 'schema_path'",
        )
    return _validate_stdout_against_schema(
        schema_path=spec.schema_path,
        label=spec.label,
        stdout_path=stdout_path,
        artifact=artifact,
        fixtures_root=None,
    )


def _collect_jsonpath_batch(
    *, expressions: list[str], stdout_path: Path, out_dir: Path
) -> CollectedEvidence:
    artifact = out_dir / "expect_json_path.txt"
    parsed, parse_err = _safe_parse_json(stdout_path)
    if parse_err:
        artifact.write_text(parse_err, encoding="utf-8")
        return CollectedEvidence(
            label="expect_json_path",
            kind="jsonpath_batch",
            ok=False,
            summary=parse_err,
            artifact_path=artifact,
        )
    results: list[dict[str, Any]] = []
    all_ok = True
    for raw_expr in expressions:
        expr, assertion = raw_expr, "value"
        if raw_expr.strip().lower().endswith(" exists"):
            expr = raw_expr.rsplit(" ", 1)[0].strip()
            assertion = "exists"
        value, found = _eval_jsonpath(parsed, expr)
        ok = found if assertion == "exists" else (found and value not in (None, "", []))
        if not ok:
            all_ok = False
        results.append(
            {"expression": expr, "assertion": assertion, "found": found, "value": value, "ok": ok}
        )
    artifact.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    return CollectedEvidence(
        label="expect_json_path",
        kind="jsonpath_batch",
        ok=all_ok,
        summary=(
            f"{sum(1 for r in results if r['ok'])}/{len(results)} JSONPath assertions passed"
        ),
        artifact_path=artifact,
    )


def _collect_jsonschema(
    *,
    schema_path: str,
    stdout_path: Path,
    out_dir: Path,
    fixtures_root: Path | None,
) -> CollectedEvidence:
    artifact = out_dir / "expect_jsonschema.txt"
    return _validate_stdout_against_schema(
        schema_path=schema_path,
        label="expect_jsonschema",
        stdout_path=stdout_path,
        artifact=artifact,
        fixtures_root=fixtures_root,
    )


def _validate_stdout_against_schema(
    *,
    schema_path: str,
    label: str,
    stdout_path: Path,
    artifact: Path,
    fixtures_root: Path | None,
) -> CollectedEvidence:
    try:
        import jsonschema  # type: ignore
    except ImportError:
        msg = "jsonschema library not installed in the harness venv"
        artifact.write_text(msg + "\n", encoding="utf-8")
        return CollectedEvidence(
            label=label, kind="stdout_jsonschema", ok=False, summary=msg, artifact_path=artifact
        )

    resolved = _resolve_schema(schema_path, fixtures_root)
    if not resolved or not resolved.exists():
        msg = f"schema not found: {schema_path} (resolved: {resolved})"
        artifact.write_text(msg + "\n", encoding="utf-8")
        return CollectedEvidence(
            label=label, kind="stdout_jsonschema", ok=False, summary=msg, artifact_path=artifact
        )
    try:
        schema = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        msg = f"schema not valid JSON: {exc}"
        artifact.write_text(msg + "\n", encoding="utf-8")
        return CollectedEvidence(
            label=label, kind="stdout_jsonschema", ok=False, summary=msg, artifact_path=artifact
        )

    parsed, parse_err = _safe_parse_json(stdout_path)
    if parse_err:
        artifact.write_text(parse_err, encoding="utf-8")
        return CollectedEvidence(
            label=label, kind="stdout_jsonschema", ok=False, summary=parse_err, artifact_path=artifact
        )
    try:
        jsonschema.validate(parsed, schema)
    except jsonschema.ValidationError as exc:
        body = (
            f"schema path: {resolved}\n"
            f"validation error at {list(exc.absolute_path)!r}: {exc.message}\n"
        )
        artifact.write_text(body, encoding="utf-8")
        return CollectedEvidence(
            label=label,
            kind="stdout_jsonschema",
            ok=False,
            summary=f"schema validation failed: {exc.message}",
            artifact_path=artifact,
        )
    artifact.write_text(f"schema {resolved} validated OK\n", encoding="utf-8")
    return CollectedEvidence(
        label=label,
        kind="stdout_jsonschema",
        ok=True,
        summary=f"schema {resolved.name} passed",
        artifact_path=artifact,
    )


def _resolve_schema(schema_path: str, fixtures_root: Path | None) -> Path | None:
    p = Path(schema_path).expanduser()
    if p.is_absolute() and p.exists():
        return p
    if fixtures_root:
        return (fixtures_root / "schemas" / schema_path).resolve()
    return p.resolve()


def _safe_parse_json(stdout_path: Path) -> tuple[Any, str | None]:
    if not stdout_path.exists():
        return None, f"stdout not captured at {stdout_path}"
    try:
        raw = stdout_path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"could not read stdout: {exc}"
    if not raw.strip():
        return None, "stdout was empty"
    try:
        return json.loads(raw), None
    except json.JSONDecodeError as exc:
        snippet = raw.strip().splitlines()[0][:200] if raw.strip() else ""
        return None, f"stdout was not JSON: {exc.msg} (first line: {snippet!r})"


def _eval_jsonpath(parsed: Any, expr: str) -> tuple[Any, bool]:
    """Tiny dot-notation JSONPath evaluator.

    Supports ``$``, ``.key``, and ``[index]`` segments. Returns ``(value,
    found)``. The harness deliberately avoids a full jsonpath library to
    keep the dependency surface small; cases needing complex filters
    should write a ``followup_evidence`` of kind ``file_content`` or use
    a custom ``stdout_jsonschema``.
    """
    if not expr.startswith("$"):
        return None, False
    cur: Any = parsed
    rest = expr[1:]
    if not rest:
        return cur, True
    # Tokenize into ``.key`` and ``[index]`` / ``[*]`` chunks.
    import re

    tokens = re.findall(r"\.[A-Za-z0-9_\-]+|\[[^\]]+\]", rest)
    for tok in tokens:
        if cur is None:
            return None, False
        if tok.startswith("."):
            key = tok[1:]
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                return None, False
        elif tok.startswith("[") and tok.endswith("]"):
            inner = tok[1:-1].strip()
            if inner == "*":
                if not isinstance(cur, list):
                    return None, False
                # No way to express "all" without a list; just keep the list.
                return cur, True
            try:
                idx = int(inner)
            except ValueError:
                return None, False
            if isinstance(cur, list) and -len(cur) <= idx < len(cur):
                cur = cur[idx]
            else:
                return None, False
    return cur, True


def _slug(label: str) -> str:
    import re

    s = re.sub(r"[^a-zA-Z0-9]+", "-", label.strip().lower()).strip("-")
    return s or "evidence"
