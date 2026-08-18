#!/usr/bin/env python3
"""Prove that the released observability runtime has no live v7 owner.

This is deliberately a semantic allowlist, not a checked-in inventory of line
counts or file hashes. Additive generated families do not change the proof.
Only a new use of a retired runtime API, config field, writer, sink, or direct
provider does.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = ("internal", "cmd", "cli/defenseclaw")
SOURCE_SUFFIXES = {".go", ".py", ".sh"}
ADDITIONAL_RUNTIME_SOURCES = (
    ".github/workflows/e2e.yml",
    "scripts/test-e2e-cli.py",
    "packaging/macos/install.sh",
    "packaging/macos/lib/installer_lib.sh",
    "scripts/bundle-sandbox-test.sh",
    "scripts/test-macos-enterprise-packaging.sh",
)

# These implementations have no valid target-runtime use. Their presence is a
# hard failure even when no current caller happens to reference them.
REMOVED_RUNTIME_PATHS = (
    "cli/defenseclaw/tui/services/gateway_events.py",
    "internal/audit/sinkconfig",
    "internal/audit/sinks",
    "internal/gateway/audit_bridge.go",
    "internal/gateway/jsonl_kill_switch.go",
    "internal/gateway/raw_telemetry.go",
    "internal/gatewaylog/writer.go",
    "internal/gatewaylog/pretty.go",
    "internal/gatewaylog/validator.go",
    "internal/scanner/gateway_writer_ctx.go",
    "internal/telemetry/global_provider.go",
    "internal/telemetry/runtime.go",
)


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    explanation: str
    allowed_prefixes: tuple[str, ...] = ()
    include_tests: bool = True
    suffixes: tuple[str, ...] = (".go", ".py")


# Exact compatibility boundaries. They may decode or reject v7 source, but may
# not construct a target runtime. Runtime callsites outside these paths fail.
LEGACY_CONFIG_BOUNDARIES = (
    "internal/config/config.go",
    "internal/config/sinks.go",
    "internal/config/yaml_v8.go",
    "cli/defenseclaw/config.py",
    # Recovery commands can classify credentials before a v7 source has been
    # upgraded; exact-v8 classification still resolves canonical destinations.
    "cli/defenseclaw/credentials.py",
    "cli/defenseclaw/migrations.py",
    "cli/defenseclaw/observability/v8_migration.py",
)

RULES = (
    Rule(
        "gateway-writer",
        re.compile(
            r"\bgatewaylog\.(?:Writer|Config|New)\b|\b(?:SetEventWriter|EventWriter|withCapturedEvents)\b",
        ),
        "pre-v8 gateway Writer ownership is forbidden",
    ),
    Rule(
        "audit-fanout",
        re.compile(
            r"\b(?:StructuredEmitter|SetStructuredEmitter|SetGatewayLogWriter|"
            r"ForwardGatewayEventToSinks|SetSinks|SwapSinks)\b|internal/audit/(?:sinks|sinkconfig)",
        ),
        "audit fanout/sink bridges are forbidden",
    ),
    Rule(
        "direct-telemetry-provider",
        re.compile(
            r"\*telemetry\.Provider\b|\btelemetry\.(?:NewProvider|SetGlobalProvider|GlobalProvider)\b",
        ),
        "only the unified runtime may own the telemetry provider",
        allowed_prefixes=("internal/observability/", "internal/telemetry/"),
        suffixes=(".go",),
    ),
    Rule(
        "legacy-go-config-use",
        re.compile(r"\.(?:OTel|AuditSinks|EmitOTel)\b|\bDEFENSECLAW_DISABLE_REDACTION\b"),
        "target Go code may not read legacy observability config",
        allowed_prefixes=LEGACY_CONFIG_BOUNDARIES,
        include_tests=False,
        suffixes=(".go",),
    ),
    Rule(
        "legacy-python-config-use",
        re.compile(
            r"\beffective_audit_sinks\s*\(|\.privacy\.disable_redaction\b|\.emit_otel\b|"
            r"\b(?:app\.)?cfg\.(?:otel|splunk)\b|"
            r"\bgetattr\(\s*(?:(?:app\.)?cfg|config)\s*,\s*[\"'](?:otel|splunk|privacy)[\"']|"
            r"\bDEFENSECLAW_DISABLE_REDACTION\b|[\"']audit_sinks[\"']",
        ),
        "target Python commands and TUI may not read or write v7 observability controls",
        allowed_prefixes=LEGACY_CONFIG_BOUNDARIES,
        include_tests=False,
        suffixes=(".py",),
    ),
    Rule(
        "legacy-config-authoring",
        re.compile(
            r"\b(?:cfg|config)\s*\[\s*[\"'](?:audit_sinks|otel|privacy)[\"']\s*\]\s*=",
        ),
        "released workflow/runtime fixtures must author canonical v8 observability destinations",
        suffixes=(".py", ".sh", ".yml", ".yaml"),
    ),
    Rule(
        "legacy-packaged-config",
        re.compile(
            r"(?m)^\s*(?:config_version:\s*[0-7]\b|audit_db:|judge_bodies_db:|disable_redaction:)"
            r"|--(?:disable-redaction|no-redact)\b|\bDEFENSECLAW_DISABLE_REDACTION\b",
        ),
        "released installers must render strict v8 observability config and profile-based redaction",
        suffixes=(".sh",),
    ),
    Rule(
        "gateway-jsonl-reader",
        re.compile(
            r"\b(?:load_gateway_events|load_gateway_egress|parse_gateway_event|"
            r"parse_gateway_log_row|tail_gateway_jsonl)\b|"
            r"(?:open|read_text|read_bytes)\([^\n]{0,160}gateway\.jsonl",
        ),
        "operator/runtime reads must use canonical v8 event history, not gateway.jsonl",
        allowed_prefixes=("cli/defenseclaw/observability/v8_migration.py",),
        include_tests=False,
        suffixes=(".py",),
    ),
    Rule(
        "ambient-python-otel",
        re.compile(
            r"from\s+opentelemetry\s+import\s+(?:trace|metrics)\b|"
            r"import\s+opentelemetry\.(?:trace|metrics)\b|"
            r"\b(?:get_meter|get_tracer|start_as_current_span)\s*\(",
        ),
        "Python producers must submit source facts to canonical v8 ingress, not own an OTel SDK provider",
        include_tests=False,
        suffixes=(".py",),
    ),
    Rule(
        "direct-alert-severity-mutation",
        re.compile(r"UPDATE\s+audit_events\s+SET\s+severity", re.IGNORECASE),
        "immutable alert severity must not be rewritten; use the protected CAS projection",
        include_tests=False,
    ),
    Rule(
        "direct-store-event-fallback",
        re.compile(r"\b(?:store|s)\.LogEvent\s*\("),
        "target runtime producers must use the canonical logger/runtime, not Store.LogEvent",
        allowed_prefixes=("internal/audit/",),
        include_tests=False,
        suffixes=(".go",),
    ),
    Rule(
        "legacy-span-processor-arm",
        re.compile(r"\bLegacy\s+sdktrace\.SpanProcessor\b|\.Legacy\.(?:OnStart|OnEnd|ForceFlush|Shutdown)\b"),
        "v8 span destinations may consume generated canonical spans only",
        include_tests=False,
        suffixes=(".go",),
    ),
)


def relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for source_root in SOURCE_ROOTS:
        directory = root / source_root
        if not directory.exists():
            continue
        files.extend(
            path
            for path in directory.rglob("*")
            if path.is_file()
            and path.suffix in SOURCE_SUFFIXES
            and "__pycache__" not in path.parts
        )
    for source in ADDITIONAL_RUNTIME_SOURCES:
        path = root / source
        if path.is_file():
            files.append(path)
    return sorted(files)


def allowed(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == prefix or path.startswith(prefix) for prefix in prefixes)


def check(root: Path) -> tuple[list[dict[str, object]], int]:
    failures: list[dict[str, object]] = []
    for removed in REMOVED_RUNTIME_PATHS:
        candidate = root / removed
        exists = candidate.is_file() or (candidate.is_dir() and any(candidate.rglob("*")))
        if exists:
            failures.append(
                {"rule": "removed-runtime-path", "path": removed, "line": 1, "text": "still exists"},
            )

    files = source_files(root)
    for path in files:
        rel = relative(path, root)
        text = path.read_text(encoding="utf-8")
        is_test = rel.endswith("_test.go") or "/tests/" in rel or rel.startswith("cli/tests/")
        for rule in RULES:
            if path.suffix not in rule.suffixes:
                continue
            if is_test and not rule.include_tests:
                continue
            if allowed(rel, rule.allowed_prefixes):
                continue
            for match in rule.pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                excerpt = text.splitlines()[line - 1].strip()
                failures.append(
                    {
                        "rule": rule.name,
                        "path": rel,
                        "line": line,
                        "text": excerpt[:240],
                        "explanation": rule.explanation,
                    },
                )
    return failures, len(files)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    failures, scanned = check(root)
    if args.json:
        print(json.dumps({"files_scanned": scanned, "failures": failures}, indent=2, sort_keys=True))
    elif failures:
        for failure in failures:
            print(
                f"{failure['path']}:{failure['line']}: {failure['rule']}: {failure['text']}",
                file=sys.stderr,
            )
        print(f"observability v8 hard cut: {len(failures)} violation(s)", file=sys.stderr)
    else:
        print(f"observability v8 hard cut: PASS ({scanned} source files scanned)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
