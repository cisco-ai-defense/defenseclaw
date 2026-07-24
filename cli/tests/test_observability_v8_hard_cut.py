import importlib.util
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts/check_observability_v8_hard_cut.py"
_E2E_CLI = _SCRIPT.with_name("test-e2e-cli.py")
_SPEC = importlib.util.spec_from_file_location("observability_v8_hard_cut", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)
check = _MODULE.check


def _write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_hard_cut_checker_is_semantic_and_allows_only_migration_boundary(tmp_path: Path) -> None:
    _write(tmp_path, "internal/gateway/runtime.go", "package gateway\n")
    _write(
        tmp_path,
        "cli/defenseclaw/observability/v8_migration.py",
        'legacy = source.get("audit_sinks")\n',
    )
    failures, scanned = check(tmp_path)
    assert scanned == 2
    assert failures == []

    _write(
        tmp_path,
        "cli/defenseclaw/commands/live.py",
        'legacy = source.get("audit_sinks")\n',
    )
    failures, _ = check(tmp_path)
    assert [(item["rule"], item["path"]) for item in failures] == [
        ("legacy-python-config-use", "cli/defenseclaw/commands/live.py"),
    ]


def test_hard_cut_checker_rejects_removed_writer_even_in_tests(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "internal/gateway/runtime_test.go",
        "package gateway\nfunc test() { _, _ = gatewaylog.New(gatewaylog.Config{}) }\n",
    )
    failures, _ = check(tmp_path)
    assert any(item["rule"] == "gateway-writer" for item in failures)


def test_hard_cut_checker_rejects_target_command_reads_of_legacy_status_dtos(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "cli/defenseclaw/commands/status.py",
        "enabled = app.cfg.otel.enabled or app.cfg.splunk.enabled\n",
    )
    failures, scanned = check(tmp_path)
    assert scanned == 1
    assert [(item["rule"], item["path"]) for item in failures] == [
        ("legacy-python-config-use", "cli/defenseclaw/commands/status.py"),
        ("legacy-python-config-use", "cli/defenseclaw/commands/status.py"),
    ]


def test_hard_cut_checker_rejects_indirect_legacy_status_dto_reads(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "cli/defenseclaw/commands/dashboards.py",
        'otel = getattr(app.cfg, "otel", None)\n',
    )
    failures, scanned = check(tmp_path)
    assert scanned == 1
    assert [(item["rule"], item["path"]) for item in failures] == [
        ("legacy-python-config-use", "cli/defenseclaw/commands/dashboards.py"),
    ]


def test_hard_cut_checker_ignores_empty_deleted_directory_but_not_source(tmp_path: Path) -> None:
    removed = tmp_path / "internal/audit/sinks"
    removed.mkdir(parents=True)
    failures, _ = check(tmp_path)
    assert failures == []

    _write(tmp_path, "internal/audit/sinks/http.go", "package sinks\n")
    failures, _ = check(tmp_path)
    assert any(item["rule"] == "removed-runtime-path" for item in failures)


def test_hard_cut_checker_rejects_ambient_otel_direct_alert_sql_and_legacy_span_arm(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "cli/defenseclaw/llm.py",
        "from opentelemetry import trace\ntrace.get_tracer('raw')\n",
    )
    _write(
        tmp_path,
        "cli/defenseclaw/db.py",
        'db.execute("UPDATE audit_events SET severity = \'ACK\'")\n',
    )
    _write(
        tmp_path,
        "internal/telemetry/provider.go",
        "package telemetry\ntype pipeline struct { Legacy sdktrace.SpanProcessor }\n",
    )
    failures, _ = check(tmp_path)
    assert {item["rule"] for item in failures} == {
        "ambient-python-otel",
        "direct-alert-severity-mutation",
        "legacy-span-processor-arm",
    }


def test_hard_cut_checker_rejects_legacy_packaged_config(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "packaging/macos/lib/installer_lib.sh",
        """#!/usr/bin/env bash
config_version: 6
audit_db: /var/lib/defenseclaw/audit.db
privacy:
  disable_redaction: true
""",
    )
    _write(
        tmp_path,
        "packaging/macos/install.sh",
        """#!/usr/bin/env bash
case "$1" in --disable-redaction) ;; esac
""",
    )
    failures, scanned = check(tmp_path)
    assert scanned == 2
    assert [(item["rule"], item["path"]) for item in failures] == [
        ("legacy-packaged-config", "packaging/macos/install.sh"),
        ("legacy-packaged-config", "packaging/macos/lib/installer_lib.sh"),
        ("legacy-packaged-config", "packaging/macos/lib/installer_lib.sh"),
        ("legacy-packaged-config", "packaging/macos/lib/installer_lib.sh"),
    ]


def test_hard_cut_checker_rejects_legacy_observability_authored_by_release_workflow(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        ".github/workflows/e2e.yml",
        "cfg['audit_sinks'] = []\n",
    )
    failures, scanned = check(tmp_path)
    assert scanned == 1
    assert [(item["rule"], item["path"]) for item in failures] == [
        ("legacy-config-authoring", ".github/workflows/e2e.yml"),
    ]


def test_hard_cut_checker_rejects_retired_gateway_jsonl_row_parser(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "cli/defenseclaw/tui/services/history.py",
        "def parse_gateway_log_row(line: str):\n    return line\n",
    )
    failures, scanned = check(tmp_path)
    assert scanned == 1
    assert [(item["rule"], item["path"]) for item in failures] == [
        ("gateway-jsonl-reader", "cli/defenseclaw/tui/services/history.py"),
    ]


def test_release_e2e_uses_canonical_destination_setup_and_probe() -> None:
    source = _E2E_CLI.read_text(encoding="utf-8")
    assert "test_splunk_otel_signals" not in source
    assert "otel: provider initialized" not in source
    assert "setup observability add splunk-hec" in source
    assert "defenseclaw config validate" in source
    assert "observability destination test e2e-splunk --write-probe" in source
