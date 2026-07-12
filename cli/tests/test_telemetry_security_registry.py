"""Focused authored-registry contracts for current security producers."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts/generate_telemetry_registry.py"


def _compile_registry():  # type: ignore[no-untyped-def]
    name = "telemetry_security_registry_contract"
    spec = importlib.util.spec_from_file_location(name, GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module.compile_registry(ROOT)


def _index(ir):  # type: ignore[no-untyped-def]
    attributes = {attribute.id: attribute for domain in ir.domains for attribute in domain.attributes}
    groups = {group.id: group for domain in ir.domains for group in domain.groups}
    return attributes, groups


def _resolved(ir, group_id: str):  # type: ignore[no-untyped-def]
    return {use.ref: use for use in ir.resolved_group_uses[group_id]}


def test_current_security_producers_have_lossless_authored_contracts() -> None:
    ir = _compile_registry()
    attributes, groups = _index(ir)

    judge = _resolved(ir, "log.guardrail.judge.completed")
    assert groups["log.guardrail.judge.completed"].allowed_outcomes == (
        "allowed",
        "blocked",
        "failed",
    )
    assert judge["defenseclaw.judge.error_summary"].requirement_level == "recommended"
    assert judge["defenseclaw.judge.parse_error"].conditional == ("judge-output-parse-failed-v1")
    assert attributes["defenseclaw.judge.error_summary"].field_class == "error"

    scan_fields = {
        "defenseclaw.scan.scanner",
        "defenseclaw.scan.target_ref",
        "defenseclaw.scan.target_type",
        "defenseclaw.scan.duration_ms",
        "defenseclaw.scan.finding_count",
        "defenseclaw.scan.critical_count",
        "defenseclaw.scan.high_count",
        "defenseclaw.scan.medium_count",
        "defenseclaw.scan.low_count",
        "defenseclaw.scan.info_count",
        "defenseclaw.scan.severity_max",
        "defenseclaw.scan.verdict",
        "defenseclaw.scan.exit_code",
        "defenseclaw.scan.error_summary",
    }
    for group_id in (
        "security.scan",
        "body.asset.scan",
        "log.scan.completed",
        "log.scan.failed",
        "span.asset.scan",
        "span.asset.scan.phase",
    ):
        assert scan_fields <= _resolved(ir, group_id).keys()
    assert groups["body.asset.scan"].extends == ("security.scan",)
    assert "security.scan" in groups["span.asset.scan"].extends
    assert "security.scan" in groups["span.asset.scan.phase"].extends
    assert attributes["defenseclaw.scan.exit_code"].normalization.effective_constraints == {
        "min": -2147483648,
        "max": 2147483647,
    }

    finding = _resolved(ir, "log.finding.observed")
    finding_fields = {
        "defenseclaw.finding.title",
        "defenseclaw.finding.description",
        "defenseclaw.finding.location",
        "defenseclaw.finding.line_number",
        "defenseclaw.finding.tags",
        "defenseclaw.finding.data_axes",
        "defenseclaw.finding.tool_capability_class",
        "defenseclaw.finding.external_endpoint",
        "defenseclaw.finding.decision_path",
        "defenseclaw.finding.content_fingerprint",
        "defenseclaw.scan.scanner",
    }
    assert finding_fields <= finding.keys()
    assert "defenseclaw.finding.status" not in finding
    assert attributes["defenseclaw.finding.status"].stability == "deprecated"
    assert attributes["defenseclaw.finding.location"].field_class == "path"
    assert attributes["defenseclaw.finding.title"].field_class == "evidence"
    assert attributes["defenseclaw.finding.decision_path"].field_class == "evidence"
    assert attributes["defenseclaw.finding.tags"].normalization.effective_constraints["max_items"] == 64
    finding_event = _resolved(ir, "event.security.finding.observed")
    assert finding_fields <= finding_event.keys()
    assert "defenseclaw.finding.status" not in finding_event

    network_fields = {
        "defenseclaw.network.target_ref",
        "defenseclaw.network.target_path",
        "defenseclaw.network.policy_outcome",
        "defenseclaw.network.decision",
        "defenseclaw.network.decision_code",
        "defenseclaw.network.reason",
        "defenseclaw.network.branch",
        "defenseclaw.network.source",
        "defenseclaw.network.body_shape",
        "defenseclaw.network.looks_like_llm",
        "defenseclaw.network.blocked",
    }
    for group_id in (
        "security.network.egress",
        "body.network.egress",
        "log.egress.allowed",
        "log.egress.blocked",
        "span.network.request",
    ):
        assert network_fields <= _resolved(ir, group_id).keys()
    assert set(groups["body.network.egress"].extends) == {
        "correlation.interaction",
        "correlation.agent",
        "correlation.tool.identity",
        "security.network.egress",
    }
    assert "security.network.egress" in groups["span.network.request"].extends
    assert attributes["defenseclaw.network.target_path"].field_class == "path"
    assert attributes["defenseclaw.network.policy_outcome"].field_class == "reason"
    assert attributes["defenseclaw.network.blocked"].field_type == "boolean"
    assert attributes["defenseclaw.network.branch"].normalization.effective_constraints["enum"] == (
        "known",
        "shape",
        "passthrough",
        "chat",
    )
