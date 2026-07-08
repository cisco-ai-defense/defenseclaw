"""Strict extraction and normalization of DefenseClaw distribution controls."""

from __future__ import annotations

import copy
import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any

import yaml

OPA_EVALUATOR = "defenseclaw.opa_policy"
RULE_PACK_EVALUATOR = "defenseclaw.rule_pack"
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
TRUST_LEVELS = {"full", "advisory", "none"}
MAX_CONTROLS = 1000
MAX_OPA_CONFIG_BYTES = 64 * 1024
MAX_RULE_PACK_BYTES = 1024 * 1024
MAX_RULES = 1000
MAX_PATTERN_CHARS = 2048
MAX_TAGS = 32
MAX_TAG_CHARS = 128
MAX_RULE_ID_CHARS = 128
MAX_RULE_TITLE_CHARS = 256


class ControlValidationError(ValueError):
    """A matching DefenseClaw control violates the closed v1 contract."""


@dataclass(frozen=True)
class CandidateSet:
    opa_config: dict[str, Any] | None
    rules: tuple[dict[str, Any], ...]
    opa_source_digest: str
    rule_pack_source_digest: str
    matching_controls: int
    ignored_controls: int

    def opa_artifact(self, precedence: str) -> bytes:
        if self.opa_config is None:
            payload: dict[str, Any] = {
                "agent_control": {
                    "schema_version": 1,
                    "enabled": False,
                    "precedence": precedence,
                }
            }
        else:
            policy = self.opa_config["policy"]
            payload = {
                "agent_control": {
                    "schema_version": 1,
                    "enabled": True,
                    "precedence": precedence,
                    "source_digest": self.opa_source_digest,
                    "guardrail": {
                        "block_threshold": SEVERITY_RANK[policy["block_at"]],
                        "alert_threshold": SEVERITY_RANK[policy["alert_at"]],
                        "cisco_trust_level": policy["cisco_trust_level"],
                    },
                }
            }
        return canonical_json(payload)

    def rule_pack_artifact(self) -> bytes | None:
        if not self.rules:
            return None
        payload = {
            "version": 1,
            "category": "agent-control",
            "rules": list(self.rules),
        }
        rendered = yaml.safe_dump(
            payload,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
            width=4096,
        )
        return rendered.encode("utf-8")


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def extract_candidates(controls: list[dict[str, Any]]) -> CandidateSet:
    return _extract_candidates(controls, {OPA_EVALUATOR, RULE_PACK_EVALUATOR})


def extract_lane_candidates(controls: list[dict[str, Any]], evaluator_name: str) -> CandidateSet:
    if evaluator_name not in {OPA_EVALUATOR, RULE_PACK_EVALUATOR}:
        raise ValueError(f"unsupported DefenseClaw evaluator lane: {evaluator_name}")
    return _extract_candidates(controls, {evaluator_name})


def snapshot_counts(controls: list[dict[str, Any]]) -> tuple[int, int]:
    _validate_snapshot_shape(controls)
    matching = sum(
        1
        for borrowed in controls
        if isinstance(borrowed, dict)
        and _contains_evaluator(borrowed.get("control"), {OPA_EVALUATOR, RULE_PACK_EVALUATOR})
    )
    return matching, len(controls) - matching


def _extract_candidates(controls: list[dict[str, Any]], evaluator_names: set[str]) -> CandidateSet:
    _validate_snapshot_shape(controls)

    opa_configs: list[dict[str, Any]] = []
    rules_by_id: dict[str, dict[str, Any]] = {}
    matching = 0
    ignored = 0

    for index, borrowed in enumerate(controls):
        if not isinstance(borrowed, dict):
            ignored += 1
            continue
        control = borrowed.get("control")
        evaluator_name = _evaluator_name(control)
        if evaluator_name not in evaluator_names:
            embedded = sorted(name for name in evaluator_names if _contains_evaluator(control, {name}))
            if not embedded:
                ignored += 1
                continue
            evaluator_name = embedded[0]
        matching += 1
        item = copy.deepcopy(borrowed)
        validated_control = _validate_envelope(item, index, evaluator_name)
        config = validated_control["condition"]["evaluator"]["config"]
        if evaluator_name == OPA_EVALUATOR:
            opa_configs.append(_validate_opa_config(config, index))
        else:
            for rule in _validate_rule_pack_config(config, index):
                existing = rules_by_id.get(rule["id"])
                if existing is not None and existing != rule:
                    raise ControlValidationError(f"control[{index}]: conflicting duplicate rule id {rule['id']!r}")
                rules_by_id[rule["id"]] = rule

    normalized_opa: dict[str, Any] | None = None
    if opa_configs:
        normalized_opa = opa_configs[0]
        if any(candidate != normalized_opa for candidate in opa_configs[1:]):
            raise ControlValidationError("effective snapshot contains conflicting DefenseClaw OPA policies")

    rules = tuple(rules_by_id[key] for key in sorted(rules_by_id))
    if len(rules) > MAX_RULES:
        raise ControlValidationError(f"effective rule-pack exceeds {MAX_RULES} rules")
    normalized_rule_source = {
        "schema_version": 1,
        "rule_pack": {"version": 1, "category": "agent-control", "rules": list(rules)},
    }
    if len(canonical_json(normalized_rule_source)) > MAX_RULE_PACK_BYTES:
        raise ControlValidationError(f"effective rule-pack exceeds {MAX_RULE_PACK_BYTES} bytes")

    return CandidateSet(
        opa_config=normalized_opa,
        rules=rules,
        opa_source_digest=digest_bytes(canonical_json(normalized_opa if normalized_opa is not None else [])),
        rule_pack_source_digest=digest_bytes(canonical_json(normalized_rule_source)),
        matching_controls=matching,
        ignored_controls=ignored,
    )


def _validate_snapshot_shape(controls: list[dict[str, Any]]) -> None:
    if not isinstance(controls, list):
        raise ControlValidationError("Agent Control snapshot must be a list")
    if len(controls) > MAX_CONTROLS:
        raise ControlValidationError(f"Agent Control snapshot exceeds {MAX_CONTROLS} controls")


def _evaluator_name(control: Any) -> str:
    if not isinstance(control, dict):
        return ""
    condition = control.get("condition")
    if not isinstance(condition, dict):
        return ""
    evaluator = condition.get("evaluator")
    if not isinstance(evaluator, dict):
        return ""
    value = evaluator.get("name")
    return value if isinstance(value, str) else ""


def _contains_evaluator(value: Any, evaluator_names: set[str]) -> bool:
    if isinstance(value, dict):
        evaluator = value.get("evaluator")
        if isinstance(evaluator, dict) and evaluator.get("name") in evaluator_names:
            return True
        return any(_contains_evaluator(child, evaluator_names) for child in value.values())
    if isinstance(value, list):
        return any(_contains_evaluator(child, evaluator_names) for child in value)
    return False


def _validate_envelope(item: dict[str, Any], index: int, evaluator_name: str) -> dict[str, Any]:
    control = item.get("control")
    if not isinstance(control, dict):
        raise ControlValidationError(f"control[{index}].control must be an object")
    if control.get("enabled") is not True:
        raise ControlValidationError(f"control[{index}] must be enabled")
    if control.get("execution") != "sdk":
        raise ControlValidationError(f"control[{index}].execution must be 'sdk'")
    if control.get("scope") != {}:
        raise ControlValidationError(f"control[{index}].scope must be an empty object")
    if control.get("action") != {"decision": "observe"}:
        raise ControlValidationError(f"control[{index}].action must be observe")
    condition = control.get("condition")
    if not isinstance(condition, dict) or set(condition) != {"selector", "evaluator"}:
        raise ControlValidationError(f"control[{index}].condition must be one selector/evaluator leaf")
    if condition.get("selector") != {"path": "*"}:
        raise ControlValidationError(f"control[{index}].selector path must be '*'")
    evaluator = condition.get("evaluator")
    if not isinstance(evaluator, dict) or set(evaluator) != {"name", "config"}:
        raise ControlValidationError(f"control[{index}].evaluator must contain only name and config")
    if evaluator.get("name") != evaluator_name or not isinstance(evaluator.get("config"), dict):
        raise ControlValidationError(f"control[{index}].evaluator is invalid")
    return control


def _validate_opa_config(config: Any, index: int) -> dict[str, Any]:
    path = f"control[{index}].config"
    _require_exact_keys(config, {"schema_version", "policy"}, path)
    if not _is_int(config["schema_version"]) or config["schema_version"] != 1:
        raise ControlValidationError(f"{path}.schema_version must be 1")
    policy = config["policy"]
    _require_exact_keys(policy, {"domain", "block_at", "alert_at", "cisco_trust_level"}, f"{path}.policy")
    if policy["domain"] != "guardrail":
        raise ControlValidationError(f"{path}.policy.domain must be 'guardrail'")
    for field in ("block_at", "alert_at"):
        if policy[field] not in SEVERITY_RANK:
            raise ControlValidationError(f"{path}.policy.{field} has unsupported severity")
    if SEVERITY_RANK[policy["alert_at"]] > SEVERITY_RANK[policy["block_at"]]:
        raise ControlValidationError(f"{path}.policy.alert_at cannot exceed block_at")
    if policy["cisco_trust_level"] not in TRUST_LEVELS:
        raise ControlValidationError(f"{path}.policy.cisco_trust_level is unsupported")
    normalized = {"schema_version": 1, "policy": dict(policy)}
    if len(canonical_json(normalized)) > MAX_OPA_CONFIG_BYTES:
        raise ControlValidationError(f"{path} exceeds {MAX_OPA_CONFIG_BYTES} bytes")
    return normalized


def _validate_rule_pack_config(config: Any, index: int) -> list[dict[str, Any]]:
    path = f"control[{index}].config"
    _require_exact_keys(config, {"schema_version", "rule_pack"}, path)
    if not _is_int(config["schema_version"]) or config["schema_version"] != 1:
        raise ControlValidationError(f"{path}.schema_version must be 1")
    pack = config["rule_pack"]
    _require_exact_keys(pack, {"version", "category", "rules"}, f"{path}.rule_pack")
    if not _is_int(pack["version"]) or pack["version"] != 1:
        raise ControlValidationError(f"{path}.rule_pack.version must be 1")
    if pack["category"] != "agent-control":
        raise ControlValidationError(f"{path}.rule_pack.category must be 'agent-control'")
    raw_rules = pack["rules"]
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ControlValidationError(f"{path}.rule_pack.rules must contain at least one rule")
    if len(raw_rules) > MAX_RULES:
        raise ControlValidationError(f"{path}.rule_pack.rules exceeds {MAX_RULES} rules")
    return [_validate_rule(rule, f"{path}.rule_pack.rules[{rule_index}]") for rule_index, rule in enumerate(raw_rules)]


def _validate_rule(rule: Any, path: str) -> dict[str, Any]:
    fields = {"id", "pattern", "title", "severity", "confidence", "tags"}
    _require_exact_keys(rule, fields, path)
    rule_id = _bounded_string(rule["id"], 1, MAX_RULE_ID_CHARS, f"{path}.id").strip()
    if not rule_id:
        raise ControlValidationError(f"{path}.id cannot be whitespace")
    pattern = _bounded_string(rule["pattern"], 1, MAX_PATTERN_CHARS, f"{path}.pattern")
    title = _bounded_string(rule["title"], 1, MAX_RULE_TITLE_CHARS, f"{path}.title")
    if not title.strip():
        raise ControlValidationError(f"{path}.title cannot be whitespace")
    severity = rule["severity"]
    if severity not in SEVERITY_RANK:
        raise ControlValidationError(f"{path}.severity is unsupported")
    confidence = rule["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise ControlValidationError(f"{path}.confidence must be numeric")
    confidence = float(confidence)
    if not math.isfinite(confidence) or confidence < 0 or confidence > 1:
        raise ControlValidationError(f"{path}.confidence must be finite and between 0 and 1")
    raw_tags = rule["tags"]
    if not isinstance(raw_tags, list) or len(raw_tags) > MAX_TAGS:
        raise ControlValidationError(f"{path}.tags must contain at most {MAX_TAGS} entries")
    tags: list[str] = []
    for tag_index, raw_tag in enumerate(raw_tags):
        tag = _bounded_string(raw_tag, 1, MAX_TAG_CHARS, f"{path}.tags[{tag_index}]").strip()
        if not tag:
            raise ControlValidationError(f"{path}.tags[{tag_index}] cannot be whitespace")
        tags.append(tag)
    return {
        "id": rule_id,
        "pattern": pattern,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "tags": tags,
    }


def _require_exact_keys(value: Any, keys: set[str], path: str) -> None:
    if not isinstance(value, dict):
        raise ControlValidationError(f"{path} must be an object")
    actual = set(value)
    if actual != keys:
        missing = sorted(keys - actual)
        unknown = sorted(actual - keys)
        raise ControlValidationError(f"{path} has missing={missing} unknown={unknown}")


def _bounded_string(value: Any, minimum: int, maximum: int, path: str) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise ControlValidationError(f"{path} must contain {minimum}-{maximum} characters")
    return value


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
