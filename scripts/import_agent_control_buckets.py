#!/usr/bin/env python3
"""Import DefenseClaw's bundled regexes into Agent Control as toggleable buckets.

The importer is intentionally REST-only so it can seed either a self-hosted Agent
Control server or the Cisco-hosted enterprise service without sharing runtime state
with the DefenseClaw synchronizer.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

DEFAULT_AGENT_NAME = "defenseclaw-policy-sync"
DEFAULT_TARGET_TYPE = "defenseclaw.installation"
DEFAULT_TARGET_ID = "defenseclaw-local-e2e"
DEFAULT_DISABLED_BUCKET = "local-prompt-injection"
_REGEX_META = re.compile(r"([\\.^$|?*+()\[\]{}])")


@dataclass(frozen=True)
class Bucket:
    """One Agent Control control containing a related set of DefenseClaw rules."""

    name: str
    rules: list[dict[str, Any]]


def _literal_pattern(value: str) -> str:
    """Return a Go/RE2-compatible case-insensitive literal regex."""
    return "(?i)" + _REGEX_META.sub(r"\\\1", value)


def _rule(
    *,
    rule_id: str,
    pattern: str,
    title: str,
    severity: str,
    confidence: float,
    bucket: str,
) -> dict[str, Any]:
    return {
        "id": rule_id,
        "pattern": pattern,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "tags": ["defenseclaw", f"bucket:{bucket}"],
    }


def load_buckets(rules_dir: Path) -> list[Bucket]:
    """Load canonical rule files and local-pattern families from ``rules_dir``."""
    if not rules_dir.is_dir():
        raise ValueError(f"rules directory does not exist: {rules_dir}")

    buckets: list[Bucket] = []
    for path in sorted(rules_dir.glob("*.yaml")):
        if path.name == "local-patterns.yaml":
            continue
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: expected a YAML object")
        source_rules = raw.get("rules")
        if not isinstance(source_rules, list) or not source_rules:
            raise ValueError(f"{path}: expected a non-empty rules list")
        rules: list[dict[str, Any]] = []
        for item in source_rules:
            if not isinstance(item, dict):
                raise ValueError(f"{path}: each rule must be an object")
            if item.get("enabled", True) is False:
                continue
            required = ("id", "pattern", "title", "severity", "confidence", "tags")
            missing = [key for key in required if key not in item]
            if missing:
                identity = item.get("id", "<unknown>")
                raise ValueError(f"{path}: rule {identity!r} missing fields: {', '.join(missing)}")
            rules.append({key: item[key] for key in required})
        buckets.append(Bucket(name=path.stem, rules=rules))

    local_path = rules_dir / "local-patterns.yaml"
    if not local_path.is_file():
        raise ValueError(f"required local pattern file does not exist: {local_path}")
    local = yaml.safe_load(local_path.read_text(encoding="utf-8"))
    if not isinstance(local, dict):
        raise ValueError(f"{local_path}: expected a YAML object")

    local_specs = (
        (
            "local-prompt-injection",
            (("injection", False), ("injection_regexes", True)),
            "LOCAL-INJECTION",
            "Prompt injection",
            # Prompt-surface HIGH verdicts are deliberately demoted to alerts
            # by DefenseClaw's chat UX contract. A managed bucket intended to
            # demonstrate hard enforcement therefore uses CRITICAL severity.
            "CRITICAL",
            0.95,
        ),
        (
            "local-data-privacy",
            (("pii_requests", False), ("pii_data_regexes", True)),
            "LOCAL-PRIVACY",
            "Sensitive data",
            "HIGH",
            0.90,
        ),
        (
            "local-secrets",
            (("secrets", False),),
            "LOCAL-SECRET",
            "Secret material",
            "CRITICAL",
            0.95,
        ),
        (
            "local-data-exfiltration",
            (("exfiltration", False),),
            "LOCAL-EXFIL",
            "Data exfiltration",
            "HIGH",
            0.90,
        ),
    )
    for bucket_name, fields, id_prefix, title_prefix, severity, confidence in local_specs:
        rules = []
        position = 0
        for field, is_regex in fields:
            values = local.get(field, [])
            if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
                raise ValueError(f"{local_path}: {field} must be a list of strings")
            for value in values:
                position += 1
                rules.append(
                    _rule(
                        rule_id=f"{id_prefix}-{position:03d}",
                        pattern=f"(?i){value}" if is_regex else _literal_pattern(value),
                        title=f"{title_prefix} pattern {position}",
                        severity=severity,
                        confidence=confidence,
                        bucket=bucket_name,
                    )
                )
        buckets.append(Bucket(name=bucket_name, rules=rules))

    rule_ids = [rule["id"] for bucket in buckets for rule in bucket.rules]
    if len(rule_ids) != len(set(rule_ids)):
        raise ValueError("DefenseClaw source contains duplicate rule IDs across buckets")
    return buckets


def rule_pack_control(bucket: Bucket, *, enabled: bool) -> dict[str, Any]:
    """Build the Agent Control wire representation for a rule bucket."""
    return {
        "description": f"DefenseClaw regex bucket: {bucket.name}",
        "enabled": enabled,
        "execution": "sdk",
        "scope": {},
        "condition": {
            "selector": {"path": "*"},
            "evaluator": {
                "name": "defenseclaw.rule_pack",
                "config": {
                    "schema_version": 1,
                    "rule_pack": {
                        "version": 1,
                        "category": "agent-control",
                        "rules": bucket.rules,
                    },
                },
            },
        },
        "action": {"decision": "observe"},
        "tags": ["defenseclaw", "regex-bucket", bucket.name],
    }


def opa_policy_control() -> dict[str, Any]:
    """Build the companion Agent Control OPA threshold control."""
    return {
        "description": "DefenseClaw managed guardrail thresholds",
        "enabled": True,
        "execution": "sdk",
        "scope": {},
        "condition": {
            "selector": {"path": "*"},
            "evaluator": {
                "name": "defenseclaw.opa_policy",
                "config": {
                    "schema_version": 1,
                    "policy": {
                        "domain": "guardrail",
                        "block_at": "HIGH",
                        "alert_at": "MEDIUM",
                        "cisco_trust_level": "full",
                    },
                },
            },
        },
        "action": {"decision": "observe"},
        "tags": ["defenseclaw", "opa-policy"],
    }


class AgentControlAPI:
    """Small JSON client for the Agent Control authoring endpoints."""

    def __init__(self, base_url: str, api_key: str | None, api_key_header: str) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Agent Control server URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Agent Control server URL cannot contain credentials, a query, or a fragment")
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("non-loopback Agent Control servers must use HTTPS")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.api_key_header = api_key_header
        self._opener = urllib.request.build_opener(_NoRedirectHandler())

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers[self.api_key_header] = self.api_key
        request = urllib.request.Request(f"{self.base_url}{path}", data=body, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Agent Control {method} {path} failed: {exc.code} {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"Agent Control {method} {path} transport failed ({type(exc).__name__})") from exc

    def find_control(self, name: str) -> int | None:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        while True:
            params: dict[str, str | int] = {"name": name, "limit": 100}
            if cursor is not None:
                params["cursor"] = cursor
            response = self.request("GET", f"/api/v1/controls?{urllib.parse.urlencode(params)}")
            for control in response.get("controls", []):
                if control.get("name") == name:
                    return int(control["id"])
            pagination = response.get("pagination", {})
            next_cursor = pagination.get("next_cursor")
            if not pagination.get("has_more"):
                return None
            if next_cursor is None or str(next_cursor) in seen_cursors:
                raise RuntimeError("Agent Control returned invalid control-list pagination")
            cursor = str(next_cursor)
            seen_cursors.add(cursor)

    def upsert_control(self, name: str, data: dict[str, Any]) -> int:
        control_id = self.find_control(name)
        if control_id is None:
            response = self.request("PUT", "/api/v1/controls", {"name": name, "data": data})
            control_id = int(response["control_id"])
        else:
            self.request("PUT", f"/api/v1/controls/{control_id}/data", {"data": data})
            self.request("PATCH", f"/api/v1/controls/{control_id}", {"enabled": data["enabled"]})
        return control_id

    def bind(self, control_id: int, *, target_type: str, target_id: str) -> None:
        self.request(
            "PUT",
            "/api/v1/control-bindings/by-key",
            {
                "target_type": target_type,
                "target_id": target_id,
                "control_id": control_id,
                "enabled": True,
            },
        )

    def attach_agent(self, control_id: int, agent_name: str) -> None:
        """Attach a control directly so the current Agent Control UI can edit it."""
        quoted_name = urllib.parse.quote(agent_name, safe="")
        self.request("POST", f"/api/v1/agents/{quoted_name}/controls/{control_id}")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Keep API credentials on the configured origin by rejecting redirects."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-url", default="http://127.0.0.1:8000")
    parser.add_argument("--api-key")
    parser.add_argument("--api-key-header", default="X-API-Key")
    parser.add_argument("--target-type", default=DEFAULT_TARGET_TYPE)
    parser.add_argument("--target-id", default=DEFAULT_TARGET_ID)
    parser.add_argument(
        "--attach-agent",
        default=None,
        metavar="AGENT_NAME",
        help=(
            "Also attach each control directly to an existing agent so it is visible in "
            "Agent Control UIs that do not yet render target bindings (local demos only)"
        ),
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "policies/guardrail/default/rules",
    )
    parser.add_argument(
        "--disable-bucket",
        action="append",
        default=[],
        help=f"Bucket slug to import disabled (demo: {DEFAULT_DISABLED_BUCKET})",
    )
    parser.add_argument("--prefix", default="defenseclaw")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    buckets = load_buckets(args.rules_dir)
    known = {bucket.name for bucket in buckets}
    disabled = set(args.disable_bucket)
    unknown = disabled - known
    if unknown:
        raise ValueError(f"unknown bucket(s): {', '.join(sorted(unknown))}")

    controls = [
        (f"{args.prefix}-{bucket.name}", rule_pack_control(bucket, enabled=bucket.name not in disabled))
        for bucket in buckets
    ]
    controls.append((f"{args.prefix}-opa-policy", opa_policy_control()))
    if args.dry_run:
        json.dump(dict(controls), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    api = AgentControlAPI(args.server_url, args.api_key, args.api_key_header)
    for name, control in controls:
        control_id = api.upsert_control(name, control)
        api.bind(control_id, target_type=args.target_type, target_id=args.target_id)
        if args.attach_agent:
            api.attach_agent(control_id, args.attach_agent)
        state = "enabled" if control["enabled"] else "disabled"
        rule_count = len(control["condition"]["evaluator"]["config"].get("rule_pack", {}).get("rules", []))
        print(f"{name}: id={control_id} {state} rules={rule_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
