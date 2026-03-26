#!/usr/bin/env python3

import argparse
import csv
import io
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Optional


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from product_telemetry_sender import emit_event, emit_result


INSTANCE_ID_PATH = Path("/opt/splunk/etc/apps/defenseclaw_local_mode/local/.product_telemetry_instance_id")
SPLUNK_VERSION_COMMAND = ["/opt/splunk/bin/splunk", "version"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit a bounded usage_summary product telemetry event.")
    parser.add_argument("--summary-json", default=None, help="Usage-summary event_details JSON object.")
    parser.add_argument("--summary-file", default=None, help="Optional path to a JSON or CSV summary file.")
    parser.add_argument("--output", choices=["json", "text"], default="json")
    parser.add_argument("positional_inputs", nargs="*")
    return parser.parse_args()


def parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_summary_json(raw: str) -> Dict[str, Any]:
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("usage summary JSON must decode to an object")
    return value


def parse_summary_csv(text: str) -> Dict[str, Any]:
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        return {key: value for key, value in row.items() if key}
    raise ValueError("usage summary CSV did not contain any rows")


def load_summary_file(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8").strip()
    if path.suffix.lower() == ".json":
        return parse_summary_json(text)
    return parse_summary_csv(text)


def extract_summary(args: argparse.Namespace) -> Dict[str, Any]:
    if args.summary_json:
        return parse_summary_json(args.summary_json)

    if args.summary_file:
        return load_summary_file(Path(args.summary_file))

    for value in args.positional_inputs:
        candidate = Path(value)
        if candidate.is_file():
            return load_summary_file(candidate)

    stdin_text = sys.stdin.read().strip()
    if stdin_text:
        if stdin_text.startswith("{"):
            return parse_summary_json(stdin_text)
        return parse_summary_csv(stdin_text)

    raise ValueError("no usage summary input was provided")


def normalize_summary(summary: Dict[str, Any]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}

    alerts_enabled_count = summary.get("alerts_enabled_count", 0)
    try:
        normalized["alerts_enabled_count"] = int(alerts_enabled_count)
    except (TypeError, ValueError) as exc:
        raise ValueError("alerts_enabled_count must be an integer") from exc

    if "query_interface_used_24h" in summary and summary["query_interface_used_24h"] not in ("", None):
        value = summary["query_interface_used_24h"]
        if isinstance(value, bool):
            normalized["query_interface_used_24h"] = value
        else:
            normalized["query_interface_used_24h"] = parse_bool(str(value))

    signal_families = summary.get("signal_families_seen_24h", [])
    if isinstance(signal_families, str):
        families = [item.strip() for item in signal_families.split(",") if item.strip()]
    elif isinstance(signal_families, list):
        families = [str(item).strip() for item in signal_families if str(item).strip()]
    else:
        raise ValueError("signal_families_seen_24h must be a string or list")
    normalized["signal_families_seen_24h"] = families

    return normalized


def ensure_instance_id(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            return existing

    instance_id = str(uuid.uuid4())
    path.write_text(instance_id + "\n", encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return instance_id


def read_splunk_version() -> str:
    env_value = os.environ.get("SPLUNK_VERSION", "").strip()
    if env_value:
        return env_value

    try:
        result = subprocess.run(
            SPLUNK_VERSION_COMMAND,
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception:
        return "unknown"

    match = re.search(r"^Splunk ([^ ]+)", result.stdout, flags=re.MULTILINE)
    if match is None:
        return "unknown"
    return match.group(1)


def main() -> int:
    args = parse_args()
    summary = normalize_summary(extract_summary(args))
    sender_args = argparse.Namespace(
        event_type="usage_summary",
        instance_id=ensure_instance_id(INSTANCE_ID_PATH),
        splunk_version=read_splunk_version(),
        defenseclaw_integration_enabled="true" if parse_bool(os.environ.get("DEFENSECLAW_INTEGRATION_ENABLED", "false")) else "false",
        event_details_json=summary,
        output=args.output,
        hec_url=os.environ.get("PHONE_HOME_HEC_URL", ""),
        hec_token=os.environ.get("PHONE_HOME_HEC_TOKEN", ""),
        enabled=os.environ.get("PHONE_HOME_ENABLED", "true"),
        timeout=10,
    )
    payload, result = emit_event(sender_args)
    return emit_result(payload, result, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
