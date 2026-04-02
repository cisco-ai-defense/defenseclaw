#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import configparser
import json
import os
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib import error, request


APP_ID = "defenseclaw_local_mode"
DEPLOYMENT_MODE = "defenseclaw_local_mode"
DEPLOYMENT_NAME = "defenseclaw_local_mode"
DEFAULT_SOURCE = "splunk-claw-bridge"
DEFAULT_SOURCETYPE = "defenseclaw:producttelemetry"
DEFAULT_DESTINATION_URL = "https://quickdraw.splunk.com/telemetry/destination"
ALLOWED_EVENT_TYPES = {
    "install",
    "startup",
    "shutdown",
    "health",
    "usage_summary",
    "integration_configured",
}
USAGE_SUMMARY_EVENT_DETAIL_FIELDS = {
    "query_interface_used_24h",
    "alerts_enabled_count",
    "signal_families_seen_24h",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Emit bounded DefenseClaw product telemetry to a Splunk HEC endpoint.")
    parser.add_argument("--event-type", required=True, choices=sorted(ALLOWED_EVENT_TYPES))
    parser.add_argument("--instance-id", default=None)
    parser.add_argument("--splunk-version", default=os.environ.get("SPLUNK_VERSION", "unknown"))
    parser.add_argument("--defenseclaw-integration-enabled", choices=["true", "false"], default="false")
    parser.add_argument("--event-details-json", type=parse_event_details_arg, default=None)
    parser.add_argument("--output", choices=["json", "text"], default="json")
    parser.add_argument("--hec-url", default=os.environ.get("PHONE_HOME_HEC_URL", DEFAULT_DESTINATION_URL))
    parser.add_argument("--hec-token", default=os.environ.get("PHONE_HOME_HEC_TOKEN", ""))
    parser.add_argument("--enabled", default=os.environ.get("PHONE_HOME_ENABLED", "true"))
    parser.add_argument("--timeout", type=int, default=10)
    return parser


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def parse_event_details_arg(raw: str) -> Dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"invalid --event-details-json value: {exc}") from exc
    if not isinstance(value, dict):
        raise argparse.ArgumentTypeError("--event-details-json must decode to a JSON object")
    return value


def app_root() -> Path:
    return Path(__file__).resolve().parents[1]


def read_bridge_version() -> str:
    app_conf = app_root() / "default" / "app.conf"
    if not app_conf.is_file():
        return "unknown"
    parser = configparser.ConfigParser()
    parser.read(app_conf, encoding="utf-8")
    return parser.get("launcher", "version", fallback="unknown")


def parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def normalize_arch(machine: str) -> str:
    value = machine.strip().lower()
    if value in {"x86_64", "amd64"}:
        return "amd64"
    if value in {"aarch64", "arm64"}:
        return "arm64"
    return value or "unknown"


def should_skip_delivery(enabled_raw: str, hec_url: str, hec_token: str) -> Optional[str]:
    if not parse_bool(enabled_raw):
        return "disabled"
    if not hec_url:
        return "skipped_no_destination"
    return None


def normalize_known_ref(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned or cleaned.lower() == "unknown":
        return None
    return cleaned


def normalize_usage_summary_event_details(event_details: Dict[str, Any]) -> Dict[str, Any]:
    unexpected = sorted(set(event_details) - USAGE_SUMMARY_EVENT_DETAIL_FIELDS)
    if unexpected:
        raise ValueError(f"usage_summary event_details contained unsupported keys: {', '.join(unexpected)}")

    normalized: Dict[str, Any] = {}
    if "query_interface_used_24h" in event_details:
        value = event_details["query_interface_used_24h"]
        if not isinstance(value, bool):
            raise ValueError("usage_summary query_interface_used_24h must be a boolean")
        normalized["queryInterfaceUsed24h"] = value

    if "alerts_enabled_count" in event_details:
        value = event_details["alerts_enabled_count"]
        try:
            normalized["alertsEnabledCount"] = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("usage_summary alerts_enabled_count must be an integer") from exc

    if "signal_families_seen_24h" in event_details:
        raw_families = event_details["signal_families_seen_24h"]
        if isinstance(raw_families, str):
            families = [item.strip() for item in raw_families.split(",") if item.strip()]
        elif isinstance(raw_families, list):
            families = [str(item).strip() for item in raw_families if str(item).strip()]
        else:
            raise ValueError("usage_summary signal_families_seen_24h must be a string or list")
        normalized["signalFamiliesSeen24h"] = families

    return normalized


def normalize_event_details(event_type: str, event_details: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if event_details is None:
        return None
    if event_type == "usage_summary":
        return normalize_usage_summary_event_details(event_details)
    return event_details


def build_payload(args: argparse.Namespace) -> Dict[str, Any]:
    event_details = normalize_event_details(args.event_type, args.event_details_json)
    instance_id = args.instance_id or os.environ.get("PHONE_HOME_INSTANCE_ID")
    if not instance_id:
        raise ValueError("instance_id is required for product telemetry emission")

    bridge_version = read_bridge_version()
    payload: Dict[str, Any] = {
        "deploymentID": instance_id,
        "instanceID": instance_id,
        "name": DEPLOYMENT_NAME,
        "appID": APP_ID,
        "appVersion": bridge_version,
        "bridgeVersion": bridge_version,
        "deploymentMode": DEPLOYMENT_MODE,
        "eventType": args.event_type,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "splunkVersion": args.splunk_version,
        "platformArch": f"{platform.system().lower()}/{normalize_arch(platform.machine())}",
        "splunkImage": os.environ.get("SPLUNK_IMAGE", "unknown"),
        "defenseclawIntegrationEnabled": args.defenseclaw_integration_enabled == "true",
    }

    nemoclaw_ref = normalize_known_ref(os.environ.get("NEMOCLAW_REF"))
    if nemoclaw_ref is not None:
        payload["nemoclawRef"] = nemoclaw_ref

    defenseclaw_ref = normalize_known_ref(os.environ.get("DEFENSECLAW_REF"))
    if defenseclaw_ref is not None:
        payload["defenseclawRef"] = defenseclaw_ref

    if event_details:
        payload.update(event_details)

    return payload


def post_event(hec_url: str, hec_token: str, payload: Dict[str, Any], timeout: int) -> Dict[str, Any]:
    body = json.dumps(
        {
            "source": DEFAULT_SOURCE,
            "sourcetype": DEFAULT_SOURCETYPE,
            "event": payload,
        }
    ).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if hec_token:
        headers["Authorization"] = f"Splunk {hec_token}"
    req = request.Request(hec_url, data=body, headers=headers, method="POST")
    with request.urlopen(req, timeout=timeout) as response:
        response_body = response.read().decode("utf-8")
        return {
            "status": "sent",
            "status_code": response.getcode(),
            "response_body": response_body,
        }


def emit_event(args: argparse.Namespace) -> tuple[Dict[str, Any], Dict[str, Any]]:
    payload = build_payload(args)
    skip_reason = should_skip_delivery(args.enabled, args.hec_url, args.hec_token)
    if skip_reason is not None:
        return payload, {"status": skip_reason, "hec_url": args.hec_url}

    try:
        result = post_event(args.hec_url, args.hec_token, payload, args.timeout)
        result["hec_url"] = args.hec_url
        return payload, result
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return payload, {
            "status": "http_error",
            "status_code": exc.code,
            "response_body": body,
            "hec_url": args.hec_url,
        }
    except Exception as exc:  # pragma: no cover - defensive path
        return payload, {
            "status": "send_error",
            "error": str(exc),
            "hec_url": args.hec_url,
        }


def emit_result(payload: Dict[str, Any], result: Dict[str, Any], output: str) -> int:
    full = {"payload": payload, **result}
    if output == "json":
        print(json.dumps(full, indent=2, sort_keys=True))
    else:
        print(f"status: {result['status']}")
        print(f"event_type: {payload['eventType']}")
        print(f"instance_id: {payload['instanceID']}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        payload, result = emit_event(args)
    except ValueError as exc:
        if args.output == "json":
            print(json.dumps({"status": "invalid_payload", "error": str(exc)}, indent=2, sort_keys=True))
        else:
            print(f"status: invalid_payload")
            print(f"error: {exc}")
        return 2
    return emit_result(payload, result, args.output)
