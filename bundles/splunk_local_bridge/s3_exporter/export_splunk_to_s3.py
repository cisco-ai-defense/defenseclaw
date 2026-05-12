#!/usr/bin/env python3
"""Export local DefenseClaw Splunk events to S3 as JSONL.GZ batches."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

import boto3
import requests
from requests.auth import HTTPBasicAuth


SCHEMA_VERSION = "defenseclaw.splunk_s3.raw_event.v0.1"
MANIFEST_SCHEMA_VERSION = "defenseclaw.splunk_s3.manifest.v0.1"
SOURCE_SYSTEM = "splunk_local_bridge"
DEFAULT_SPLUNK_USERNAME = "admin"
DEFAULT_SPLUNK_PASSWORD = "DefenseClawLocalMode1!"
SEARCH_FIELDS = [
    "_time",
    "_indextime",
    "index",
    "source",
    "sourcetype",
    "run_id",
    "session_id",
    "trace_id",
    "request_id",
    "agent_name",
    "agent_type",
    "tool_name",
    "destination_app",
    "action",
    "severity",
    "policy_id",
    "decision",
    "_raw",
]
SEARCH = """
search index=defenseclaw_local earliest="{earliest}" latest="{latest}"
(
  sourcetype="defenseclaw:json"
  OR sourcetype="openclaw:gateway:json"
  OR sourcetype="openclaw:diagnostics:json"
  OR sourcetype="otel:metric"
  OR sourcetype="otel:trace"
)
| spath
| table {fields}
| sort 0 _time
""".strip().format(fields=" ".join(SEARCH_FIELDS), earliest="{earliest}", latest="{latest}")


@dataclass(frozen=True)
class ExportConfig:
    enabled: bool
    once: bool
    bucket: str
    prefix: str
    aws_region: str
    endpoint_url: str | None
    sse: str | None
    splunk_base_url: str
    splunk_username: str
    splunk_password: str
    splunk_verify_tls: bool
    interval_seconds: int
    window_seconds: int
    lookback_seconds: int
    checkpoint_file: Path
    tenant_id: str
    workspace_id: str
    deployment_environment: str


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name, "").strip()
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed < 0:
        raise ValueError(f"{name} must be non-negative")
    return parsed


def load_config() -> ExportConfig:
    enabled = _truthy(os.environ.get("S3_EXPORT_ENABLED"))
    config = ExportConfig(
        enabled=enabled,
        once=_truthy(os.environ.get("S3_EXPORT_ONCE")),
        bucket=os.environ.get("S3_BUCKET", "").strip(),
        prefix=os.environ.get("S3_PREFIX", "agentwatch/defenseclaw").strip().strip("/"),
        aws_region=os.environ.get("AWS_REGION", "us-west-2").strip(),
        endpoint_url=os.environ.get("S3_ENDPOINT_URL", "").strip() or None,
        sse=os.environ.get("S3_SSE", "AES256").strip() or None,
        splunk_base_url=os.environ.get("SPLUNK_BASE_URL", "https://splunk:8089").strip().rstrip("/"),
        splunk_username=os.environ.get("SPLUNK_USERNAME", DEFAULT_SPLUNK_USERNAME).strip(),
        splunk_password=os.environ.get("SPLUNK_PASSWORD", DEFAULT_SPLUNK_PASSWORD),
        splunk_verify_tls=_truthy(os.environ.get("SPLUNK_VERIFY_TLS", "true")),
        interval_seconds=_env_int("S3_EXPORT_INTERVAL_SECONDS", 60),
        window_seconds=_env_int("S3_EXPORT_WINDOW_SECONDS", 300),
        lookback_seconds=_env_int("S3_EXPORT_LOOKBACK_SECONDS", 30),
        checkpoint_file=Path(os.environ.get("S3_EXPORT_CHECKPOINT_FILE", "/state/checkpoint.json")),
        tenant_id=os.environ.get("TENANT_ID", "c3-demo-tenant").strip(),
        workspace_id=os.environ.get("WORKSPACE_ID", "workspace-demo").strip(),
        deployment_environment=os.environ.get("DEPLOYMENT_ENVIRONMENT", "local").strip(),
    )
    if enabled:
        missing = []
        if not config.bucket:
            missing.append("S3_BUCKET")
        if missing:
            raise ValueError(f"missing required env var(s): {', '.join(missing)}")
    return config


def parse_iso(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def to_iso(dt: datetime) -> str:
    return dt.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def to_splunk_time(value: str) -> str:
    return str(int(parse_iso(value).timestamp()))


def load_checkpoint(path: Path) -> str | None:
    try:
        payload = json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("latest"), str):
        return payload["latest"]
    return None


def save_checkpoint(path: Path, latest_iso: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps({"latest": latest_iso}, sort_keys=True) + "\n")
    tmp.replace(path)


def splunk_export(
    base_url: str,
    username: str,
    password: str,
    verify_tls: bool,
    earliest: str,
    latest: str,
) -> Iterable[dict[str, Any]]:
    response = requests.post(
        f"{base_url.rstrip('/')}/services/search/jobs/export",
        auth=HTTPBasicAuth(username, password),
        data={
            "search": SEARCH.format(
                earliest=to_splunk_time(earliest),
                latest=to_splunk_time(latest),
            ),
            "output_mode": "json",
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        stream=True,
        timeout=(10, 120),
        verify=verify_tls,
    )
    response.raise_for_status()
    for line in response.iter_lines(decode_unicode=True):
        if not line:
            continue
        payload = json.loads(line)
        if isinstance(payload, dict) and isinstance(payload.get("result"), dict):
            yield payload["result"]


def parse_raw(raw: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def event_id(row: dict[str, Any]) -> str:
    values = [
        row_value(row, "_time"),
        row_value(row, "_indextime"),
        row_value(row, "index"),
        row_value(row, "source"),
        row_value(row, "sourcetype"),
        row_value(row, "_raw"),
    ]
    material = "\x1f".join("" if value is None else str(value) for value in values)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def normalize_value(value: Any) -> Any:
    if not isinstance(value, list):
        return value
    if not value:
        return None
    first = value[0]
    if all(item == first for item in value):
        return first
    return value


def row_value(row: dict[str, Any], field: str) -> Any:
    return normalize_value(row.get(field))


def normalize_row(row: dict[str, Any], exported_at: str) -> dict[str, Any]:
    raw = row_value(row, "_raw")
    raw_text = "" if raw is None else str(raw)
    return {
        "schema_version": SCHEMA_VERSION,
        "exported_at": exported_at,
        "tenant_id": os.environ.get("TENANT_ID", "c3-demo-tenant"),
        "workspace_id": os.environ.get("WORKSPACE_ID", "workspace-demo"),
        "deployment_environment": os.environ.get("DEPLOYMENT_ENVIRONMENT", "local"),
        "source_system": SOURCE_SYSTEM,
        "splunk": {
            "_time": row_value(row, "_time"),
            "_indextime": row_value(row, "_indextime"),
            "index": row_value(row, "index"),
            "source": row_value(row, "source"),
            "sourcetype": row_value(row, "sourcetype"),
        },
        "correlation": {
            "run_id": row_value(row, "run_id"),
            "session_id": row_value(row, "session_id"),
            "trace_id": row_value(row, "trace_id"),
            "request_id": row_value(row, "request_id"),
            "agent_name": row_value(row, "agent_name"),
            "agent_type": row_value(row, "agent_type"),
            "tool_name": row_value(row, "tool_name"),
            "destination_app": row_value(row, "destination_app"),
            "action": row_value(row, "action"),
            "policy_id": row_value(row, "policy_id"),
            "decision": row_value(row, "decision"),
            "severity": row_value(row, "severity"),
        },
        "event": parse_raw(raw_text),
        "raw": raw_text,
        "export_event_id": event_id(row),
    }


def _s3_client(config: ExportConfig):
    kwargs: dict[str, Any] = {"region_name": config.aws_region}
    if config.endpoint_url:
        kwargs["endpoint_url"] = config.endpoint_url
    return boto3.client("s3", **kwargs)


def _safe_partition(value: str) -> str:
    return value.replace("/", "_").replace(" ", "_")


def s3_data_key(config: ExportConfig, earliest: str, latest: str) -> str:
    start = parse_iso(earliest)
    end = parse_iso(latest)
    filename = (
        "defenseclaw-splunk-local-"
        f"{start.strftime('%Y%m%dT%H%M%SZ')}-{end.strftime('%Y%m%dT%H%M%SZ')}.jsonl.gz"
    )
    parts = [
        config.prefix,
        f"tenant_id={_safe_partition(config.tenant_id)}",
        f"workspace_id={_safe_partition(config.workspace_id)}",
        f"dt={start.strftime('%Y-%m-%d')}",
        f"hour={start.strftime('%H')}",
        filename,
    ]
    return "/".join(part.strip("/") for part in parts if part)


def manifest_key(config: ExportConfig, latest: str) -> str:
    end = parse_iso(latest)
    return "/".join(
        part.strip("/")
        for part in [
            config.prefix,
            "_manifests",
            f"manifest-{end.strftime('%Y%m%dT%H%M%SZ')}.json",
        ]
        if part
    )


def write_batch(rows: Iterable[dict[str, Any]], earliest: str, latest: str) -> dict[str, Any] | None:
    config = load_config()
    materialized = list(rows)
    if not materialized:
        return None

    jsonl = "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in materialized)
    sha256 = hashlib.sha256(jsonl.encode("utf-8")).hexdigest()
    body = io.BytesIO()
    with gzip.GzipFile(fileobj=body, mode="wb", mtime=0) as gz:
        gz.write(jsonl.encode("utf-8"))

    object_key = s3_data_key(config, earliest, latest)
    exported_at = to_iso(datetime.now(UTC))
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "bucket": config.bucket,
        "object_key": object_key,
        "record_count": len(materialized),
        "earliest": earliest,
        "latest": latest,
        "sha256": sha256,
        "tenant_id": config.tenant_id,
        "workspace_id": config.workspace_id,
        "exported_at": exported_at,
    }

    put_kwargs: dict[str, Any] = {}
    if config.sse:
        put_kwargs["ServerSideEncryption"] = config.sse
    client = _s3_client(config)
    client.put_object(
        Bucket=config.bucket,
        Key=object_key,
        Body=body.getvalue(),
        ContentType="application/jsonl",
        ContentEncoding="gzip",
        **put_kwargs,
    )
    client.put_object(
        Bucket=config.bucket,
        Key=manifest_key(config, latest),
        Body=json.dumps(manifest, sort_keys=True).encode("utf-8"),
        ContentType="application/json",
        **put_kwargs,
    )
    return manifest


def _window_from_checkpoint(config: ExportConfig, now: datetime) -> tuple[str, str]:
    checkpoint = load_checkpoint(config.checkpoint_file)
    if checkpoint:
        earliest_dt = parse_iso(checkpoint) - timedelta(seconds=config.lookback_seconds)
    else:
        earliest_dt = now - timedelta(seconds=config.window_seconds)
    return to_iso(earliest_dt), to_iso(now)


def run_once() -> dict[str, Any]:
    config = load_config()
    now = datetime.now(UTC)
    earliest, latest = _window_from_checkpoint(config, now)
    exported_at = to_iso(now)
    rows = [
        normalize_row(row, exported_at)
        for row in splunk_export(
            config.splunk_base_url,
            config.splunk_username,
            config.splunk_password,
            config.splunk_verify_tls,
            earliest,
            latest,
        )
    ]
    manifest = write_batch(rows, earliest, latest)
    save_checkpoint(config.checkpoint_file, latest)
    status = {
        "status": "ok",
        "earliest": earliest,
        "latest": latest,
        "record_count": len(rows),
        "checkpoint": str(config.checkpoint_file),
    }
    if manifest:
        status.update(
            {
                "bucket": manifest["bucket"],
                "object_key": manifest["object_key"],
                "manifest_key": manifest_key(config, latest),
            }
        )
    return status


def main() -> int:
    try:
        config = load_config()
    except ValueError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stderr)
        return 2

    if not config.enabled:
        print(json.dumps({"status": "disabled", "message": "S3 export disabled"}))
        return 0

    while True:
        try:
            print(json.dumps(run_once(), sort_keys=True), flush=True)
        except Exception as exc:  # noqa: BLE001 - sidecar should log and retry
            print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stderr, flush=True)
            if config.once:
                return 1
        if config.once:
            return 0
        time.sleep(config.interval_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
