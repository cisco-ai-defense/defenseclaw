# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib import error, parse, request

DEFAULT_GALILEO_API_BASE = "https://api.galileo.ai"


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text or None


@dataclass(frozen=True)
class GalileoRuntimeConfig:
    """Server-side Galileo runtime config.

    The API key intentionally has no public serializer. Use ``public_status``
    for health/debug responses so the Cisco Cloud Control browser never
    receives secret values.
    """

    api_base: str = DEFAULT_GALILEO_API_BASE
    api_key: str | None = None
    project: str | None = None
    project_id: str | None = None
    log_stream: str | None = None
    log_stream_id: str | None = None

    @property
    def api_key_configured(self) -> bool:
        return bool(self.api_key)

    @property
    def project_configured(self) -> bool:
        return bool(self.project_id or self.project)

    @property
    def live_query_ready(self) -> bool:
        return self.api_key_configured and self.project_configured

    def public_status(self) -> dict[str, Any]:
        return {
            "api_base": self.api_base,
            "api_key_configured": self.api_key_configured,
            "project": self.project,
            "project_id": self.project_id,
            "log_stream": self.log_stream,
            "log_stream_id": self.log_stream_id,
            "live_query_ready": self.live_query_ready,
        }


def galileo_config_from_env(
    *,
    api_base: str | None = None,
    api_key: str | None = None,
    project: str | None = None,
    project_id: str | None = None,
    log_stream: str | None = None,
    log_stream_id: str | None = None,
) -> GalileoRuntimeConfig:
    return GalileoRuntimeConfig(
        api_base=_clean(api_base or os.environ.get("GALILEO_API_BASE")) or DEFAULT_GALILEO_API_BASE,
        api_key=_clean(api_key or os.environ.get("GALILEO_API_KEY")),
        project=_clean(project or os.environ.get("GALILEO_PROJECT")),
        project_id=_clean(project_id or os.environ.get("GALILEO_PROJECT_ID")),
        log_stream=_clean(log_stream or os.environ.get("GALILEO_LOG_STREAM")),
        log_stream_id=_clean(log_stream_id or os.environ.get("GALILEO_LOG_STREAM_ID")),
    )


def apply_galileo_runtime_config(
    galileo_payload: Mapping[str, Any],
    config: GalileoRuntimeConfig | None = None,
) -> dict[str, Any]:
    """Overlay non-secret Galileo env config onto a fixture/live payload."""
    cfg = config or galileo_config_from_env()
    payload = copy.deepcopy(dict(galileo_payload))
    original_project = payload.get("project")
    original_log_stream = payload.get("log_stream")
    project_changed = bool(cfg.project and cfg.project != original_project)
    log_stream_changed = bool(cfg.log_stream and cfg.log_stream != original_log_stream)
    if cfg.project:
        payload["project"] = cfg.project
    if cfg.project_id:
        payload["project_id"] = cfg.project_id
    elif project_changed:
        payload.pop("project_id", None)
    if cfg.log_stream:
        payload["log_stream"] = cfg.log_stream
    if cfg.log_stream_id:
        payload["log_stream_id"] = cfg.log_stream_id
    elif log_stream_changed:
        payload.pop("log_stream_id", None)

    for trace in payload.get("traces", []):
        if not isinstance(trace, dict):
            continue
        if cfg.project:
            trace["project"] = cfg.project
        if cfg.project_id:
            trace["project_id"] = cfg.project_id
        elif project_changed:
            trace.pop("project_id", None)
        if cfg.log_stream:
            trace["log_stream"] = cfg.log_stream
        if cfg.log_stream_id:
            trace["log_stream_id"] = cfg.log_stream_id
        elif log_stream_changed:
            trace.pop("log_stream_id", None)
    return payload


class GalileoAPIError(RuntimeError):
    """Raised for Galileo API failures without exposing credentials."""


def _request_json(method: str, url: str, api_key: str, body: Mapping[str, Any] | None, timeout: float) -> Any:
    data = None
    headers = {"Galileo-API-Key": api_key}
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = request.Request(url, method=method, headers=headers, data=data)
    try:
        with request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise GalileoAPIError(f"{method} {url} failed with HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise GalileoAPIError(f"{method} {url} failed: {exc.reason}") from exc


def _project_summary(project: Mapping[str, Any]) -> dict[str, Any]:
    log_streams = project.get("log_streams")
    if not isinstance(log_streams, list):
        log_streams = []
    return {
        "id": project.get("id"),
        "name": project.get("name"),
        "num_logstreams": project.get("num_logstreams"),
        "log_streams": _log_stream_summaries(log_streams),
    }


def _log_stream_summaries(log_streams: list[Any]) -> list[dict[str, Any]]:
    return [
        {"id": item.get("id"), "name": item.get("name")}
        for item in log_streams
        if isinstance(item, Mapping)
    ]


def _fetch_log_streams(base: str, project_id: str, api_key: str, timeout: float) -> list[dict[str, Any]]:
    payload = _request_json("GET", f"{base}/v2/projects/{parse.quote(project_id)}/log_streams", api_key, None, timeout)
    return _log_stream_summaries(payload if isinstance(payload, list) else [])


def _attach_log_stream_match(result: dict[str, Any], config: GalileoRuntimeConfig) -> dict[str, Any]:
    wanted_stream = config.log_stream_id or config.log_stream
    if not wanted_stream:
        return result
    project = result.get("project")
    streams = project.get("log_streams") if isinstance(project, Mapping) else []
    if not isinstance(streams, list):
        streams = []
    matched_stream = next(
        (
            item
            for item in streams
            if isinstance(item, Mapping)
            and wanted_stream in {str(item.get("id") or ""), str(item.get("name") or "")}
        ),
        None,
    )
    result["log_stream"] = matched_stream
    result["log_stream_matched"] = matched_stream is not None
    return result


def resolve_galileo_project(config: GalileoRuntimeConfig, *, timeout: float = 10.0) -> dict[str, Any]:
    """Validate Galileo API access and resolve a project name to API metadata."""
    if not config.api_key:
        raise ValueError("GALILEO_API_KEY is required for a live Galileo check.")
    base = config.api_base.rstrip("/")
    if config.project_id:
        url = f"{base}/v2/projects/{parse.quote(config.project_id)}"
        payload = _request_json("GET", url, config.api_key, None, timeout)
        project = payload if isinstance(payload, Mapping) else {}
        project_summary = _project_summary(project)
        if (config.log_stream_id or config.log_stream) and not project_summary["log_streams"]:
            project_summary["log_streams"] = _fetch_log_streams(base, config.project_id, config.api_key, timeout)
        return _attach_log_stream_match(
            {"ok": True, "matched_by": "project_id", "project": project_summary},
            config,
        )

    if not config.project:
        raise ValueError("Set GALILEO_PROJECT or GALILEO_PROJECT_ID for a live Galileo check.")

    url = f"{base}/v2/projects/paginated?include_logstreams=true&limit=25"
    body = {
        "filters": [
            {
                "operator": "eq",
                "value": config.project,
                "name": "name",
                "case_sensitive": True,
            }
        ],
        "sort": {
            "name": "created_at",
            "ascending": False,
            "sort_type": "column",
        },
    }
    payload = _request_json("POST", url, config.api_key, body, timeout)
    projects = payload.get("projects", []) if isinstance(payload, Mapping) else []
    projects = [item for item in projects if isinstance(item, Mapping)]
    exact = [item for item in projects if item.get("name") == config.project]
    if not exact:
        return {
            "ok": False,
            "matched_by": "project",
            "project": None,
            "total_count": payload.get("total_count") if isinstance(payload, Mapping) else None,
            "message": "No Galileo project matched GALILEO_PROJECT.",
        }

    project = _project_summary(exact[0])
    result: dict[str, Any] = {"ok": True, "matched_by": "project", "project": project}
    return _attach_log_stream_match(result, config)
