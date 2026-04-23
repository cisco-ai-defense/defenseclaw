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

"""Observability preset registry.

Each preset describes a first-class telemetry destination. A preset
resolves to one of two targets:

* ``otel`` — the top-level ``otel:`` block in ``config.yaml``, used by
  the gateway's unified OTel exporter (traces + metrics + logs via
  ``internal/telemetry/provider.go``).
* ``audit_sinks`` — an entry in the ``audit_sinks:`` list, used by the
  audit manager to fan out security events (see
  ``internal/audit/sinks``). Supported kinds: ``splunk_hec``,
  ``otlp_logs``, ``http_jsonl``.

All header values that reference secrets use ``${VAR}`` substitution so
the tokens themselves live in ``~/.defenseclaw/.env`` rather than
``config.yaml``. See ``internal/audit/sinks/otlp_logs.go`` and
``internal/telemetry/provider.go`` for the runtime expansion contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Target = Literal["otel", "audit_sinks"]
SinkKind = Literal["splunk_hec", "otlp_logs", "http_jsonl"]
Signal = Literal["traces", "metrics", "logs"]


@dataclass(frozen=True)
class Preset:
    """Declarative description of a telemetry destination preset.

    Fields are intentionally flat — the writer in
    ``observability.writer`` consumes this struct together with the
    user-supplied inputs to produce the YAML diff that lands in
    ``config.yaml``.
    """

    id: str
    display_name: str
    target: Target
    description: str

    # ---- otel target ----
    # Default OTLP protocol (``grpc`` or ``http``) for the gateway
    # exporter; individual signals may override at the signal level when
    # the vendor uses different URL paths per signal.
    otel_protocol: str = "http"
    # Default endpoint (hostname only, ``https://`` scheme stripped).
    # ``{placeholder}`` fields are substituted from the resolved inputs.
    endpoint_template: str = ""
    # Per-signal URL paths (HTTP protocol only). Keys are ``traces``,
    # ``metrics``, ``logs``; values are URL paths like ``/v1/traces``.
    signal_url_paths: dict[Signal, str] = field(default_factory=dict)
    # Default signal enablement when the user does not override.
    default_signals: tuple[Signal, ...] = ("traces", "metrics", "logs")
    # Header map applied to the OTel exporter. Values may contain
    # ``${ENV_NAME}`` substitutions that resolve at sink-build time.
    otel_headers: dict[str, str] = field(default_factory=dict)
    # Optional TLS mode override for the OTel exporter. ``None`` means
    # preserve the operator's existing setting. The bundled local stack
    # uses plaintext OTLP on loopback, so its preset must stamp
    # ``otel.tls.insecure=true``.
    otel_tls_insecure: bool | None = None

    # ---- audit_sinks target ----
    sink_kind: SinkKind | None = None

    # ---- secrets ----
    # Canonical env var name for this preset's primary credential. The
    # writer stamps this into the corresponding ``*_token_env`` /
    # ``*_api_key_env`` field and persists the value to
    # ``~/.defenseclaw/.env``. Empty means the preset has no secret.
    token_env: str = ""
    # Optional human-friendly description of the secret used at prompt
    # time (e.g. ``"Splunk O11y access token"``).
    token_label: str = ""

    # ---- prompts / flag surface ----
    # Ordered list of ``(flag_name, placeholder, description,
    # default_if_any)`` tuples describing the required prompts for an
    # interactive run and the ``--<flag>`` surface for non-interactive
    # runs. ``flag_name`` is the Click option long name without dashes.
    prompts: tuple[tuple[str, str, str, str], ...] = ()


# ---------------------------------------------------------------------------
# Built-in presets (small set; see docs/OBSERVABILITY.md for details)
# ---------------------------------------------------------------------------

SPLUNK_O11Y = Preset(
    id="splunk-o11y",
    display_name="Splunk Observability Cloud",
    target="otel",
    description="Traces + metrics + logs via OTLP HTTP to ingest.<realm>.observability.splunkcloud.com",
    otel_protocol="http",
    endpoint_template="ingest.{realm}.observability.splunkcloud.com",
    signal_url_paths={
        "traces": "/v2/trace/otlp",
        "metrics": "/v2/datapoint/otlp",
        "logs": "/v1/log/otlp",
    },
    default_signals=("traces", "metrics"),
    otel_headers={"X-SF-Token": "${SPLUNK_ACCESS_TOKEN}"},
    token_env="SPLUNK_ACCESS_TOKEN",
    token_label="Splunk Observability access token",
    prompts=(
        ("realm", "us1", "Splunk O11y realm (e.g. us1, us0, eu0)", "us1"),
    ),
)

SPLUNK_HEC = Preset(
    id="splunk-hec",
    display_name="Splunk HEC",
    target="audit_sinks",
    sink_kind="splunk_hec",
    description="Audit events via Splunk HTTP Event Collector",
    token_env="DEFENSECLAW_SPLUNK_HEC_TOKEN",
    token_label="Splunk HEC token",
    prompts=(
        ("host", "localhost", "Splunk host (name or IP without scheme)", "localhost"),
        ("port", "8088", "Splunk HEC port", "8088"),
        ("index", "defenseclaw", "HEC index", "defenseclaw"),
        ("source", "defenseclaw", "HEC source", "defenseclaw"),
        ("sourcetype", "_json", "HEC sourcetype", "_json"),
    ),
)

DATADOG = Preset(
    id="datadog",
    display_name="Datadog",
    target="otel",
    description="Traces + metrics + logs via OTLP HTTP to Datadog",
    otel_protocol="http",
    endpoint_template="https://otlp.{site}.datadoghq.com",
    signal_url_paths={
        "traces": "/v1/traces",
        "metrics": "/v1/metrics",
        "logs": "/v1/logs",
    },
    otel_headers={"DD-API-KEY": "${DD_API_KEY}"},
    token_env="DD_API_KEY",
    token_label="Datadog API key",
    prompts=(
        ("site", "us5", "Datadog site (us1, us3, us5, eu, ...)", "us5"),
    ),
)

HONEYCOMB = Preset(
    id="honeycomb",
    display_name="Honeycomb",
    target="otel",
    description="Traces + metrics + logs via OTLP HTTP to api.honeycomb.io",
    otel_protocol="http",
    endpoint_template="https://api.honeycomb.io",
    signal_url_paths={
        "traces": "/v1/traces",
        "metrics": "/v1/metrics",
        "logs": "/v1/logs",
    },
    otel_headers={"x-honeycomb-team": "${HONEYCOMB_API_KEY}"},
    token_env="HONEYCOMB_API_KEY",
    token_label="Honeycomb API key",
    prompts=(
        (
            "dataset",
            "defenseclaw",
            "Honeycomb dataset (applied as x-honeycomb-dataset header)",
            "defenseclaw",
        ),
    ),
)

NEWRELIC = Preset(
    id="newrelic",
    display_name="New Relic",
    target="otel",
    description="Traces + metrics + logs via OTLP HTTP to otlp.<region>.nr-data.net",
    otel_protocol="http",
    endpoint_template="https://otlp.{region}.nr-data.net",
    signal_url_paths={
        "traces": "/v1/traces",
        "metrics": "/v1/metrics",
        "logs": "/v1/logs",
    },
    otel_headers={"api-key": "${NEW_RELIC_LICENSE_KEY}"},
    token_env="NEW_RELIC_LICENSE_KEY",
    token_label="New Relic license key",
    prompts=(
        ("region", "us", "New Relic region (us or eu)", "us"),
    ),
)

GRAFANA_CLOUD = Preset(
    id="grafana-cloud",
    display_name="Grafana Cloud",
    target="otel",
    description="Traces + metrics + logs via OTLP HTTP to grafana.net OTLP gateway",
    otel_protocol="http",
    endpoint_template="https://otlp-gateway-{region}.grafana.net",
    signal_url_paths={
        "traces": "/otlp/v1/traces",
        "metrics": "/otlp/v1/metrics",
        "logs": "/otlp/v1/logs",
    },
    otel_headers={"Authorization": "Basic ${GRAFANA_OTLP_TOKEN}"},
    token_env="GRAFANA_OTLP_TOKEN",
    token_label="Grafana Cloud OTLP token (base64(instance_id:token))",
    prompts=(
        ("region", "prod-us-east-0", "Grafana Cloud region/zone", "prod-us-east-0"),
    ),
)

LOCAL_OTLP = Preset(
    id="local-otlp",
    display_name="Local Observability Stack",
    target="otel",
    description=(
        "Bundled docker-compose stack on loopback (OTel Collector + "
        "Prometheus + Loki + Tempo + Grafana). Driven by "
        "`defenseclaw setup local-observability`."
    ),
    otel_protocol="grpc",
    # ``{endpoint}`` is substituted from the sole prompt so operators
    # can re-point at a non-default host:port without editing YAML, but
    # the out-of-box path is zero-config loopback.
    endpoint_template="{endpoint}",
    # grpc has no per-signal URL paths — the single endpoint multiplexes
    # traces / metrics / logs.
    signal_url_paths={},
    default_signals=("traces", "metrics", "logs"),
    # No auth: the stack binds to 127.0.0.1 by default. If an operator
    # opens it up to the LAN they are expected to add headers manually.
    otel_headers={},
    otel_tls_insecure=True,
    token_env="",
    token_label="",
    prompts=(
        (
            "endpoint",
            "127.0.0.1:4317",
            "OTLP endpoint (host:port) for the local collector",
            "127.0.0.1:4317",
        ),
    ),
)

GENERIC_OTLP = Preset(
    id="otlp",
    display_name="Generic OTLP",
    target="otel",
    description="Generic OTLP endpoint (grpc or http); lands in otel: or audit_sinks[otlp_logs]",
    otel_protocol="grpc",
    endpoint_template="{endpoint}",
    signal_url_paths={},
    # Writer treats this as "user decides target at apply time" by
    # honouring the ``target_override`` input (``otel`` vs
    # ``audit_sinks``). Default is ``otel``; when the caller supplies
    # ``--target audit_sinks``, the writer builds an ``otlp_logs`` sink
    # instead.
    token_env="",
    token_label="",
    prompts=(
        ("endpoint", "otel.example.com:4317", "OTLP endpoint (host:port or URL)", ""),
        ("protocol", "grpc", "OTLP protocol (grpc or http)", "grpc"),
    ),
)

GENERIC_WEBHOOK = Preset(
    id="webhook",
    display_name="Generic HTTP JSONL",
    target="audit_sinks",
    sink_kind="http_jsonl",
    description="HTTP(S) webhook that receives audit events as JSON lines",
    token_env="",
    token_label="Webhook bearer token env var name",
    prompts=(
        ("url", "https://example.com/webhook", "Webhook URL (must be https)", ""),
        ("method", "POST", "HTTP method", "POST"),
    ),
)


PRESETS: dict[str, Preset] = {
    p.id: p
    for p in (
        SPLUNK_O11Y,
        SPLUNK_HEC,
        DATADOG,
        HONEYCOMB,
        NEWRELIC,
        GRAFANA_CLOUD,
        LOCAL_OTLP,
        GENERIC_OTLP,
        GENERIC_WEBHOOK,
    )
}


def resolve_preset(preset_id: str) -> Preset:
    """Return the preset for ``preset_id`` or raise ``ValueError``.

    Accepts the canonical id only; aliases are not resolved here (the
    Click command layer is responsible for mapping e.g. ``splunk-o11y``
    legacy shorthands).
    """
    if preset_id not in PRESETS:
        choices = ", ".join(sorted(PRESETS.keys()))
        raise ValueError(f"unknown preset {preset_id!r}; choose one of: {choices}")
    return PRESETS[preset_id]


def preset_choices() -> list[str]:
    """Return preset ids in menu-display order (matches the TUI picker)."""
    return [
        "splunk-o11y",
        "splunk-hec",
        "datadog",
        "honeycomb",
        "newrelic",
        "grafana-cloud",
        "local-otlp",
        "otlp",
        "webhook",
    ]
