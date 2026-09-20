# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Isolated, secret-safe observability destination connectivity probes.

This module deliberately consumes only the canonical Go effective plan.  It
does not recompile source configuration and it never enters the ordinary
collection/router/export pipeline.  Network and compliance dependencies are
explicit so the command cannot silently fall back to legacy SQLite logging.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import queue
import re
import socket
import ssl
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol
from urllib.parse import urlsplit

from defenseclaw.credentials import resolve as resolve_credential
from defenseclaw.gateway import resolve_gateway_binary
from defenseclaw.observability.v8_presets import DESTINATION_NAME_RE

_REMOTE_KINDS: Final = frozenset({"http_jsonl", "splunk_hec", "otlp"})
_WRITE_KINDS: Final = frozenset({"http_jsonl", "splunk_hec"})
_LOCAL_OR_PULL_KINDS: Final = frozenset({"sqlite", "jsonl", "console", "prometheus"})
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,255}$")
_PROBE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$")
_MAX_RESPONSE_BODY: Final = 4096
_PROBE_MARKER_HEADER: Final = "X-DefenseClaw-Probe"
_PROBE_ID_HEADER: Final = "X-DefenseClaw-Probe-ID"
_LOCAL_COMPLIANCE_TIMEOUT_SECONDS: Final = 10
_FORBIDDEN_HEADERS: Final = frozenset(
    {
        "host",
        "content-length",
        "content-type",
        "connection",
        "proxy-authorization",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
        "trailer",
        "te",
    }
)
_FAILURE_CLASSES: Final = frozenset(
    {
        "audit_unavailable",
        "authentication_failed",
        "connection_failed",
        "credential_unavailable",
        "dns_failed",
        "internal_failure",
        "invalid_destination",
        "not_found",
        "protocol_failed",
        "remote_rejected",
        "timeout",
        "tls_failed",
        "unsafe_endpoint",
        "unsupported",
    }
)

_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_METADATA = tuple(
    ipaddress.ip_network(value)
    for value in (
        "169.254.169.254/32",
        "169.254.170.0/24",
        "100.100.100.200/32",
        "168.63.129.16/32",
        "fd00:ec2::254/128",
        "fe80::a9fe:a9fe/128",
    )
)
_RESERVED = tuple(
    ipaddress.ip_network(value)
    for value in (
        "0.0.0.0/8",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4",
        "::/96",
        "64:ff9b::/96",
        "100::/64",
        "64:ff9b:1::/48",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "5f00::/16",
    )
)
_METADATA_HOSTS: Final = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "metadata.azure.internal",
        "instance-data.ec2.internal",
        "task-metadata-endpoint",
    }
)


class DestinationTestError(RuntimeError):
    """A bounded, display-safe destination-test failure."""

    def __init__(self, failure_class: str, message: str) -> None:
        if failure_class not in _FAILURE_CLASSES:
            failure_class = "internal_failure"
            message = "the destination test failed safely"
        super().__init__(message)
        self.failure_class = failure_class
        self.message = message


@dataclass(frozen=True)
class ComplianceActivity:
    """Content-free local-only audit input for one probe transition."""

    phase: str
    destination: str
    probe_id: str
    mode: str
    result: str
    failure_class: str | None


class LocalComplianceRecorder(Protocol):
    """Gateway-owned seam; implementations must persist locally only."""

    def record(self, activity: ComplianceActivity) -> None:
        """Persist one attempt/outcome without ordinary routing or fan-out."""


class GatewayLocalComplianceRecorder:
    """Persist content-free activity through the gateway-owned local-only path.

    The installed Go helper resolves the gateway bearer without returning it to
    Python, then calls the authenticated loopback endpoint. Activity JSON is
    supplied on stdin so no probe metadata or credential enters process argv.
    """

    def __init__(self, *, config_path: str, data_dir: str) -> None:
        self._config_path = config_path
        self._data_dir = data_dir

    def record(self, activity: ComplianceActivity) -> None:
        binary = resolve_gateway_binary()
        if not binary:
            raise _audit_unavailable()
        payload: dict[str, str] = {
            "phase": activity.phase,
            "destination": activity.destination,
            "probe_id": activity.probe_id,
            "mode": activity.mode,
            "result": activity.result,
        }
        if activity.failure_class is not None:
            payload["failure_class"] = activity.failure_class
        argv = [
            binary,
            "observability-v8",
            "record-destination-test-activity",
            "--config",
            self._config_path,
            "--data-dir",
            self._data_dir,
        ]
        try:
            completed = subprocess.run(
                argv,
                input=json.dumps(payload, separators=(",", ":")),
                capture_output=True,
                text=True,
                timeout=_LOCAL_COMPLIANCE_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise _audit_unavailable() from exc
        if completed.returncode != 0:
            raise _audit_unavailable()
        try:
            response = json.loads(completed.stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise _audit_unavailable() from exc
        if response != {"recorded": True}:
            raise _audit_unavailable()


def _audit_unavailable() -> DestinationTestError:
    return DestinationTestError(
        "audit_unavailable",
        "the gateway local-only destination-test compliance recorder is unavailable; "
        "ensure the v8 gateway is running and retry",
    )


def canonical_local_compliance_recorder(*, config_path: str, data_dir: str) -> LocalComplianceRecorder:
    """Return the canonical helper-backed, local-only compliance recorder."""

    return GatewayLocalComplianceRecorder(config_path=config_path, data_dir=data_dir)


@dataclass(frozen=True)
class DestinationTestResult:
    destination: str
    kind: str
    mode: str
    probe_id: str
    endpoint_count: int
    protocol: str
    authentication_verified: bool
    compliance_recorded: bool


@dataclass(frozen=True)
class _NetworkSafety:
    allow_private_networks: bool = False
    allow_cgnat: bool = False


@dataclass(frozen=True)
class _TLSSettings:
    insecure: bool = False
    insecure_skip_verify: bool = False
    ca_cert: str = ""


@dataclass(frozen=True)
class _Target:
    scheme: str
    host: str
    port: int
    request_target: str
    protocol: str
    safety: _NetworkSafety
    tls: _TLSSettings


@dataclass(frozen=True)
class _Destination:
    name: str
    kind: str
    protocol: str
    targets: tuple[_Target, ...]
    method: str
    headers: Mapping[str, str]
    token: str
    index: str


Resolver = Callable[[str, int, float], Sequence[str]]
Dialer = Callable[[str, int, float], socket.socket]


class ProbeTransport(Protocol):
    def handshake(self, target: _Target, *, timeout: float) -> None:
        """Perform one non-mutating application/transport handshake."""

    def write_probe(
        self,
        destination: _Destination,
        *,
        probe_id: str,
        timeout: float,
    ) -> None:
        """Write exactly one marked, content-free synthetic probe."""


class SocketProbeTransport:
    """No-proxy, redirect-free transport with dial-time address pinning."""

    def __init__(self, *, resolver: Resolver | None = None, dialer: Dialer | None = None) -> None:
        self._resolver = resolver or _system_resolver
        self._dialer = dialer or _system_dialer

    def handshake(self, target: _Target, *, timeout: float) -> None:
        if target.protocol == "grpc" and target.scheme != "https":
            raise DestinationTestError(
                "unsupported",
                "a non-mutating plaintext gRPC protocol handshake requires the gateway runtime adapter",
            )
        sock = self._open_resolved_socket(target, timeout)
        if target.protocol == "grpc":
            try:
                negotiated = getattr(sock, "selected_alpn_protocol", lambda: None)()
                if negotiated != "h2":
                    raise DestinationTestError("protocol_failed", "the destination did not negotiate HTTP/2")
            finally:
                sock.close()
            return
        try:
            _request_over_socket(
                sock,
                target,
                method="OPTIONS",
                body=b"",
                headers={"Content-Length": "0", "Connection": "close"},
                inspect_hec=False,
            )
        finally:
            sock.close()

    def write_probe(
        self,
        destination: _Destination,
        *,
        probe_id: str,
        timeout: float,
    ) -> None:
        if destination.kind not in _WRITE_KINDS or len(destination.targets) != 1:
            raise DestinationTestError(
                "unsupported",
                "this destination has no provably isolated synthetic write-probe adapter",
            )
        target = destination.targets[0]
        if destination.kind == "splunk_hec":
            payload = {
                "event": {
                    "defenseclaw_destination_test": True,
                    "probe_id": probe_id,
                },
                "source": "defenseclaw-destination-test",
                "sourcetype": "defenseclaw:destination_test",
            }
            if destination.index:
                payload["index"] = destination.index
            body = json.dumps(
                payload,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            headers = {
                "Authorization": f"Splunk {destination.token}",
                "Content-Type": "application/json",
            }
            method = "POST"
        else:
            body = (
                json.dumps(
                    {
                        "defenseclaw_destination_test": True,
                        "probe_id": probe_id,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
            headers = dict(destination.headers)
            headers["Content-Type"] = "application/x-ndjson"
            method = destination.method
        _drop_case_insensitive(headers, _PROBE_MARKER_HEADER)
        _drop_case_insensitive(headers, _PROBE_ID_HEADER)
        headers[_PROBE_MARKER_HEADER] = "destination-test"
        headers[_PROBE_ID_HEADER] = probe_id
        headers["Content-Length"] = str(len(body))
        headers["Connection"] = "close"

        sock = self._open_resolved_socket(target, timeout)
        try:
            _request_over_socket(
                sock,
                target,
                method=method,
                body=body,
                headers=headers,
                inspect_hec=destination.kind == "splunk_hec",
            )
        finally:
            sock.close()

    def _open_socket(self, target: _Target, address: str, timeout: float) -> socket.socket:
        try:
            sock = self._dialer(address, target.port, timeout)
        except TimeoutError as exc:
            raise DestinationTestError("timeout", "the destination connection timed out") from exc
        except OSError as exc:
            raise DestinationTestError("connection_failed", "the destination connection failed") from exc
        if target.scheme != "https":
            return sock
        try:
            context = _tls_context(target)
            wrapped = context.wrap_socket(sock, server_hostname=target.host)
        except (OSError, ssl.SSLError) as exc:
            sock.close()
            raise DestinationTestError("tls_failed", "the destination TLS handshake failed") from exc
        return wrapped

    def _open_resolved_socket(self, target: _Target, timeout: float) -> socket.socket:
        deadline = time.monotonic() + timeout
        addresses = _resolve_allowed_addresses(
            target,
            self._resolver,
            _remaining_timeout(deadline),
        )
        last_error: DestinationTestError | None = None
        for address in addresses:
            try:
                return self._open_socket(target, address, _remaining_timeout(deadline))
            except DestinationTestError as exc:
                if exc.failure_class not in {"connection_failed", "timeout", "tls_failed"}:
                    raise
                last_error = exc
        _remaining_timeout(deadline)
        if last_error is not None:
            raise last_error
        raise DestinationTestError("connection_failed", "the destination connection failed")


def run_destination_test(
    effective: Mapping[str, object],
    *,
    name: str,
    data_dir: str,
    timeout: float,
    write_probe: bool,
    compliance: LocalComplianceRecorder,
    transport: ProbeTransport | None = None,
    credential_resolver: Callable[[str, str], str] | None = None,
    probe_id_factory: Callable[[], str] | None = None,
) -> DestinationTestResult:
    """Test one named destination without invoking collection or routing."""

    if not DESTINATION_NAME_RE.fullmatch(name):
        raise DestinationTestError("invalid_destination", "destination name is not a stable identifier")
    if timeout < 0.1 or timeout > 60:
        raise DestinationTestError("invalid_destination", "timeout must be from 0.1 through 60 seconds")
    probe_id = (probe_id_factory or (lambda: str(uuid.uuid4())))()
    if not _PROBE_ID.fullmatch(probe_id):
        raise DestinationTestError("internal_failure", "probe ID generation failed")
    mode = "write_probe" if write_probe else "handshake"
    compliance.record(
        ComplianceActivity(
            phase="attempt",
            destination=name,
            probe_id=probe_id,
            mode=mode,
            result="attempted",
            failure_class=None,
        )
    )

    try:
        source = _find_destination(effective, name)
        destination = _compile_destination(
            source,
            data_dir=data_dir,
            credential_resolver=credential_resolver or _resolve_secret,
        )
        if write_probe and destination.kind not in _WRITE_KINDS:
            if destination.kind == "otlp":
                message = (
                    "OTLP writes would create ordinary logs, traces, or metrics; "
                    "an isolated runtime-adapter probe is required"
                )
            else:
                message = "this local or pull destination has no isolated write-probe semantics"
            raise DestinationTestError("unsupported", message)
        active_transport = transport or SocketProbeTransport()
        if write_probe:
            active_transport.write_probe(destination, probe_id=probe_id, timeout=timeout)
        else:
            for target in destination.targets:
                active_transport.handshake(target, timeout=timeout)
    except DestinationTestError as exc:
        _record_outcome(compliance, name, probe_id, mode, "failed", exc.failure_class)
        raise
    except Exception as exc:
        failure = DestinationTestError("internal_failure", "the destination test failed safely")
        _record_outcome(compliance, name, probe_id, mode, "failed", failure.failure_class)
        raise failure from exc

    _record_outcome(compliance, name, probe_id, mode, "succeeded", None)
    return DestinationTestResult(
        destination=name,
        kind=destination.kind,
        mode=mode,
        probe_id=probe_id,
        endpoint_count=len(destination.targets),
        protocol=destination.protocol,
        authentication_verified=write_probe and _destination_has_credentials(destination),
        compliance_recorded=True,
    )


def _record_outcome(
    compliance: LocalComplianceRecorder,
    destination: str,
    probe_id: str,
    mode: str,
    result: str,
    failure_class: str | None,
) -> None:
    compliance.record(
        ComplianceActivity(
            phase="outcome",
            destination=destination,
            probe_id=probe_id,
            mode=mode,
            result=result,
            failure_class=failure_class,
        )
    )


def _find_destination(effective: Mapping[str, object], name: str) -> Mapping[str, object]:
    destinations = effective.get("destinations")
    if not isinstance(destinations, list):
        raise DestinationTestError("invalid_destination", "the effective plan omitted destinations")
    matches = [item for item in destinations if isinstance(item, dict) and item.get("name") == name]
    if not matches:
        raise DestinationTestError("not_found", "the named destination does not exist")
    if len(matches) != 1:
        raise DestinationTestError("invalid_destination", "the effective plan contains duplicate destinations")
    return matches[0]


def _compile_destination(
    source: Mapping[str, object],
    *,
    data_dir: str,
    credential_resolver: Callable[[str, str], str],
) -> _Destination:
    name = _required_string(source, "name")
    kind = _required_string(source, "kind")
    if kind in _LOCAL_OR_PULL_KINDS:
        raise DestinationTestError(
            "unsupported",
            "local storage, console, file, and pull-listener destinations cannot be safely connectivity-tested",
        )
    if kind not in _REMOTE_KINDS:
        raise DestinationTestError("unsupported", "the destination kind has no supported test semantics")
    transport = source.get("transport")
    if not isinstance(transport, dict):
        raise DestinationTestError("invalid_destination", "the effective destination omitted its transport")
    protocol = str(transport.get("protocol") or ("http" if kind != "otlp" else ""))
    if kind == "otlp" and protocol not in {"grpc", "grpc/protobuf", "http", "http/protobuf"}:
        raise DestinationTestError("invalid_destination", "the effective destination has an invalid protocol")
    normalized_protocol = "grpc" if protocol.startswith("grpc") else "http"
    tls = _tls_settings(transport.get("tls"))
    if kind != "otlp" and tls.insecure:
        raise DestinationTestError("invalid_destination", "tls.insecure is valid only for OTLP")
    if kind == "otlp" and tls.insecure_skip_verify:
        raise DestinationTestError("invalid_destination", "OTLP does not support insecure_skip_verify")
    if tls.insecure and tls.ca_cert:
        raise DestinationTestError("invalid_destination", "plaintext OTLP cannot configure a CA certificate")
    safety = _network_safety(transport.get("network_safety"))
    headers = _resolved_headers(transport.get("headers"), data_dir, credential_resolver)
    token = ""
    token_env = str(transport.get("token_env") or "")
    bearer_env = str(transport.get("bearer_env") or "")
    if token_env:
        token = _required_token(token_env, data_dir, credential_resolver)
    if bearer_env:
        bearer = _required_token(bearer_env, data_dir, credential_resolver)
        if any(key.lower() == "authorization" for key in headers):
            raise DestinationTestError(
                "invalid_destination",
                "bearer_env and an Authorization header cannot both be configured",
            )
        headers = dict(headers)
        headers["Authorization"] = f"Bearer {bearer}"

    endpoints: list[_Target] = []
    if kind == "otlp":
        selected = source.get("selected_signals")
        if not isinstance(selected, list) or not selected:
            raise DestinationTestError("invalid_destination", "the OTLP destination selects no signals")
        overrides = transport.get("signal_overrides")
        override_map = overrides if isinstance(overrides, dict) else {}
        for signal in selected:
            if signal not in {"logs", "traces", "metrics"}:
                raise DestinationTestError("invalid_destination", "the OTLP destination selects an invalid signal")
            override = override_map.get(signal)
            override_map_value = override if isinstance(override, dict) else {}
            endpoint = str(override_map_value.get("endpoint") or transport.get("endpoint") or "")
            path = str(override_map_value.get("path") or "")
            if not path and normalized_protocol == "http":
                try:
                    endpoint_path = urlsplit(endpoint).path
                except ValueError:
                    endpoint_path = ""
                if endpoint_path in {"", "/"}:
                    path = f"/v1/{signal}"
            endpoints.append(
                _parse_target(
                    endpoint,
                    normalized_protocol,
                    path,
                    safety,
                    tls,
                    require_tls_mode_match=True,
                )
            )
    else:
        endpoint = str(transport.get("endpoint") or "")
        endpoints.append(_parse_target(endpoint, "http", "", safety, tls))
    targets = tuple(dict.fromkeys(endpoints))
    method = str(transport.get("method") or "POST").upper()
    if kind == "http_jsonl" and method not in {"POST", "PUT", "PATCH"}:
        raise DestinationTestError("invalid_destination", "the HTTP JSONL method is invalid")
    return _Destination(
        name=name,
        kind=kind,
        protocol=protocol or "http",
        targets=targets,
        method=method,
        headers=headers,
        token=token,
        index=str(transport.get("index") or ""),
    )


def _parse_target(
    endpoint: str,
    protocol: str,
    override_path: str,
    safety: _NetworkSafety,
    tls: _TLSSettings,
    *,
    require_tls_mode_match: bool = False,
) -> _Target:
    value = endpoint.strip()
    if not value or len(value) > 2048 or any(character in value for character in "\x00\r\n\t "):
        raise DestinationTestError("invalid_destination", "the destination endpoint is invalid")
    if "://" not in value:
        if protocol != "grpc":
            raise DestinationTestError("invalid_destination", "an HTTP endpoint must include its scheme")
        value = ("http://" if tls.insecure else "https://") + value
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise DestinationTestError("invalid_destination", "the destination endpoint is invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "%" in parsed.hostname
    ):
        raise DestinationTestError("invalid_destination", "the destination endpoint is invalid")
    if require_tls_mode_match and (parsed.fragment or parsed.query):
        raise DestinationTestError("invalid_destination", "an OTLP endpoint cannot contain query or fragment data")
    if protocol == "grpc" and (parsed.fragment or parsed.query):
        raise DestinationTestError("invalid_destination", "the gRPC endpoint cannot contain query or fragment data")
    if require_tls_mode_match and tls.insecure != (parsed.scheme == "http"):
        raise DestinationTestError("invalid_destination", "OTLP TLS mode and endpoint scheme disagree")
    if not require_tls_mode_match and parsed.scheme == "http" and (tls.ca_cert or tls.insecure_skip_verify):
        raise DestinationTestError("invalid_destination", "plaintext HTTP cannot configure TLS options")
    if protocol == "grpc" and parsed.path not in {"", "/"}:
        raise DestinationTestError("invalid_destination", "the gRPC endpoint cannot contain a path")
    if override_path and (
        len(override_path) > 2048
        or not override_path.startswith("/")
        or any(character in override_path for character in "\x00\r\n\t #?")
    ):
        raise DestinationTestError("invalid_destination", "the OTLP signal path is invalid")
    request_target = override_path or parsed.path or "/"
    if parsed.query:
        request_target += "?" + parsed.query
    host = parsed.hostname.rstrip(".").lower()
    if not host:
        raise DestinationTestError("invalid_destination", "the destination endpoint is invalid")
    return _Target(
        scheme=parsed.scheme,
        host=host,
        port=port or (443 if parsed.scheme == "https" else 80),
        request_target=request_target,
        protocol=protocol,
        safety=safety,
        tls=tls,
    )


def _resolved_headers(
    value: object,
    data_dir: str,
    credential_resolver: Callable[[str, str], str],
) -> Mapping[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise DestinationTestError("invalid_destination", "destination headers are invalid")
    result: dict[str, str] = {}
    canonical: set[str] = set()
    for raw_name, raw_value in value.items():
        if (
            not isinstance(raw_name, str)
            or not _HEADER_NAME.fullmatch(raw_name)
            or raw_name.lower() in _FORBIDDEN_HEADERS
        ):
            raise DestinationTestError("invalid_destination", "a destination header name is invalid")
        lowered = raw_name.lower()
        if lowered in canonical:
            raise DestinationTestError("invalid_destination", "destination headers contain a duplicate name")
        canonical.add(lowered)
        if isinstance(raw_value, str):
            resolved = raw_value
            secret_value = False
        elif isinstance(raw_value, dict) and set(raw_value) == {"env"} and isinstance(raw_value.get("env"), str):
            resolved = _required_secret(raw_value["env"], data_dir, credential_resolver)
            secret_value = True
        else:
            raise DestinationTestError("invalid_destination", "a destination header value is invalid")
        if len(resolved) > 16_384 or any(character in resolved for character in "\x00\r\n\x7f"):
            raise DestinationTestError("invalid_destination", "a destination header value is invalid")
        if secret_value and not resolved.strip():
            raise DestinationTestError("credential_unavailable", "a destination header secret is unavailable")
        result[raw_name] = resolved
    return result


def _required_secret(
    reference: str,
    data_dir: str,
    credential_resolver: Callable[[str, str], str],
) -> str:
    if not _ENV_NAME.fullmatch(reference):
        raise DestinationTestError("invalid_destination", "a destination secret reference is invalid")
    try:
        value = credential_resolver(reference, data_dir)
    except Exception as exc:
        raise DestinationTestError("credential_unavailable", "a destination credential is unavailable") from exc
    if not value or not value.strip() or "\r" in value or "\n" in value:
        raise DestinationTestError("credential_unavailable", "a destination credential is unavailable")
    return value


def _required_token(
    reference: str,
    data_dir: str,
    credential_resolver: Callable[[str, str], str],
) -> str:
    value = _required_secret(reference, data_dir, credential_resolver)
    if len(value) > 64 * 1024 or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        raise DestinationTestError("credential_unavailable", "a destination credential is unavailable")
    return value


def _resolve_secret(reference: str, data_dir: str) -> str:
    return resolve_credential(reference, data_dir).value


def _tls_settings(value: object) -> _TLSSettings:
    if value is None:
        source: Mapping[str, object] = {}
    elif isinstance(value, dict):
        source = value
    else:
        raise DestinationTestError("invalid_destination", "destination TLS settings are invalid")
    return _TLSSettings(
        insecure=bool(source.get("insecure", False)),
        insecure_skip_verify=bool(source.get("insecure_skip_verify", False)),
        ca_cert=str(source.get("ca_cert") or ""),
    )


def _network_safety(value: object) -> _NetworkSafety:
    if value is None:
        source: Mapping[str, object] = {}
    elif isinstance(value, dict):
        source = value
    else:
        raise DestinationTestError("invalid_destination", "destination network safety is invalid")
    return _NetworkSafety(
        allow_private_networks=bool(source.get("allow_private_networks", False)),
        allow_cgnat=bool(source.get("allow_cgnat", False)),
    )


def _required_string(source: Mapping[str, object], key: str) -> str:
    value = source.get(key)
    if not isinstance(value, str) or not value:
        raise DestinationTestError("invalid_destination", f"the effective destination omitted {key}")
    return value


def _system_resolver(host: str, port: int, timeout: float) -> Sequence[str]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        result: queue.Queue[Sequence[tuple] | Exception] = queue.Queue(maxsize=1)

        def lookup() -> None:
            try:
                result.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM), block=False)
            except Exception as exc:  # daemon boundary converts resolver failures below
                result.put(exc, block=False)

        threading.Thread(target=lookup, name="defenseclaw-destination-dns", daemon=True).start()
        try:
            resolved = result.get(timeout=timeout)
        except queue.Empty as exc:
            raise DestinationTestError("timeout", "the destination DNS resolution timed out") from exc
        if isinstance(resolved, Exception):
            raise DestinationTestError("dns_failed", "the destination hostname could not be resolved") from resolved
        answers = resolved
        return tuple(dict.fromkeys(str(answer[4][0]) for answer in answers))
    return (str(literal),)


def _system_dialer(address: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((address, port), timeout=timeout)


def _resolve_allowed_addresses(target: _Target, resolver: Resolver, timeout: float) -> tuple[str, ...]:
    if target.host in _METADATA_HOSTS:
        raise DestinationTestError("unsafe_endpoint", "the destination resolves to a prohibited address")
    try:
        answers = resolver(target.host, target.port, timeout)
    except DestinationTestError:
        raise
    except Exception as exc:
        raise DestinationTestError("dns_failed", "the destination hostname could not be resolved") from exc
    if not answers:
        raise DestinationTestError("dns_failed", "the destination hostname could not be resolved")
    allowed: list[str] = []
    for raw in answers:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise DestinationTestError("dns_failed", "the destination hostname returned an invalid address") from exc
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if not _address_allowed(address, target.safety):
            raise DestinationTestError("unsafe_endpoint", "the destination resolves to a prohibited address")
        allowed.append(str(address))
    return tuple(dict.fromkeys(allowed))


def _remaining_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DestinationTestError("timeout", "the destination connection timed out")
    return remaining


def _address_allowed(address: ipaddress.IPv4Address | ipaddress.IPv6Address, safety: _NetworkSafety) -> bool:
    if any(address in network for network in _METADATA):
        return False
    if address.is_unspecified or address.is_link_local or address.is_multicast:
        return False
    # Documentation, benchmark, transition, and other reserved ranges remain
    # blocked even when the reviewed private-network opt-in is enabled.
    if any(address in network for network in _RESERVED):
        return False
    if address.version == 4 and address in _CGNAT:
        return safety.allow_cgnat
    if address.is_loopback or address.is_private:
        return safety.allow_private_networks
    return True


def _tls_context(target: _Target) -> ssl.SSLContext:
    try:
        context = ssl.create_default_context(cafile=target.tls.ca_cert or None)
    except (OSError, ssl.SSLError) as exc:
        raise DestinationTestError("tls_failed", "the destination CA configuration could not be loaded") from exc
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if target.tls.insecure_skip_verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if target.protocol == "grpc":
        context.set_alpn_protocols(["h2"])
    return context


def _request_over_socket(
    sock: socket.socket,
    target: _Target,
    *,
    method: str,
    body: bytes,
    headers: Mapping[str, str],
    inspect_hec: bool,
) -> None:
    connection = http.client.HTTPConnection(target.host, target.port, timeout=sock.gettimeout())
    connection.sock = sock
    try:
        connection.request(method, target.request_target, body=body, headers=dict(headers))
        response = connection.getresponse()
        status = response.status
        if 300 <= status < 400:
            raise DestinationTestError("unsafe_endpoint", "the destination attempted a redirect")
        if method != "OPTIONS" and status in {401, 403}:
            raise DestinationTestError("authentication_failed", "the destination rejected authentication")
        if inspect_hec:
            if not 200 <= status < 300:
                raise DestinationTestError("remote_rejected", "the destination rejected the synthetic probe")
            encoded = response.read(_MAX_RESPONSE_BODY + 1)
            if len(encoded) > _MAX_RESPONSE_BODY:
                raise DestinationTestError("remote_rejected", "the destination returned an invalid acknowledgement")
            try:
                acknowledgement = json.loads(encoded)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise DestinationTestError(
                    "remote_rejected", "the destination returned an invalid acknowledgement"
                ) from exc
            if not isinstance(acknowledgement, dict) or acknowledgement.get("code") != 0:
                raise DestinationTestError("remote_rejected", "the destination rejected the synthetic probe")
        elif method != "OPTIONS" and not 200 <= status < 300:
            raise DestinationTestError("remote_rejected", "the destination rejected the synthetic probe")
    except DestinationTestError:
        raise
    except TimeoutError as exc:
        raise DestinationTestError("timeout", "the destination protocol handshake timed out") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise DestinationTestError("protocol_failed", "the destination protocol handshake failed") from exc
    finally:
        connection.close()


def _drop_case_insensitive(headers: dict[str, str], name: str) -> None:
    for existing in tuple(headers):
        if existing.lower() == name.lower():
            del headers[existing]


def _destination_has_credentials(destination: _Destination) -> bool:
    if destination.token:
        return True
    for name in destination.headers:
        lowered = name.lower()
        if (
            lowered in {"authorization", "proxy-authorization"}
            or "api-key" in lowered
            or "apikey" in lowered
            or "token" in lowered
            or "secret" in lowered
        ):
            return True
    return False
