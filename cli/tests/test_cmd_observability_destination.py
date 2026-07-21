# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_observability
from defenseclaw.config_inspect import ConfigV8WireResult
from defenseclaw.observability import destination_test


def _destination(
    name: str,
    *,
    endpoint: str = "https://collector.example.test/events",
    kind: str = "http_jsonl",
    protocol: str = "",
    headers: dict | None = None,
    selected_signals: list[str] | None = None,
    signal_overrides: dict | None = None,
) -> dict:
    return {
        "name": name,
        "kind": kind,
        "enabled": True,
        "selected_signals": selected_signals or (["logs"] if kind != "otlp" else ["logs", "traces"]),
        "transport": {
            "endpoint": endpoint,
            "protocol": protocol,
            "method": "POST",
            "headers": headers or {},
            "timeout_ms": 10_000,
            "tls": {},
            "network_safety": {},
            "signal_overrides": signal_overrides or {},
        },
    }


def _effective(*destinations: dict) -> dict:
    return {"destinations": list(destinations)}


@dataclass
class _Compliance:
    activities: list[destination_test.ComplianceActivity] = field(default_factory=list)

    def record(self, activity: destination_test.ComplianceActivity) -> None:
        self.activities.append(activity)


@dataclass
class _Transport:
    handshakes: list[object] = field(default_factory=list)
    writes: list[tuple[object, str]] = field(default_factory=list)
    error: destination_test.DestinationTestError | None = None

    def handshake(self, target: object, *, timeout: float) -> None:
        assert timeout == 2.5
        self.handshakes.append(target)
        if self.error is not None:
            raise self.error

    def write_probe(self, destination: object, *, probe_id: str, timeout: float) -> None:
        assert timeout == 2.5
        self.writes.append((destination, probe_id))
        if self.error is not None:
            raise self.error


def _resolve(reference: str, data_dir: str) -> str:
    assert data_dir == "/data"
    return {"SOC_TOKEN": "super-secret-soc-token", "HEC_TOKEN": "super-secret-hec-token"}[reference]


def test_default_handshake_is_named_non_writing_and_records_local_attempt_outcome() -> None:
    compliance = _Compliance()
    transport = _Transport()

    result = destination_test.run_destination_test(
        _effective(
            _destination("ignored", endpoint="https://ignored.example.test/ingest"),
            _destination(
                "soc",
                headers={"X-SOC-Key": {"env": "SOC_TOKEN"}},
            ),
        ),
        name="soc",
        data_dir="/data",
        timeout=2.5,
        write_probe=False,
        compliance=compliance,
        transport=transport,
        credential_resolver=_resolve,
        probe_id_factory=lambda: "probe-123",
    )

    assert result.mode == "handshake"
    assert result.authentication_verified is False
    assert len(transport.handshakes) == 1
    assert not transport.writes
    assert transport.handshakes[0].host == "collector.example.test"
    assert [item.phase for item in compliance.activities] == ["attempt", "outcome"]
    assert compliance.activities[-1].result == "succeeded"
    assert all(item.destination == "soc" for item in compliance.activities)
    assert "super-secret" not in repr(result)
    assert "super-secret" not in repr(compliance.activities)


def test_destination_test_accepts_setup_valid_uppercase_and_dotted_name() -> None:
    compliance = _Compliance()
    transport = _Transport()

    result = destination_test.run_destination_test(
        _effective(_destination("SOC.Primary")),
        name="SOC.Primary",
        data_dir="/data",
        timeout=2.5,
        write_probe=False,
        compliance=compliance,
        transport=transport,
        credential_resolver=_resolve,
        probe_id_factory=lambda: "setup-name-1",
    )

    assert result.destination == "SOC.Primary"
    assert len(transport.handshakes) == 1


def test_missing_named_destination_records_attempt_and_bounded_outcome() -> None:
    compliance = _Compliance()

    with pytest.raises(destination_test.DestinationTestError) as captured:
        destination_test.run_destination_test(
            _effective(_destination("other")),
            name="missing",
            data_dir="/data",
            timeout=2.5,
            write_probe=False,
            compliance=compliance,
            transport=_Transport(),
            credential_resolver=_resolve,
            probe_id_factory=lambda: "missing-destination-1",
        )

    assert captured.value.failure_class == "not_found"
    assert [item.phase for item in compliance.activities] == ["attempt", "outcome"]
    assert compliance.activities[-1].failure_class == "not_found"


def test_explicit_http_write_targets_only_named_adapter() -> None:
    compliance = _Compliance()
    transport = _Transport()

    result = destination_test.run_destination_test(
        _effective(
            _destination("one", endpoint="https://one.example.test/ingest"),
            _destination(
                "two",
                endpoint="https://two.example.test/ingest",
                headers={"X-Api-Key": {"env": "SOC_TOKEN"}},
            ),
        ),
        name="two",
        data_dir="/data",
        timeout=2.5,
        write_probe=True,
        compliance=compliance,
        transport=transport,
        credential_resolver=_resolve,
        probe_id_factory=lambda: "write-456",
    )

    assert result.mode == "write_probe"
    assert result.authentication_verified is True
    assert not transport.handshakes
    assert len(transport.writes) == 1
    destination, probe_id = transport.writes[0]
    assert destination.name == "two"
    assert destination.targets[0].host == "two.example.test"
    assert probe_id == "write-456"


@pytest.mark.parametrize("kind", ["sqlite", "jsonl", "console", "prometheus", "unknown"])
def test_unsupported_destination_kinds_fail_closed_without_transport(kind: str) -> None:
    compliance = _Compliance()
    transport = _Transport()
    source = _destination("target", kind=kind)

    with pytest.raises(destination_test.DestinationTestError) as captured:
        destination_test.run_destination_test(
            _effective(source),
            name="target",
            data_dir="/data",
            timeout=2.5,
            write_probe=False,
            compliance=compliance,
            transport=transport,
            credential_resolver=_resolve,
            probe_id_factory=lambda: "unsupported-1",
        )

    assert captured.value.failure_class == "unsupported"
    assert not transport.handshakes
    assert not transport.writes
    assert [item.phase for item in compliance.activities] == ["attempt", "outcome"]
    assert compliance.activities[-1].failure_class == "unsupported"


def test_otlp_write_refuses_before_adapter_or_normal_signal_fanout() -> None:
    compliance = _Compliance()
    transport = _Transport()
    source = _destination(
        "otel",
        endpoint="https://otel.example.test",
        kind="otlp",
        protocol="http/protobuf",
    )

    with pytest.raises(destination_test.DestinationTestError) as captured:
        destination_test.run_destination_test(
            _effective(source),
            name="otel",
            data_dir="/data",
            timeout=2.5,
            write_probe=True,
            compliance=compliance,
            transport=transport,
            credential_resolver=_resolve,
            probe_id_factory=lambda: "otlp-write-1",
        )

    assert captured.value.failure_class == "unsupported"
    assert "ordinary logs, traces, or metrics" in captured.value.message
    assert not transport.handshakes
    assert not transport.writes


def test_bounded_failure_class_and_masking_are_preserved_in_outcome() -> None:
    compliance = _Compliance()
    transport = _Transport(
        error=destination_test.DestinationTestError("timeout", "the destination connection timed out")
    )
    source = _destination("soc", headers={"Authorization": {"env": "SOC_TOKEN"}})

    with pytest.raises(destination_test.DestinationTestError) as captured:
        destination_test.run_destination_test(
            _effective(source),
            name="soc",
            data_dir="/data",
            timeout=2.5,
            write_probe=False,
            compliance=compliance,
            transport=transport,
            credential_resolver=_resolve,
            probe_id_factory=lambda: "masked-1",
        )

    assert captured.value.failure_class == "timeout"
    assert captured.value.message == "the destination connection timed out"
    assert "super-secret-soc-token" not in str(captured.value)
    assert compliance.activities[-1].failure_class == "timeout"
    assert "super-secret-soc-token" not in repr(compliance.activities)


def test_unknown_failure_class_is_collapsed_to_bounded_internal_failure() -> None:
    failure = destination_test.DestinationTestError("secret-provider-text", "do-not-display")

    assert failure.failure_class == "internal_failure"
    assert str(failure) == "the destination test failed safely"


def test_missing_credential_is_bounded_and_does_not_reach_transport() -> None:
    compliance = _Compliance()
    transport = _Transport()

    with pytest.raises(destination_test.DestinationTestError) as captured:
        destination_test.run_destination_test(
            _effective(_destination("soc", headers={"X-Key": {"env": "SOC_TOKEN"}})),
            name="soc",
            data_dir="/data",
            timeout=2.5,
            write_probe=False,
            compliance=compliance,
            transport=transport,
            credential_resolver=lambda _reference, _data_dir: "",
            probe_id_factory=lambda: "missing-1",
        )

    assert captured.value.failure_class == "credential_unavailable"
    assert "SOC_TOKEN" not in captured.value.message
    assert not transport.handshakes


@pytest.mark.parametrize("header_name", ["Proxy-Authorization", "pRoXy-AuThOrIzAtIoN"])
def test_proxy_authorization_header_is_rejected_before_origin_transport(header_name: str) -> None:
    compliance = _Compliance()
    transport = _Transport()

    with pytest.raises(destination_test.DestinationTestError) as captured:
        destination_test.run_destination_test(
            _effective(_destination("soc", headers={header_name: "Basic origin-secret"})),
            name="soc",
            data_dir="/data",
            timeout=2.5,
            write_probe=True,
            compliance=compliance,
            transport=transport,
            credential_resolver=_resolve,
            probe_id_factory=lambda: "proxy-auth-1",
        )

    assert captured.value.failure_class == "invalid_destination"
    assert not transport.handshakes
    assert not transport.writes


def test_unbound_compliance_seam_blocks_before_dns_or_network() -> None:
    transport = _Transport()

    with (
        patch.object(destination_test, "resolve_gateway_binary", return_value=None),
        pytest.raises(destination_test.DestinationTestError) as captured,
    ):
        destination_test.run_destination_test(
            _effective(_destination("soc")),
            name="soc",
            data_dir="/data",
            timeout=2.5,
            write_probe=False,
            compliance=destination_test.canonical_local_compliance_recorder(
                config_path="/data/config.yaml",
                data_dir="/data",
            ),
            transport=transport,
            credential_resolver=lambda _reference, _data_dir: "",
            probe_id_factory=lambda: "audit-1",
        )

    assert captured.value.failure_class == "audit_unavailable"
    assert "ensure the v8 gateway is running" in captured.value.message
    assert not transport.handshakes
    assert not transport.writes


def test_mixed_public_private_dns_answers_fail_before_dial() -> None:
    dialed: list[tuple[str, int]] = []

    def dialer(address: str, port: int, timeout: float):
        del timeout
        dialed.append((address, port))
        raise AssertionError("dial must not occur")

    transport = destination_test.SocketProbeTransport(
        resolver=lambda _host, _port, _timeout: ["8.8.8.8", "10.0.0.2"],
        dialer=dialer,
    )
    target = destination_test._parse_target(
        "https://collector.example.test/ingest",
        "http",
        "",
        destination_test._NetworkSafety(),
        destination_test._TLSSettings(),
    )

    with pytest.raises(destination_test.DestinationTestError) as captured:
        transport.handshake(target, timeout=2.5)

    assert captured.value.failure_class == "unsafe_endpoint"
    assert not dialed


def test_socket_probe_retries_validated_addresses_with_one_timeout_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dialed: list[tuple[str, float]] = []
    resolver_timeouts: list[float] = []
    sock = _DummySocket()
    timeline = iter([100.0, 100.1, 100.5, 101.0])
    monkeypatch.setattr(destination_test.time, "monotonic", lambda: next(timeline))

    def resolver(_host: str, _port: int, timeout: float) -> list[str]:
        resolver_timeouts.append(timeout)
        return ["2606:4700:4700::1111", "1.1.1.1"]

    def dialer(address: str, _port: int, timeout: float):
        dialed.append((address, timeout))
        if len(dialed) == 1:
            raise OSError("IPv6 route unavailable")
        return sock

    target = destination_test._parse_target(
        "http://collector.example.test/ingest",
        "http",
        "",
        destination_test._NetworkSafety(),
        destination_test._TLSSettings(),
    )
    transport = destination_test.SocketProbeTransport(resolver=resolver, dialer=dialer)

    with patch.object(destination_test, "_request_over_socket"):
        transport.handshake(target, timeout=2.5)

    assert resolver_timeouts == pytest.approx([2.4])
    assert [address for address, _timeout in dialed] == ["2606:4700:4700::1111", "1.1.1.1"]
    assert [timeout for _address, timeout in dialed] == pytest.approx([2.0, 1.5])
    assert sock.closed


def test_private_opt_in_never_allows_reserved_documentation_address() -> None:
    target = destination_test._parse_target(
        "https://collector.example.test/ingest",
        "http",
        "",
        destination_test._NetworkSafety(allow_private_networks=True),
        destination_test._TLSSettings(),
    )

    with pytest.raises(destination_test.DestinationTestError) as captured:
        destination_test.SocketProbeTransport(
            resolver=lambda _host, _port, _timeout: ["192.0.2.10"],
            dialer=lambda *_args: (_ for _ in ()).throw(AssertionError("dial must not occur")),
        ).handshake(target, timeout=2.5)

    assert captured.value.failure_class == "unsafe_endpoint"


def test_otlp_signal_override_path_rejects_request_injection() -> None:
    source = _destination(
        "otel",
        endpoint="https://otel.example.test",
        kind="otlp",
        protocol="http/protobuf",
        selected_signals=["logs"],
        signal_overrides={"logs": {"path": "/v1/logs\r\nX-Evil: true"}},
    )

    with pytest.raises(destination_test.DestinationTestError) as captured:
        destination_test._compile_destination(
            source,
            data_dir="/data",
            credential_resolver=_resolve,
        )

    assert captured.value.failure_class == "invalid_destination"


@pytest.mark.parametrize(
    ("endpoint", "expected_path"),
    [
        ("https://otel.example.test", "/v1/traces"),
        ("https://otel.example.test/acme/v1/traces", "/acme/v1/traces"),
    ],
)
def test_otlp_handshake_uses_the_runtime_resolved_endpoint_path(
    endpoint: str,
    expected_path: str,
) -> None:
    destination = destination_test._compile_destination(
        _destination(
            "otel",
            endpoint=endpoint,
            kind="otlp",
            protocol="http/protobuf",
            selected_signals=["traces"],
        ),
        data_dir="/data",
        credential_resolver=_resolve,
    )

    assert len(destination.targets) == 1
    assert destination.targets[0].request_target == expected_path


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://otel.example.test/v1/traces?tenant=hidden",
        "https://otel.example.test/v1/traces#private",
    ],
)
def test_otlp_handshake_defensively_rejects_query_and_fragment(endpoint: str) -> None:
    with pytest.raises(destination_test.DestinationTestError) as captured:
        destination_test._compile_destination(
            _destination(
                "otel",
                endpoint=endpoint,
                kind="otlp",
                protocol="http/protobuf",
                selected_signals=["traces"],
            ),
            data_dir="/data",
            credential_resolver=_resolve,
        )

    assert captured.value.failure_class == "invalid_destination"


@pytest.mark.parametrize("field", ["tls", "network_safety"])
def test_effective_transport_security_shapes_fail_closed(field: str) -> None:
    source = _destination("soc")
    source["transport"][field] = "invalid"

    with pytest.raises(destination_test.DestinationTestError) as captured:
        destination_test._compile_destination(
            source,
            data_dir="/data",
            credential_resolver=_resolve,
        )

    assert captured.value.failure_class == "invalid_destination"


def test_system_dns_resolution_honors_timeout_without_exposing_resolver_error() -> None:
    release = Event()

    def blocked_lookup(*_args, **_kwargs):
        release.wait(1)
        return []

    try:
        with (
            patch.object(destination_test.socket, "getaddrinfo", side_effect=blocked_lookup),
            pytest.raises(destination_test.DestinationTestError) as captured,
        ):
            destination_test._system_resolver("collector.example.test", 443, 0.01)
    finally:
        release.set()

    assert captured.value.failure_class == "timeout"
    assert "collector.example.test" not in captured.value.message


def test_socket_default_http_handshake_is_bodyless_options_and_never_writes() -> None:
    captured: dict = {}
    sock = _DummySocket()
    target = destination_test._parse_target(
        "http://8.8.8.8/ingest",
        "http",
        "",
        destination_test._NetworkSafety(),
        destination_test._TLSSettings(),
    )

    def capture_request(request_sock, request_target, **kwargs) -> None:
        captured.update(sock=request_sock, target=request_target, **kwargs)

    transport = destination_test.SocketProbeTransport(
        resolver=lambda _host, _port, _timeout: ["8.8.8.8"],
        dialer=lambda _address, _port, _timeout: sock,
    )
    with patch.object(destination_test, "_request_over_socket", side_effect=capture_request):
        transport.handshake(target, timeout=2.5)

    assert captured["method"] == "OPTIONS"
    assert captured["body"] == b""
    assert captured["inspect_hec"] is False
    assert captured["headers"] == {"Content-Length": "0", "Connection": "close"}
    assert sock.closed


class _DummySocket:
    def __init__(self) -> None:
        self.closed = False

    def gettimeout(self) -> float:
        return 2.5

    def close(self) -> None:
        self.closed = True


class _DummyHTTPResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.body = body
        self.reads = 0

    def read(self, amount: int) -> bytes:
        self.reads += 1
        return self.body[:amount]


class _DummyHTTPConnection:
    def __init__(self, response: _DummyHTTPResponse) -> None:
        self.response = response
        self.closed = False
        self.sock = None

    def request(self, *_args, **_kwargs) -> None:
        return None

    def getresponse(self) -> _DummyHTTPResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize("kind", ["http_jsonl", "splunk_hec"])
def test_socket_write_probe_is_content_free_marked_and_direct(kind: str) -> None:
    captured: dict = {}
    sock = _DummySocket()
    source = _destination("target", endpoint="http://8.8.8.8/ingest", kind=kind)
    if kind == "splunk_hec":
        source["transport"]["token_env"] = "HEC_TOKEN"
        source["transport"]["index"] = "security"
    destination = destination_test._compile_destination(
        source,
        data_dir="/data",
        credential_resolver=_resolve,
    )

    def capture_request(
        request_sock,
        target,
        *,
        method: str,
        body: bytes,
        headers: dict,
        inspect_hec: bool,
    ) -> None:
        captured.update(
            sock=request_sock,
            target=target,
            method=method,
            body=body,
            headers=headers,
            inspect_hec=inspect_hec,
        )

    transport = destination_test.SocketProbeTransport(
        resolver=lambda _host, _port, _timeout: ["8.8.8.8"],
        dialer=lambda _address, _port, _timeout: sock,
    )
    with patch.object(destination_test, "_request_over_socket", side_effect=capture_request):
        transport.write_probe(destination, probe_id="probe-direct-1", timeout=2.5)

    payload = captured["body"].decode("utf-8")
    assert "probe-direct-1" in payload
    assert "defenseclaw_destination_test" in payload
    assert all(token not in payload for token in ("prompt", "response", "finding", "tool"))
    assert captured["headers"]["X-DefenseClaw-Probe"] == "destination-test"
    assert captured["headers"]["X-DefenseClaw-Probe-ID"] == "probe-direct-1"
    assert captured["target"].host == "8.8.8.8"
    assert sock.closed


def test_splunk_probe_uses_token_default_index_when_none_is_configured() -> None:
    captured: dict = {}
    sock = _DummySocket()
    source = _destination("target", endpoint="http://8.8.8.8/ingest", kind="splunk_hec")
    source["transport"]["token_env"] = "HEC_TOKEN"
    destination = destination_test._compile_destination(
        source,
        data_dir="/data",
        credential_resolver=_resolve,
    )
    transport = destination_test.SocketProbeTransport(
        resolver=lambda _host, _port, _timeout: ["8.8.8.8"],
        dialer=lambda _address, _port, _timeout: sock,
    )

    def capture_request(_sock, _target, **kwargs) -> None:
        captured.update(kwargs)

    with patch.object(destination_test, "_request_over_socket", side_effect=capture_request):
        transport.write_probe(destination, probe_id="splunk-default-1", timeout=2.5)

    assert "index" not in destination_test.json.loads(captured["body"])


def test_splunk_acknowledgement_requires_successful_http_status() -> None:
    response = _DummyHTTPResponse(503, b'{"code":0}')
    connection = _DummyHTTPConnection(response)
    target = destination_test._parse_target(
        "http://8.8.8.8/ingest",
        "http",
        "",
        destination_test._NetworkSafety(),
        destination_test._TLSSettings(),
    )

    with (
        patch.object(destination_test.http.client, "HTTPConnection", return_value=connection),
        pytest.raises(destination_test.DestinationTestError) as captured,
    ):
        destination_test._request_over_socket(
            _DummySocket(),
            target,
            method="POST",
            body=b"{}",
            headers={},
            inspect_hec=True,
        )

    assert captured.value.failure_class == "remote_rejected"
    assert response.reads == 0
    assert connection.closed


def test_splunk_acknowledgement_accepts_code_zero_with_successful_http_status() -> None:
    response = _DummyHTTPResponse(200, b'{"code":0}')
    connection = _DummyHTTPConnection(response)
    target = destination_test._parse_target(
        "http://8.8.8.8/ingest",
        "http",
        "",
        destination_test._NetworkSafety(),
        destination_test._TLSSettings(),
    )

    with patch.object(destination_test.http.client, "HTTPConnection", return_value=connection):
        destination_test._request_over_socket(
            _DummySocket(),
            target,
            method="POST",
            body=b"{}",
            headers={},
            inspect_hec=True,
        )

    assert response.reads == 1
    assert connection.closed


def test_top_level_command_registers_named_write_probe_without_legacy_config_load(tmp_path: Path) -> None:
    from defenseclaw.main import cli

    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 8\nobservability: {}\n", encoding="utf-8")
    wire = ConfigV8WireResult(
        wire_version=1,
        kind="effective",
        config_version=8,
        source=str(config_path),
        data_dir=str(tmp_path),
        plan_digest="destination-test-plan",
        network_validation="offline_syntax_and_literal_policy_only",
        effective=_effective(_destination("soc")),
    )
    expected = destination_test.DestinationTestResult(
        destination="soc",
        kind="http_jsonl",
        mode="write_probe",
        probe_id="cli-probe-1",
        endpoint_count=1,
        protocol="http",
        authentication_verified=True,
        compliance_recorded=True,
    )
    with (
        patch.object(cmd_observability.config_module, "config_path", return_value=config_path),
        patch.object(cmd_observability, "inspect_v8_config", return_value=wire),
        patch.object(
            cmd_observability,
            "canonical_local_compliance_recorder",
            return_value=_Compliance(),
        ) as recorder,
        patch.object(cmd_observability, "run_destination_test", return_value=expected) as run,
        patch("defenseclaw.config.load", side_effect=AssertionError("legacy config loader must not run")),
    ):
        result = CliRunner().invoke(
            cli,
            ["observability", "destination", "test", "soc", "--write-probe", "--timeout", "2.5"],
        )

    assert result.exit_code == 0, result.output
    assert "probe ID: cli-probe-1" in result.output
    assert "super-secret" not in result.output
    assert run.call_args.kwargs["name"] == "soc"
    assert run.call_args.kwargs["write_probe"] is True
    assert run.call_args.kwargs["timeout"] == 2.5
    recorder.assert_called_once_with(config_path=str(config_path), data_dir=str(tmp_path))


def test_top_level_command_fails_before_network_when_local_only_audit_seam_is_unbound(tmp_path: Path) -> None:
    from defenseclaw.main import cli

    config_path = tmp_path / "config.yaml"
    config_path.write_text("config_version: 8\nobservability: {}\n", encoding="utf-8")
    wire = ConfigV8WireResult(
        wire_version=1,
        kind="effective",
        config_version=8,
        source=str(config_path),
        data_dir=str(tmp_path),
        plan_digest="destination-test-plan",
        network_validation="offline_syntax_and_literal_policy_only",
        effective=_effective(_destination("soc")),
    )
    with (
        patch.object(cmd_observability.config_module, "config_path", return_value=config_path),
        patch.object(cmd_observability, "inspect_v8_config", return_value=wire),
        patch.object(destination_test, "resolve_gateway_binary", return_value=None),
        patch.object(
            destination_test,
            "SocketProbeTransport",
            side_effect=AssertionError("network transport must not be created"),
        ),
    ):
        result = CliRunner().invoke(cli, ["observability", "destination", "test", "soc"])

    assert result.exit_code != 0
    assert "audit_unavailable" in result.output
    assert "ensure the v8 gateway is running" in result.output
    assert "collector.example.test" not in result.output


def test_gateway_local_compliance_recorder_uses_stdin_and_accepts_exact_acknowledgement(tmp_path: Path) -> None:
    activity = destination_test.ComplianceActivity(
        phase="outcome",
        destination="soc",
        probe_id="probe-123",
        mode="handshake",
        result="failed",
        failure_class="timeout",
    )
    completed = subprocess.CompletedProcess([], 0, stdout='{"recorded":true}\n', stderr="ignored-secret")
    recorder = destination_test.GatewayLocalComplianceRecorder(
        config_path=str(tmp_path / "config.yaml"),
        data_dir=str(tmp_path),
    )
    with (
        patch.object(destination_test, "resolve_gateway_binary", return_value="/opt/bin/defenseclaw-gateway"),
        patch.object(destination_test.subprocess, "run", return_value=completed) as run,
    ):
        recorder.record(activity)

    argv = run.call_args.args[0]
    assert argv[:3] == [
        "/opt/bin/defenseclaw-gateway",
        "observability-v8",
        "record-destination-test-activity",
    ]
    assert "probe-123" not in argv
    assert "timeout" not in argv
    assert destination_test.json.loads(run.call_args.kwargs["input"]) == {
        "phase": "outcome",
        "destination": "soc",
        "probe_id": "probe-123",
        "mode": "handshake",
        "result": "failed",
        "failure_class": "timeout",
    }
    assert "shell" not in run.call_args.kwargs


@pytest.mark.parametrize(
    ("completed", "side_effect"),
    [
        (subprocess.CompletedProcess([], 1, stdout="", stderr="remote-secret"), None),
        (subprocess.CompletedProcess([], 0, stdout='{"recorded":false}', stderr=""), None),
        (None, subprocess.TimeoutExpired(["gateway"], timeout=10)),
    ],
)
def test_gateway_local_compliance_recorder_fails_closed_without_echoing_helper_output(
    tmp_path: Path,
    completed: subprocess.CompletedProcess[str] | None,
    side_effect: BaseException | None,
) -> None:
    recorder = destination_test.GatewayLocalComplianceRecorder(
        config_path=str(tmp_path / "config.yaml"),
        data_dir=str(tmp_path),
    )
    kwargs = {"return_value": completed} if side_effect is None else {"side_effect": side_effect}
    with (
        patch.object(destination_test, "resolve_gateway_binary", return_value="gateway"),
        patch.object(destination_test.subprocess, "run", **kwargs),
        pytest.raises(destination_test.DestinationTestError) as caught,
    ):
        recorder.record(
            destination_test.ComplianceActivity("attempt", "soc", "probe-1", "handshake", "attempted", None)
        )
    assert caught.value.failure_class == "audit_unavailable"
    assert "remote-secret" not in str(caught.value)
