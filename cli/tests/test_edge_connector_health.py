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

"""The Edge pipeline check must report the real Fleet/MQTT failure modes."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_edge_connector_cli as edge
from defenseclaw.context import AppContext


class Response:
    def __init__(self, status_code: int, body: object) -> None:
        self.status_code = status_code
        self.content = json.dumps(body).encode()
        self._body = body

    def json(self) -> object:
        return self._body


def _healthy_responses() -> dict[str, Response]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "/health": Response(200, {"fleet": {"total_devices": 1, "online": 1, "offline": 0, "degraded": 0, "lockdown": 0}}),
        "/devices": Response(200, {"devices": [{"device_id": 1, "status": "online", "last_heartbeat": now}]}),
        "/policy/versions?tenant_id=1&fleet_id=1": Response(200, {"versions": [{"version": 1, "distributed": True}]}),
    }


def _invoke(monkeypatch: pytest.MonkeyPatch, responses: dict[str, Response], *options: str):
    monkeypatch.setattr(edge, "_client", lambda _app: SimpleNamespace(get=lambda path: responses[path]))
    monkeypatch.setattr(edge, "_check_broker", lambda _url, _timeout: True)
    result = CliRunner().invoke(
        edge.edge_connector_group,
        ["test", "--json", "--broker-url", "mqtt://broker.invalid:1883", *options],
        obj=AppContext(),
    )
    return result, json.loads(result.output)


def test_healthy_fleet_and_distributed_policy_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    result, output = _invoke(monkeypatch, _healthy_responses())
    assert result.exit_code == 0
    assert output["all_ok"] is True
    assert output["policy"]["policy_status"] == "distributed"


@pytest.mark.parametrize("failure", [
    "degraded_health",
    "malformed_health",
    "devices_500",
    "versions_500",
    "policy_not_distributed",
    "stale_heartbeat",
    "missing_heartbeat",
    "offline_device",
    "malformed_devices",
])
def test_unhealthy_pipeline_exits_nonzero(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    responses = copy.deepcopy(_healthy_responses())
    if failure == "degraded_health":
        responses["/health"].json()["fleet"]["degraded"] = 1
    elif failure == "malformed_health":
        responses["/health"] = Response(200, {"status": "ok"})
    elif failure == "devices_500":
        responses["/devices"] = Response(500, {"error": "database down"})
    elif failure == "versions_500":
        responses["/policy/versions?tenant_id=1&fleet_id=1"] = Response(500, {"error": "database down"})
    elif failure == "policy_not_distributed":
        responses["/policy/versions?tenant_id=1&fleet_id=1"].json()["versions"][0]["distributed"] = False
    elif failure == "stale_heartbeat":
        responses["/devices"].json()["devices"][0]["last_heartbeat"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    elif failure == "missing_heartbeat":
        del responses["/devices"].json()["devices"][0]["last_heartbeat"]
    elif failure == "offline_device":
        responses["/devices"].json()["devices"][0]["status"] = "offline"
    elif failure == "malformed_devices":
        responses["/devices"] = Response(200, {"devices": "not a list"})
    result, output = _invoke(monkeypatch, responses)
    assert result.exit_code == 1, failure
    assert output["all_ok"] is False, failure


def test_device_lookup_500_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = _healthy_responses()
    responses["/devices/281479271677953"] = Response(500, {"error": "database down"})
    result, output = _invoke(monkeypatch, responses, "--device-id", "1")
    assert result.exit_code == 1
    assert output["device_check"]["http_status"] == 500


class FakeSocket:
    def __init__(self, reply: bytes) -> None:
        self.reply = reply
        self.sent: list[bytes] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def settimeout(self, _timeout: float) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, count: int) -> bytes:
        part, self.reply = self.reply[:count], self.reply[count:]
        return part


@pytest.mark.parametrize("reply, accepted", [
    (b"\x20\x02\x00\x00", True),
    (b"\x20\x02\x00\x05", False),
    (b"HTTP", False),
    (b"", False),
])
def test_broker_probe_requires_accepted_mqtt_connack(monkeypatch: pytest.MonkeyPatch, reply: bytes, accepted: bool) -> None:
    sock = FakeSocket(reply)
    monkeypatch.setattr(edge.socket, "create_connection", lambda _address, timeout: sock)
    monkeypatch.setattr(edge, "_load_env_var", lambda _name: "")
    assert edge._check_broker("mqtt://broker.invalid:1883") is accepted
    assert sock.sent[0].startswith(b"\x10")


def test_broker_probe_tls_uses_ca_and_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    sock = FakeSocket(b"\x20\x02\x00\x00")
    observed = {}
    monkeypatch.setattr(edge.socket, "create_connection", lambda address, timeout: sock)
    monkeypatch.setattr(edge, "_load_env_var", lambda name: "/tmp/test-ca.pem" if name == "DCLAW_CA_CERT_PATH" else "")

    def make_context(*, cafile):
        observed["cafile"] = cafile

        def wrap(_raw, *, server_hostname):
            observed["hostname"] = server_hostname
            return sock

        return SimpleNamespace(wrap_socket=wrap)

    monkeypatch.setattr(edge.ssl, "create_default_context", make_context)
    assert edge._check_broker("mqtts://broker.example:8883") is True
    assert observed == {"cafile": "/tmp/test-ca.pem", "hostname": "broker.example"}


@pytest.mark.parametrize("url", ["http://broker.example", "mqtt://", "mqtt://host:invalid"])
def test_broker_probe_rejects_invalid_urls(url: str) -> None:
    assert edge._check_broker(url) is False
