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

"""GAP-0792 (issuer#subject users entries, bare-name warning) and GAP-0848
(retired budget keys at half the bound) in the Python mirror and doctor."""

from __future__ import annotations

from types import SimpleNamespace

from defenseclaw.commands import cmd_doctor, cmd_routing

IDP_A, IDP_B = "https://idp-a.example", "https://idp-b.example"


def _doc(*workloads: str) -> dict:
    return {
        "substrate": {
            "enabled": True,
            "identity": {"oidc": {"issuer": IDP_A}, "workload_oidc": [{"issuer": w} for w in workloads]},
        },
        "routing": {
            "admin": {
                "rules": [{"id": "r1", "match": {"users": ["alice", IDP_B + "#bob", "uid:1001"]}}],
                "budgets": [
                    {"id": "b1", "scope": "user", "subject": "carol"},
                    {"id": "b2", "scope": "user", "subject": "*"},
                    {"id": "b3", "scope": "user", "subject": IDP_B + "#carol"},
                ],
            }
        },
    }


def test_split_qualified_user() -> None:
    assert cmd_routing.split_qualified_user(IDP_B + "#alice") == (IDP_B, "alice")
    assert cmd_routing.split_qualified_user("alice") is None
    assert cmd_routing.split_qualified_user("dom#user") is None


def test_bare_names_warn_only_with_two_issuers() -> None:
    assert cmd_routing.person_issuers(_doc()) == [IDP_A]
    # One issuer: no bare-name note; the idp-b entries name an untrusted issuer (GAP-0895).
    one = cmd_routing.issuer_notes(_doc())
    assert len(one) == 2 and all("not a trusted issuer" in n for n in one), one
    assert cmd_routing.person_issuers(_doc(IDP_B, IDP_A)) == [IDP_A, IDP_B]
    notes = cmd_routing.issuer_notes(_doc(IDP_B))
    assert len(notes) == 2, notes
    assert notes[0].startswith("rule r1: users entry 'alice'") and IDP_A in notes[0]
    assert notes[1].startswith("budget b1: subject 'carol'")
    assert all(n in cmd_routing._lint(_doc(IDP_B)) for n in notes)


def _view(waiting: int, dropped: int = 0, cap: int = 4096) -> dict:
    return {"id": "agent", "retired_keys": {"waiting": waiting, "dropped": dropped, "cap": cap}}


def test_retired_key_rows_from_half_full() -> None:
    assert cmd_routing.retired_key_rows([_view(2047), {"id": "x"}]) == []
    rows = cmd_routing.retired_key_rows([_view(2048)])
    assert rows and rows[0][0] == "warn" and "2048 of 4096" in rows[0][1]
    rows = cmd_routing.retired_key_rows([_view(10, dropped=3)])
    assert rows and "3 retired key(s) was dropped" in rows[0][1]


class _Client:
    answer: dict = {}

    def __init__(self, **_kw) -> None:
        pass

    def routing_request(self, method: str, path: str) -> dict:
        assert (method, path) == ("GET", "/api/v1/routing/budgets")
        return self.answer

    def close(self) -> None:
        pass


def _doctor_rows(monkeypatch, scope: str, answer: dict, down: str = "") -> list[tuple]:
    import defenseclaw.gateway as gw

    _Client.answer = answer
    monkeypatch.setattr(gw, "OrchestratorClient", _Client)
    monkeypatch.setattr(cmd_doctor, "_gateway_api_host", lambda _cfg: "127.0.0.1")
    seen: list[tuple] = []
    monkeypatch.setattr(
        cmd_doctor, "_emit", lambda status, label, detail="", **kw: seen.append((status, label, detail))
    )
    cfg = SimpleNamespace(
        routing=SimpleNamespace(admin={"budgets": [{"id": "agent", "scope": scope}]}),
        gateway=SimpleNamespace(resolved_token=lambda: "t", api_port=18970),
    )
    cmd_doctor._check_routing_budget_keys(cfg, SimpleNamespace(gateway_down=down))
    return seen


def test_doctor_row_at_half_full(monkeypatch) -> None:
    answer = {"budgets": [_view(2048)]}
    rows = _doctor_rows(monkeypatch, "actor", answer)
    assert [(s, label) for s, label, _ in rows] == [("warn", "Routing budget keys")]
    assert _doctor_rows(monkeypatch, "actor", {"budgets": [_view(100)]}) == []
    assert _doctor_rows(monkeypatch, "user", answer) == []
    assert _doctor_rows(monkeypatch, "batch", answer, down="stopped") == []
