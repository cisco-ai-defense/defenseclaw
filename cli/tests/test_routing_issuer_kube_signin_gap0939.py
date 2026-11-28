# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0939 in the Python mirror: with substrate.identity.kube_sign_in
false no one signs in as a Kubernetes person, so kubernetes is not a
trusted issuer and, with one workload issuer, a bare users entry draws no
two-issuer note."""

from __future__ import annotations

from defenseclaw.commands import cmd_routing
from defenseclaw.config import _merge_substrate

CI = "https://ci.example"


def _doc(kube_sign_in: object = None) -> dict:
    ident: dict = {"workload_oidc": [{"issuer": CI}]}
    if kube_sign_in is not None:
        ident["kube_sign_in"] = kube_sign_in
    return {
        "substrate": {"enabled": True, "identity": ident},
        "routing": {"admin": {"rules": [{"id": "r1", "match": {"users": ["alice"]}}]}},
    }


def test_kube_sign_in_on_by_default() -> None:
    assert cmd_routing.person_issuers(_doc()) == ["kubernetes", CI]
    assert cmd_routing.person_issuers(_doc(True)) == ["kubernetes", CI]
    notes = cmd_routing.issuer_notes(_doc())
    assert len(notes) == 1 and "primary issuer kubernetes" in notes[0], notes


def test_kube_sign_in_false_drops_kube_issuer() -> None:
    assert cmd_routing.person_issuers(_doc(False)) == [CI]
    assert cmd_routing.issuer_notes(_doc(False)) == []


def test_kube_sign_in_loads() -> None:
    assert _merge_substrate({"identity": {"kube_sign_in": False}}).identity.kube_sign_in is False
    assert _merge_substrate({"identity": {}}).identity.kube_sign_in is None
