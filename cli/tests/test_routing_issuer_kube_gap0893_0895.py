# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0893 (the Kubernetes sign-in issuer is the primary person issuer
with no OIDC issuer on an install that is not managed) and GAP-0895 (an
issuer#subject entry with an untrusted issuer warns; HTTPS:// splits as in
Go) in the Python mirror."""

from __future__ import annotations

from defenseclaw.commands import cmd_routing

CI_A, CI_B, IDP = "https://ci-a.example", "https://ci-b.example", "https://idp-b.example"


def _doc(oidc: str = "", mode: str = "", users: list[str] | None = None) -> dict:
    return {
        "deployment_mode": mode,
        "substrate": {
            "enabled": True,
            "identity": {"oidc": {"issuer": oidc}, "workload_oidc": [{"issuer": CI_A}, {"issuer": CI_B}]},
        },
        "routing": {"admin": {"rules": [{"id": "r1", "match": {"users": users or ["alice"]}}]}},
    }


def test_kube_issuer_is_primary_without_oidc() -> None:
    assert cmd_routing.person_issuers(_doc()) == ["kubernetes", CI_A, CI_B]
    notes = cmd_routing.issuer_notes(_doc())
    assert len(notes) == 1 and "primary issuer kubernetes" in notes[0], notes
    assert cmd_routing.person_issuers(_doc(mode="managed_enterprise")) == [CI_A, CI_B]
    assert cmd_routing.person_issuers(_doc(oidc=IDP)) == [IDP, CI_A, CI_B]


def test_untrusted_issuer_warns() -> None:
    doc = _doc(oidc=IDP, users=[IDP + "#ok", IDP + "/#slash", "https://IDP-b.example#case"])
    notes = cmd_routing.issuer_notes(doc)
    assert len(notes) == 2, notes
    assert all("not a trusted issuer" in n for n in notes)
    assert "slash" in notes[0] and "case" in notes[1]
    assert all(n in cmd_routing._lint(doc) for n in notes)


def test_scheme_case_splits_like_go() -> None:
    # Go: HTTPS:// is a bare name (case-sensitive scheme); the mirror agrees.
    assert cmd_routing.split_qualified_user("HTTPS://idp-b.example#alice") is None
    doc = _doc(oidc=IDP, users=["HTTPS://idp-b.example#alice"])
    notes = cmd_routing.issuer_notes(doc)
    assert len(notes) == 1 and "has no issuer" in notes[0], notes
