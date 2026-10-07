# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Contracts for the identity starter kits (packaging/identity/entra and okta) and the Intune tenant helper.

The Entra and Intune helpers each ship as one standalone file, so the small Microsoft
Graph client inside them is copied, and this test keeps the copies identical. It also
pins the one computation an administrator relies on without a tenant (the Windows SID
of an Entra object) and checks that every script in the kit has --help and is ASCII. For the
Okta kit it renders the SSSD config without a host, because a placeholder left in sssd.conf
or a password that was expanded a second time would only show up on a Linux host.
"""

from __future__ import annotations

import importlib.util
import io
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
from email.message import Message
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ENTRA = ROOT / "packaging" / "identity" / "entra" / "entra_setup.py"
INTUNE = ROOT / "packaging" / "mdm" / "intune" / "tenant" / "intune_tenant.py"
OKTA = ROOT / "packaging" / "identity" / "okta" / "okta-ldap-setup.py"
OKTA_INSTALL = OKTA.parent / "install-sssd-okta.sh"
KIT_DIRS = (ENTRA.parent, INTUNE.parent, OKTA.parent)
REGION_BEGIN = "# region graph client"
REGION_END = "# endregion graph client"


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[path.stem] = module
    spec.loader.exec_module(module)
    return module


def test_graph_client_copies_are_identical() -> None:
    def region(path: Path) -> str:
        text = path.read_text(encoding="utf-8")
        return text[text.index(REGION_BEGIN) : text.index(REGION_END)]

    assert region(ENTRA) == region(INTUNE)


def test_graph_add_member_treats_an_existing_member_as_done() -> None:
    # GAP-0235: a rerun right after an add (the members list lags) got 400 and failed.
    intune = _load(INTUNE)
    graph = intune.Graph("token")

    def answer(status: int, message: str):
        def request(*_args, **_kwargs):
            raise intune.GraphError(status, "Request_BadRequest", message)

        return request

    graph.request = answer(400, "One or more added object references already exist for the following modified properties")
    assert graph.add_member("group", "device") is False
    graph.request = answer(403, "Insufficient privileges to complete the operation.")
    with pytest.raises(intune.GraphError):
        graph.add_member("group", "device")


def test_entra_sid_is_four_words_of_the_object_id() -> None:
    entra = _load(ENTRA)
    # Data1 = 1; Data2 and Data3 share one little-endian word; Data4 is two more.
    assert entra.sid_from_object_id("00000001-0002-0003-0405-060708090a0b") == "S-1-12-1-1-196610-117835012-185207048"
    with pytest.raises(ValueError):
        entra.sid_from_object_id("not-a-guid")


@pytest.mark.parametrize("script", [ENTRA, INTUNE, OKTA], ids=lambda path: path.name)
def test_python_helpers_print_help_without_credentials(script: Path) -> None:
    result = subprocess.run([sys.executable, "-I", str(script), "--help"], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "Credentials" in result.stdout or "credentials" in result.stdout


def test_kit_files_are_ascii_with_unix_line_endings() -> None:
    checked = 0
    for directory in KIT_DIRS:
        for path in sorted(directory.rglob("*")):
            if path.is_file() and path.suffix in {".py", ".sh", ".ps1", ".json", ".yaml", ".md", ".tmpl", ".conf"}:
                data = path.read_bytes()
                assert all(byte < 0x80 for byte in data), f"{path.relative_to(ROOT)} has non-ASCII bytes"
                assert b"\r\n" not in data, f"{path.relative_to(ROOT)} has CRLF line endings"
                checked += 1
    assert checked >= 5


def test_kit_does_not_say_an_empty_connector_entry_is_dropped() -> None:
    # GAP-0305: the config loaders keep an empty entry such as `claudecode: {}` and enable that
    # agent (GAP-0221), so the starter configs and their guides must not say it is dropped.
    guides = ROOT / "docs-site" / "content" / "docs" / "enterprise"
    paths = sorted(path for directory in KIT_DIRS for path in directory.glob("*.example.yaml"))
    assert len(paths) >= 3
    for path in [*paths, guides / "identity-okta.mdx", guides / "identity-entra-id.mdx"]:
        text = " ".join(path.read_text(encoding="utf-8").replace("#", " ").split())
        assert not re.search(r"\{\}`? is dropped", text), path.relative_to(ROOT)


@pytest.mark.skipif(not sys.platform.startswith("linux") or not shutil.which("bash"), reason="a Linux host script")
def test_okta_sssd_render_fills_every_placeholder_once(tmp_path: Path) -> None:
    out = tmp_path / "sssd.conf"
    # A password that looks like a placeholder must land in sssd.conf as written.
    password = "p@LDAP_URI@ss&word"
    result = subprocess.run(
        ["bash", str(OKTA_INSTALL), "--org", "example", "--bind-login", "ldap-bind@example.com",
         "--allow-group", "linux-users", "--map-upn", "--render-only", str(out)],
        capture_output=True, text=True, timeout=60, env={**os.environ, "OKTA_BIND_PASSWORD": password},
    )
    assert result.returncode == 0, result.stderr
    text = out.read_text(encoding="ascii")
    assert not re.search(r"@[A-Z_]+@", text.replace(password, "")), "a template placeholder was left unfilled"
    assert f"ldap_default_authtok = {password}\n" in text
    assert "ldap_uri = ldaps://example.ldap.okta.com:636\n" in text
    assert "ldap_default_bind_dn = uid=ldap-bind@example.com,dc=example,dc=okta,dc=com\n" in text
    assert "ldap_user_principal = uid\n" in text
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_okta_pagination_reads_separate_link_headers() -> None:
    okta = _load(OKTA)
    headers = Message()
    headers.add_header("Link", '<https://example.okta.com/api/v1/users?limit=1>; rel="self"')
    headers.add_header("Link", '<https://example.okta.com/api/v1/users?after=one>; rel="next"')

    class Response(io.BytesIO):
        status = 200
        def __init__(self, body: bytes, response_headers: Message):
            super().__init__(body)
            self.headers = response_headers

    responses = iter([Response(b'[{"id":"one"}]', headers), Response(b'[{"id":"two"}]', Message())])
    client = okta.Okta("https://example.okta.com", "token")
    client._opener.open = lambda *_args, **_kwargs: next(responses)
    assert [user["id"] for user in client.get_all("/api/v1/users?limit=1")] == ["one", "two"]


def test_okta_rate_limit_honors_lowercase_reset_header(monkeypatch: pytest.MonkeyPatch) -> None:
    okta = _load(OKTA)
    waited = []
    monkeypatch.setattr(okta.time, "sleep", waited.append)
    reset = int(time.time()) + 20

    class Opener:
        def open(self, *_args, **_kwargs):
            raise urllib.error.HTTPError("https://example.okta.com/api/v1/users", 429,
                                         "rate limit", {"x-rate-limit-reset": str(reset)}, io.BytesIO(b"{}"))

    client = okta.Okta("https://example.okta.com", "token")
    client._opener = Opener()
    status, _, _ = client.call("GET", "/api/v1/users")
    assert status == 429
    assert waited and min(waited) > 5


def test_okta_explicit_gid_is_not_its_own_collision(monkeypatch: pytest.MonkeyPatch) -> None:
    okta = _load(OKTA)
    group = {"id": "group1", "type": "OKTA_GROUP", "profile": {"name": "team"}}
    monkeypatch.setattr(okta, "find_group", lambda *_args: group)

    class Client:
        def must(self, method, path, body):
            assert (method, path, body["profile"]["gidNumber"]) == ("PUT", "/api/v1/groups/group1", 1720500)

    report = okta.Report(dry_run=False)
    assert okta.ensure_group(Client(), report, "team", 1720500, set(), 1720000) == (group, 1720500)
    assert report.problems == 0


def test_okta_bind_role_refuses_extra_permissions(monkeypatch: pytest.MonkeyPatch) -> None:
    okta = _load(OKTA)
    monkeypatch.setattr(okta, "find_user", lambda *_args: {"id": "bind1"})

    class Client:
        org_url = "https://example.okta.com"
        def get_all(self, path, key=None):
            if key == "roles":
                return [{"id": "role1", "label": "reader"}]
            if key == "resource-sets":
                return [{"id": "set1", "label": "all"}]
            if key == "resources":
                return [{"_links": {"self": {"href": self.org_url + "/api/v1/" + kind}}}
                        for kind in ("users", "groups")]
            raise AssertionError(path)
        def must(self, method, path, body=None):
            if path.endswith("/permissions"):
                return {"permissions": [{"label": label} for label in
                        [*okta.BIND_PERMISSIONS, "okta.users.manage"]]}
            if path.endswith("/resources"):
                return {"resources": [{"_links": {"self": {"href": self.org_url + "/api/v1/" + kind}}}
                                      for kind in ("users", "groups")]}
            if method == "GET":
                return []
            raise AssertionError("an overbroad role must not be assigned")

    args = type("Args", (), {"apply": True, "bind_login": "bind@example.com",
                             "role_label": "reader", "resource_set_label": "all"})()
    assert okta.cmd_bind_role(Client(), args) == 1


def test_okta_bind_role_refuses_narrow_resource_set(monkeypatch: pytest.MonkeyPatch) -> None:
    okta = _load(OKTA)
    monkeypatch.setattr(okta, "find_user", lambda *_args: {"id": "bind1"})

    class Client:
        org_url = "https://example.okta.com"
        def get_all(self, path, key=None):
            if key == "roles":
                return [{"id": "role1", "label": "reader"}]
            if key == "resource-sets":
                return [{"id": "set1", "label": "all"}]
            if key == "resources":
                return [{"_links": {"self": {"href": self.org_url + "/api/v1/users/one"}}}]
            raise AssertionError(path)
        def must(self, method, path, body=None):
            if path.endswith("/permissions"):
                return {"permissions": [{"label": label} for label in okta.BIND_PERMISSIONS]}
            if method == "GET":
                return []
            raise AssertionError("a narrow resource set must not be assigned")

    args = type("Args", (), {"apply": True, "bind_login": "bind@example.com",
                             "role_label": "reader", "resource_set_label": "all"})()
    assert okta.cmd_bind_role(Client(), args) == 1


def test_okta_signon_rule_repairs_non_password_decisions() -> None:
    okta = _load(OKTA)
    people = {"users": {"include": ["bind1"]}}
    for status, access, factor in [("INACTIVE", "ALLOW", "1FA"),
                                   ("ACTIVE", "DENY", "1FA"), ("ACTIVE", "ALLOW", "2FA")]:
        calls = []

        class Client:
            def must(self, method, path, body=None):
                calls.append((method, path))
                return {}

        rule = {"id": "rule1", "name": "bind", "status": status, "conditions": {"people": people},
                "actions": {"appSignOn": {"access": access, "verificationMethod": {
                    "type": "ASSURANCE", "factorMode": factor,
                    "constraints": [{"knowledge": {"types": ["password"]}}]}}}}
        report = okta.Report(dry_run=False)
        okta.ensure_rule(Client(), report, {"id": "policy1"}, [rule], "bind", 0, people, "bind user")
        assert ("PUT", "/api/v1/policies/policy1/rules/rule1") in calls
        if status == "INACTIVE":
            assert ("POST", "/api/v1/policies/policy1/rules/rule1/lifecycle/activate") in calls


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="a Linux host script")
def test_okta_render_only_replaces_world_readable_output(tmp_path: Path) -> None:
    out = tmp_path / "sssd.conf"
    out.write_text("old")
    out.chmod(0o644)
    result = subprocess.run(
        ["bash", str(OKTA_INSTALL), "--org", "example", "--bind-login", "bind@example.com",
         "--allow-group", "linux-users", "--render-only", str(out)],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "OKTA_BIND_PASSWORD": "test-password"},
    )
    assert result.returncode == 0, result.stderr
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert "ldap_default_authtok = test-password" in out.read_text()
