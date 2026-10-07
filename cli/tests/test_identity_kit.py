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

import argparse
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
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


def test_graph_add_member_retries_new_group_404(monkeypatch: pytest.MonkeyPatch) -> None:
    intune = _load(INTUNE)
    graph = intune.Graph("token")
    attempts = []

    def request(*_args):
        attempts.append(1)
        if len(attempts) == 1:
            raise intune.GraphError(404, "Request_ResourceNotFound", "group is replicating")
        return {}

    graph.request = request
    monkeypatch.setattr(intune.time, "sleep", lambda _seconds: None)
    assert graph.add_member("group", "device")
    assert len(attempts) == 2


def test_entra_apply_validates_password_file_before_graph_write(tmp_path: Path) -> None:
    entra = _load(ENTRA)
    plan = tmp_path / "tenant.json"
    plan.write_text(json.dumps({"domain": "example.onmicrosoft.com", "groups": [{"name": "group"}],
                                "users": [{"name": "alice"}]}))
    writes = []

    class Graph:
        def get_all(self, _path):
            writes.append("GET")
            return []

        def request(self, *_args):
            writes.append("POST")
            return {}

    with pytest.raises(SystemExit, match="password-file"):
        entra.cmd_apply(Graph(), argparse.Namespace(config=str(plan), apply=True, password_file=None))
    assert writes == []


def test_intune_groups_adds_to_group_just_created(monkeypatch: pytest.MonkeyPatch) -> None:
    intune = _load(INTUNE)
    graph = intune.Graph("token")
    posts = []
    graph.get_all = lambda path: ([{"id": "device-id"}] if "/devices?" in path else [])
    graph.wait_for_named_object = lambda _path: []
    graph.get_after_create = lambda _path: {"id": "group-id"}

    def request(method, _path, _body):
        posts.append(method)
        return {"id": "group-id"}

    graph.request = request
    graph.add_member = lambda group, device: posts.append((group, device)) or True
    args = argparse.Namespace(name=["new-group"], add_device=["device:new-group"], apply=True)
    assert intune.cmd_groups(graph, args) == 0
    assert ("group-id", "device-id") in posts


def test_okta_group_name_with_spaces_and_admin_url(monkeypatch: pytest.MonkeyPatch) -> None:
    okta = _load(OKTA)
    assert okta.named_int("Research ML Team=1720001") == ("Research ML Team", 1720001)
    monkeypatch.setenv("OKTA_ORG_URL", "https://example-admin.okta.com")
    monkeypatch.setenv("OKTA_API_TOKEN", "dummy")
    with pytest.raises(okta.OktaError, match="not the -admin URL"):
        okta.read_credentials()


def test_entra_apply_validates_later_group_before_first_post(tmp_path: Path) -> None:
    entra = _load(ENTRA)
    plan = tmp_path / "tenant.json"
    plan.write_text(json.dumps({"domain": "example.onmicrosoft.com",
                                "groups": [{"name": "valid"}, {"name": "!!!"}]}))
    with pytest.raises(SystemExit, match="mail nickname"):
        entra.cmd_apply(object(), argparse.Namespace(config=str(plan), apply=True, password_file=None))


def test_intune_check_hides_windows_only_rows_on_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    intune = _load(INTUNE)

    class Graph:
        def get_all(self, _path):
            return []

    monkeypatch.setattr(intune, "try_get", lambda *_args: ({}, None))
    rows = intune.check_items(Graph(), ["macos"], [])
    assert not any("MDM user scope" in row["item"] or "Windows Hello" in row["item"] for row in rows)


def test_intune_macos_script_validates_before_graph_calls(tmp_path: Path) -> None:
    intune = _load(INTUNE)
    script = tmp_path / "wrapper.sh"
    script.write_text("""#!/bin/sh
dc_inline_config() {
    cat <<'DEFENSECLAW_CONFIG'
DEFENSECLAW_CONFIG
}
""")
    args = argparse.Namespace(file=str(script), name="test", frequency="PT1H", retries=3, group=None, apply=False)
    with pytest.raises(SystemExit, match="settings block"):
        intune.cmd_macos_script(object(), args)
    script.write_text("""#!/bin/sh
echo ok
""")
    args.frequency = "bad"
    with pytest.raises(SystemExit, match="frequency"):
        intune.cmd_macos_script(object(), args)


def test_okta_assign_posix_rejects_taken_name_before_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    okta = _load(OKTA)
    user = {"id": "new", "profile": {"login": "alice@example.com"}}
    existing = {"id": "old", "profile": {"login": "other@example.com", "unixUsername": "alice"}}
    monkeypatch.setattr(okta, "collect_users", lambda *_args: [user])

    class Client:
        def get_all(self, _path):
            return [existing]

        def must(self, *_args):
            raise AssertionError("no API write or group lookup expected")

    args = argparse.Namespace(user=["alice@example.com"], users_from=None, apply=True)
    assert okta.cmd_assign_posix(Client(), args) == 1


def test_okta_reactivates_drifted_signon_rule() -> None:
    okta = _load(OKTA)
    calls = []

    class Client:
        def must(self, method, path, _body=None):
            calls.append((method, path))

    policy = {"id": "policy"}
    rule = {"id": "rule", "name": "r", "status": "INACTIVE", "conditions": {"people": {}},
            "actions": {"appSignOn": {"verificationMethod": {"factorMode": "2FA"}}}}
    report = okta.Report(dry_run=False)
    okta.ensure_rule(Client(), report, policy, [rule], "r", 1, {}, "password only")
    assert ("PUT", "/api/v1/policies/policy/rules/rule") in calls
    assert ("POST", "/api/v1/policies/policy/rules/rule/lifecycle/activate") in calls


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
