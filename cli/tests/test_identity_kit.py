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


def test_intune_group_devices_match_directory_ids(capsys: pytest.CaptureFixture[str]) -> None:
    intune = _load(INTUNE)

    class Graph:
        def get_all(self, path: str, headers=None):
            if "managedDevices" in path:
                return [
                    {"id": "managed-1", "deviceName": "SHARED", "azureADDeviceId": "AAD-1"},
                    {"id": "managed-2", "deviceName": "SHARED", "azureADDeviceId": "AAD-2"},
                ]
            if "/groups?" in path:
                return [{"id": "group-1"}]
            if "/members" in path:
                return [{"deviceId": "aad-1"}]
            raise AssertionError(path)

    args = intune.build_parser().parse_args(["devices", "--group", "team", "--json"])
    assert intune.cmd_devices(Graph(), args) == 0
    import json
    assert [d["id"] for d in json.loads(capsys.readouterr().out)] == ["managed-1"]


@pytest.mark.parametrize("command", ["remediation", "macos-script"])
def test_intune_script_validates_group_before_upsert(tmp_path: Path, command: str) -> None:
    intune = _load(INTUNE)
    script = tmp_path / "script.txt"
    script.write_text("echo ok\n", encoding="ascii")
    mutations = []

    class Graph:
        def get_all(self, path: str, headers=None):
            if "/groups?" in path:
                return []
            return [{"id": "script-1"}]

        def request(self, method: str, path: str, body):
            mutations.append((method, path))
            return {}

    options = (
        ["--detect", str(script), "--remediate", str(script)]
        if command == "remediation"
        else ["--name", "test", "--file", str(script)]
    )
    args = intune.build_parser().parse_args([command, *options, "--group", "missing", "--apply"])
    with pytest.raises(SystemExit, match="no group named"):
        args.func(Graph(), args)
    assert not mutations


def test_intune_check_counts_every_managed_device_page() -> None:
    intune = _load(INTUNE)

    class Graph:
        def get(self, path: str, headers=None):
            if "managedDevices" in path:
                return {"value": [{"operatingSystem": "Windows", "complianceState": "compliant"}]}
            return {"value": []}

        def get_all(self, path: str, headers=None):
            if "managedDevices" in path:
                return [
                    {"operatingSystem": "Windows", "complianceState": "compliant"},
                    {"operatingSystem": "Windows", "complianceState": "compliant"},
                ]
            return []

    items = intune.check_items(Graph(), ["windows"], [])
    count = next(item["detail"] for item in items if item["item"] == "managed devices")
    assert count == "windows/compliant: 2"


def test_intune_devices_json_hides_users_by_default(capsys: pytest.CaptureFixture[str]) -> None:
    intune = _load(INTUNE)
    paths = []

    class Graph:
        def get_all(self, path: str, headers=None):
            paths.append(path)
            return [{"id": "device-1", "deviceName": "workstation", "userPrincipalName": "user@example.test"}]

    args = intune.build_parser().parse_args(["devices", "--json"])
    assert intune.cmd_devices(Graph(), args) == 0
    import json
    assert "userPrincipalName" not in paths[0]
    assert "userPrincipalName" not in json.loads(capsys.readouterr().out)[0]


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="requires no-follow file opens")
def test_entra_password_file_rejects_links_and_insecure_existing_file(tmp_path: Path) -> None:
    entra = _load(ENTRA)
    target = tmp_path / "existing"
    target.write_text("original\n", encoding="ascii")
    target.chmod(0o644)
    link = tmp_path / "passwords"
    link.symlink_to(target)

    with pytest.raises(SystemExit, match="password file"):
        entra._record_password(str(link), "user@example.test", "generated-value")
    assert target.read_text(encoding="ascii") == "original\n"

    with pytest.raises(SystemExit, match="password file"):
        entra._record_password(str(target), "user@example.test", "generated-value")
    assert target.read_text(encoding="ascii") == "original\n"

    target.chmod(0o600)
    entra._record_password(str(target), "user@example.test", "generated-value")
    assert target.read_text(encoding="ascii").endswith("user@example.test\tgenerated-value\n")


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


def test_okta_check_rejects_inactive_ldap_app(monkeypatch: pytest.MonkeyPatch) -> None:
    okta = _load(OKTA)
    monkeypatch.setattr(okta, "find_ldap_app", lambda *_args: {"status": "INACTIVE"})
    monkeypatch.setattr(okta, "schema_properties", lambda _client, kind:
                        {name: {"type": definition["type"]} for name, definition in
                         (okta.USER_ATTRIBUTES if kind == "user" else okta.GROUP_ATTRIBUTES).items()})
    args = okta.build_parser().parse_args(["check"])
    assert okta.cmd_check(type("Client", (), {"org_url": "https://example.okta.com"})(), args) == 1


def test_okta_check_requires_signon_coverage_for_requested_identities(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    okta = _load(OKTA)
    app = {"status": "ACTIVE", "_links": {"accessPolicy": {"href": "/api/v1/policies/policy1"}}}
    monkeypatch.setattr(okta, "find_ldap_app", lambda *_args: app)
    monkeypatch.setattr(okta, "find_user", lambda *_args: {"id": "bind1", "status": "ACTIVE"})
    monkeypatch.setattr(okta, "find_group", lambda *_args, **_kwargs:
                        {"id": "group1", "profile": {"gidNumber": 1720000}})
    monkeypatch.setattr(okta, "schema_properties", lambda _client, kind:
                        {name: {"type": definition["type"]} for name, definition in
                         (okta.USER_ATTRIBUTES if kind == "user" else okta.GROUP_ATTRIBUTES).items()})
    monkeypatch.setattr(okta, "check_bind_user", lambda *_args: None)
    monkeypatch.setattr(okta, "check_group", lambda *_args: None)

    class Client:
        org_url = "https://example.okta.com"
        def must(self, method, path):
            return {"id": "policy1", "name": "LDAP policy"}
        def get_all(self, path):
            return [{"name": "other user", "status": "ACTIVE", "priority": 0,
                     "conditions": {"people": {"users": {"include": ["other"]}}},
                     "actions": {"appSignOn": {"access": "ALLOW",
                                              "verificationMethod": {"factorMode": "1FA"}}}}]

    args = okta.build_parser().parse_args(
        ["check", "--bind-login", "bind@example.com", "--group", "linux-users"])
    assert okta.cmd_check(Client(), args) == 1
    output = capsys.readouterr().out
    assert "no active password-only ALLOW rule covers bind user" in output
    assert "no active password-only ALLOW rule covers group" in output

    bind_only = okta.build_parser().parse_args(["check", "--bind-login", "bind@example.com"])
    assert okta.cmd_check(Client(), bind_only) == 1


def test_okta_bind_role_rejects_privileged_account(monkeypatch: pytest.MonkeyPatch) -> None:
    okta = _load(OKTA)
    monkeypatch.setattr(okta, "find_user", lambda *_args: {"id": "bind1"})
    roles = [{"type": "SUPER_ADMIN", "label": "Super Administrator"}]
    permissions = list(okta.BIND_PERMISSIONS)

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
                return {"permissions": [{"label": label} for label in permissions]}
            if path.endswith("/roles") and method == "GET":
                return roles
            if method != "GET":
                raise AssertionError("privileged account must not be changed")
            raise AssertionError(path)

    client = Client()
    report = okta.Report(dry_run=False)
    okta.check_bind_user(client, report, "bind@example.com")
    assert report.problems > 0
    args = okta.build_parser().parse_args(["bind-role", "--bind-login", "bind@example.com", "--apply"])
    assert okta.cmd_bind_role(client, args) == 1

    roles[:] = [{"type": "CUSTOM", "role": "role1", "resource-set": "set1"}]
    permissions.append("okta.users.manage")
    report = okta.Report(dry_run=False)
    okta.check_bind_user(client, report, "bind@example.com")
    assert report.problems > 0


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


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="a Linux host script")
def test_okta_render_accepts_utf8_bind_password(tmp_path: Path) -> None:
    out = tmp_path / "sssd.conf"
    password = "P@ssw\u00f6rd"
    result = subprocess.run(
        ["bash", str(OKTA_INSTALL), "--org", "example", "--bind-login", "bind@example.com",
         "--allow-group", "linux-users", "--render-only", str(out)],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "OKTA_BIND_PASSWORD": password},
    )
    assert result.returncode == 0, result.stderr
    assert f"ldap_default_authtok = {password}" in out.read_text(encoding="utf-8")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="a Linux host script")
def test_okta_installer_requires_force_for_custom_authselect(tmp_path: Path) -> None:
    source = OKTA_INSTALL.read_text().rsplit('main "$@"', 1)[0]
    probe = """
authselect() { if [[ $1 == current ]]; then echo 'custom/cis with-faillock'; fi; }
systemctl() { return 0; }
act() { echo unexpected-profile-replacement; }
NO_PAM=0 FORCE=0 DRY_RUN=0
pam_step
"""
    script = tmp_path / "probe.sh"
    script.write_text(source + probe)
    result = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert "unexpected-profile-replacement" not in result.stdout


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="a Linux host script")
def test_okta_dry_run_discloses_sssd_restart(tmp_path: Path) -> None:
    conf = tmp_path / "installed.conf"
    rendered = tmp_path / "new.conf"
    conf.write_text("# Managed by DefenseClaw packaging/identity/okta\nold\n")
    rendered.write_text("# Managed by DefenseClaw packaging/identity/okta\nnew\n")
    source = OKTA_INSTALL.read_text().rsplit('main "$@"', 1)[0]
    script = tmp_path / "probe.sh"
    script.write_text(source + f'\nCONF={conf}\nDRY_RUN=1\ninstall_conf {rendered}\nrestart_sssd\n')
    result = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "would restart sssd" in result.stdout


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="a Linux host script")
def test_okta_installer_restarts_stale_running_sssd(tmp_path: Path) -> None:
    conf = tmp_path / "installed.conf"
    conf.write_text("new configuration")
    actions = tmp_path / "actions"
    source = OKTA_INSTALL.read_text().rsplit('main "$@"', 1)[0]
    probe = f"""
CONF={conf}
CONF_CHANGED=0
DRY_RUN=0
systemctl() {{
  case $1 in
    is-active|enable) return 0 ;;
    show) echo '2020-01-01 00:00:00 UTC' ;;
    restart) echo restart >> {actions} ;;
  esac
}}
sss_cache() {{ return 0; }}
wait_online() {{ return 0; }}
check_allow_group() {{ return 0; }}
restart_sssd
"""
    script = tmp_path / "probe.sh"
    script.write_text(source + probe)
    result = subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert actions.read_text().strip() == "restart"


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="a Linux host script")
def test_okta_template_filters_local_group_names(tmp_path: Path) -> None:
    out = tmp_path / "sssd.conf"
    result = subprocess.run(
        ["bash", str(OKTA_INSTALL), "--org", "example", "--bind-login", "bind@example.com",
         "--allow-group", "linux-users", "--render-only", str(out)],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "OKTA_BIND_PASSWORD": "test-password"},
    )
    assert result.returncode == 0, result.stderr
    line = next(line for line in out.read_text().splitlines() if line.startswith("filter_groups = "))
    filtered = {name.strip() for name in line.partition("=")[2].split(",")}
    local = {line.partition(":")[0] for line in Path("/etc/group").read_text().splitlines() if ":" in line}
    assert local <= filtered
    assert {"wheel", "sudo", "adm"} <= filtered


def test_entra_rejects_existing_non_security_group_for_sid_and_apply(tmp_path: Path) -> None:
    entra = _load(ENTRA)
    group = {"id": "00000001-0002-0003-0405-060708090a0b", "displayName": "team",
             "securityIdentifier": "S-1-12-1-1-196610-117835012-185207048", "securityEnabled": False}

    class Graph:
        def get_all(self, path: str):
            assert "/groups?" in path
            return [group]

        def request(self, *_args):
            raise AssertionError("a non-security group must never be mutated or accepted")

    graph = Graph()
    args = entra.build_parser().parse_args(["sids", "--group", "team"])
    with pytest.raises(entra.GraphError, match="security group"):
        entra.cmd_sids(graph, args)

    plan = tmp_path / "tenant.json"
    plan.write_text('{"domain":"example.test","groups":[{"name":"team"}]}', encoding="ascii")
    args = entra.build_parser().parse_args(["apply", "--config", str(plan), "--apply"])
    graph.get_all = lambda path: ([{"verifiedDomains": [{"name": "example.test"}]}]
                                  if "/organization?" in path else [group])
    with pytest.raises(entra.GraphError, match="security group"):
        entra.cmd_apply(graph, args)


def test_entra_apply_checks_verified_domain_before_mutation(tmp_path: Path) -> None:
    entra = _load(ENTRA)
    plan = tmp_path / "tenant.json"
    plan.write_text('{"domain":"other.test","groups":[{"name":"team"}]}', encoding="ascii")
    calls = []

    class Graph:
        def get_all(self, path: str):
            calls.append(("GET", path))
            if "/organization?" in path:
                return [{"verifiedDomains": [{"name": "example.test"}]}]
            return []

        def request(self, method: str, path: str, body):
            calls.append((method, path))
            raise AssertionError("group creation must not be attempted")

    args = entra.build_parser().parse_args(["apply", "--config", str(plan), "--apply"])
    with pytest.raises(SystemExit, match="verified domain"):
        entra.cmd_apply(Graph(), args)
    assert all(method == "GET" for method, _ in calls)


@pytest.mark.skipif(not sys.platform.startswith("linux") or not shutil.which("bash"), reason="a Linux host script")
def test_entra_domain_services_check_fails_for_missing_directory_identities() -> None:
    script = ENTRA.parent / "join-entra-domain-services.sh"
    result = subprocess.run(
        ["bash", str(script), "check", "--user", "dc-no-such-user-91402",
         "--group", "dc-no-such-group-91402"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 1, result.stdout


def test_entra_group_diagnostic_checks_membership_before_relogin_advice() -> None:
    script = (ENTRA.parent / "Get-DefenseClawEntraIdentity.ps1").read_text(encoding="ascii")
    branch = script.split("elseif ($listedIn.Count -gt 0)", 1)[1].split("\n    else {", 1)[0]
    assert re.search(r"member(ship)?.*sign out", branch, re.IGNORECASE)


def test_intune_assign_app_replaces_exclusion(capsys: pytest.CaptureFixture[str]) -> None:
    intune = _load(INTUNE)
    calls = []

    class Graph:
        def get_all(self, path: str, headers=None):
            if "/groups?" in path:
                return [{"id": "group-1"}]
            if "/assignments" in path:
                return [{
                    "id": "assignment-1", "intent": "required",
                    "target": {"@odata.type": "#microsoft.graph.exclusionGroupAssignmentTarget", "groupId": "group-1"},
                }]
            return [{"id": "app-1", "publishingState": "published"}]

        def request(self, method: str, path: str, body):
            calls.append((method, path, body))
            return {}

    args = intune.build_parser().parse_args([
        "assign-app", "--app", "app", "--group", "team", "--apply",
    ])
    assert intune.cmd_assign_app(Graph(), args) == 0
    assert len(calls) == 1
    assert calls[0][0] == "PATCH"
    assert calls[0][1].endswith("/assignments/assignment-1")
    assert calls[0][2]["target"]["@odata.type"] == intune.GROUP_TARGET


def test_intune_assign_app_updates_existing_intent() -> None:
    intune = _load(INTUNE)
    calls = []

    class Graph:
        def get_all(self, path: str, headers=None):
            if "/groups?" in path:
                return [{"id": "group-1"}]
            if "/assignments" in path:
                return [{
                    "id": "assignment-1", "intent": "required",
                    "target": {
                        "@odata.type": intune.GROUP_TARGET, "groupId": "group-1",
                        "deviceAndAppManagementAssignmentFilterId": "filter-1",
                    },
                    "settings": {"@odata.type": "#microsoft.graph.win32LobAppAssignmentSettings"},
                }]
            return [{"id": "app-1", "publishingState": "published"}]

        def request(self, method: str, path: str, body):
            calls.append((method, path, body))
            return {}

    args = intune.build_parser().parse_args([
        "assign-app", "--app", "app", "--group", "team", "--intent", "uninstall", "--apply",
    ])
    assert intune.cmd_assign_app(Graph(), args) == 0
    assert len(calls) == 1
    assert calls[0][0] == "PATCH"
    assert calls[0][2]["intent"] == "uninstall"
    assert calls[0][2]["target"]["deviceAndAppManagementAssignmentFilterId"] == "filter-1"
    assert "settings" in calls[0][2]


def test_intune_groups_reject_dynamic_group() -> None:
    intune = _load(INTUNE)

    class Graph:
        def get_all(self, path: str, headers=None):
            return [{"id": "group-1", "securityEnabled": True, "groupTypes": ["DynamicMembership"]}]

    args = intune.build_parser().parse_args(["groups", "--name", "team", "--apply"])
    with pytest.raises(SystemExit, match="static security group"):
        intune.cmd_groups(Graph(), args)


def test_intune_macos_script_defaults_to_daily_frequency() -> None:
    intune = _load(INTUNE)
    args = intune.build_parser().parse_args([
        "macos-script", "--name", "script", "--file", "script.sh",
    ])
    assert args.frequency == "P1D"


def test_intune_app_status_fetches_every_report_page(capsys: pytest.CaptureFixture[str]) -> None:
    intune = _load(INTUNE)
    calls = []

    class Graph:
        def get_all(self, path: str, headers=None):
            return [{"id": "app-1"}]

        def request(self, method: str, path: str, body):
            calls.append(body)
            skip = body.get("skip", 0)
            return {
                "Schema": [{"Column": "DeviceName"}],
                "Values": [[f"device-{skip}"]],
                "TotalRowCount": 2,
            }

    args = intune.build_parser().parse_args(["status", "--app", "app"])
    assert intune.cmd_status(Graph(), args) == 0
    assert [body.get("skip", 0) for body in calls] == [0, 1]
    output = capsys.readouterr().out
    assert "device-0" in output and "device-1" in output
