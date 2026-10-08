"""Okta LDAP gid regression."""
import importlib.util
import pathlib

KIT = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("okta_ldap_setup", KIT / "okta-ldap-setup.py")
okta = importlib.util.module_from_spec(spec)
spec.loader.exec_module(okta)


def test_duplicate_group_gid_is_reported_by_check_and_assign(monkeypatch):
    groups = [
        {"id": "strict", "type": "OKTA_GROUP", "profile": {"name": "strict", "gidNumber": 1720000}},
        {"id": "lenient", "type": "OKTA_GROUP", "profile": {"name": "lenient", "gidNumber": 1720000}},
    ]
    client = type("Client", (), {
        "get_all": lambda self, path, key=None: groups if path.startswith("/api/v1/groups?limit") else [],
        "must": lambda self, method, path: [group for group in groups if group["profile"]["name"] in path],
    })()
    report = okta.Report(False)
    okta.check_duplicate_group_gids(client, report)
    assert report.problems == 1
    monkeypatch.setattr(okta, "collect_users", lambda client, report, args: [])
    args = type("Args", (), {"apply": True, "user": ["someone"], "users_from": None,
                              "primary_group": "strict", "primary_gid": None,
                              "group": [("lenient", None)], "gid_base": 1720000})()
    assert okta.cmd_assign_posix(client, args) == 1


def test_group_members_need_complete_posix_profile(monkeypatch):
    monkeypatch.setattr(okta, "find_group", lambda client, name: {
        "id": "group", "profile": {"name": name, "gidNumber": 1720000}})
    client = type("Client", (), {"get_all": lambda self, path: [
        {"id": "user", "profile": {"login": "user@example.com", "uidNumber": 1710000}}]})()
    report = okta.Report(False)
    okta.check_group(client, report, "linux-users", 1720000)
    assert report.problems == 1
