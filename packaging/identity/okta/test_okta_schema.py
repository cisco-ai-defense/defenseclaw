"""Okta LDAP schema permissions regression."""
import importlib.util
import pathlib

KIT = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("okta_ldap_setup", KIT / "okta-ldap-setup.py")
okta = importlib.util.module_from_spec(spec)
spec.loader.exec_module(okta)


def test_existing_gid_number_must_be_read_only_for_self(monkeypatch):
    def schema(client, kind):
        wanted = okta.USER_ATTRIBUTES if kind == "user" else okta.GROUP_ATTRIBUTES
        properties = {key: dict(value) for key, value in wanted.items()}
        properties["gidNumber"]["permissions"] = [{"principal": "SELF", "action": "READ_WRITE"}]
        return properties
    monkeypatch.setattr(okta, "schema_properties", schema)
    monkeypatch.setattr(okta, "find_ldap_app", lambda client: {"status": "ACTIVE"})
    monkeypatch.setattr(okta, "check_duplicate_group_gids", lambda client, report: None)
    client = type("Client", (), {
        "org_url": "https://example.okta.com",
        "get_all": lambda self, path: [],
    })()
    report = okta.Report(False)
    okta.ensure_attributes(client, report, "user", {"gidNumber": okta.USER_ATTRIBUTES["gidNumber"]})
    assert report.problems == 1
    args = type("Args", (), {"bind_login": None, "group": None})()
    assert okta.cmd_check(client, args) == 1

def test_check_rejects_nonunique_schema_and_duplicate_unix_names(monkeypatch, capsys):
    def schema(client, kind):
        wanted = okta.USER_ATTRIBUTES if kind == "user" else okta.GROUP_ATTRIBUTES
        properties = {key: dict(value) for key, value in wanted.items()}
        if kind == "user":
            properties["unixUsername"].pop("unique")
        return properties

    monkeypatch.setattr(okta, "schema_properties", schema)
    monkeypatch.setattr(okta, "find_ldap_app", lambda client: {"status": "ACTIVE"})
    monkeypatch.setattr(okta, "check_duplicate_group_gids", lambda client, report: None)
    users = [
        {"id": "one", "profile": {"login": "one@example.com", "uidNumber": 101, "unixUsername": "shared"}},
        {"id": "two", "profile": {"login": "two@example.com", "uidNumber": 102, "unixUsername": "shared"}},
    ]
    client = type("Client", (), {
        "org_url": "https://example.okta.com",
        "get_all": lambda self, path: users if path == "/api/v1/users?limit=200" else [],
    })()
    args = type("Args", (), {"bind_login": None, "group": None})()
    assert okta.cmd_check(client, args) == 1
    output = capsys.readouterr().out
    assert "unixUsername" in output and "UNIQUE_VALIDATED" in output
    assert "shared" in output and "one@example.com" in output and "two@example.com" in output
    report = okta.Report(dry_run=True)
    okta.ensure_attributes(client, report, "user", okta.USER_ATTRIBUTES)
    assert report.problems == 1
