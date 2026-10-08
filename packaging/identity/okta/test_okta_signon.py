"""Okta LDAP signon regression."""
import importlib.util
import pathlib

KIT = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("okta_ldap_setup", KIT / "okta-ldap-setup.py")
okta = importlib.util.module_from_spec(spec)
spec.loader.exec_module(okta)


def test_signon_requires_password_constraint(monkeypatch):
    monkeypatch.setattr(okta, "find_user", lambda client, login: {"id": "bind"})
    client = type("Client", (), {
        "must": lambda self, method, path: {"id": "policy", "name": "policy"},
        "get_all": lambda self, path: [{
            "name": "possession only", "status": "ACTIVE", "priority": 1,
            "actions": {"appSignOn": {"access": "ALLOW", "verificationMethod": {
                "type": "ASSURANCE", "factorMode": "1FA",
                "constraints": [{"possession": {"types": ["email"]}}],
            }}},
            "conditions": {"people": {"users": {"include": ["bind"]}}},
        }],
    })()
    report = okta.Report(False)
    okta.check_signon_policy(client, report, {"_links": {"accessPolicy": {"href": "/policy"}}}, "bind", [])
    assert report.problems == 1


def test_signon_uses_first_matching_rule(monkeypatch):
    monkeypatch.setattr(okta, "find_user", lambda client, login: {"id": "bind"})
    password = {"type": "ASSURANCE", "factorMode": "1FA",
                "constraints": [{"knowledge": {"types": ["password"]}}]}
    rules = [
        {"name": "deny", "status": "ACTIVE", "priority": 0,
         "conditions": {"people": {"users": {"include": ["bind"]}}},
         "actions": {"appSignOn": {"access": "DENY"}}},
        {"name": "allow", "status": "ACTIVE", "priority": 1,
         "conditions": {"people": {"users": {"include": ["bind"]}}},
         "actions": {"appSignOn": {"access": "ALLOW", "verificationMethod": password}}},
    ]
    client = type("Client", (), {
        "must": lambda self, method, path: {"id": "policy", "name": "policy"},
        "get_all": lambda self, path: rules,
    })()
    report = okta.Report(False)
    okta.check_signon_policy(client, report, {"_links": {"accessPolicy": {"href": "/policy"}}}, "bind", [])
    assert report.problems == 1


def test_signon_refuses_policy_assigned_to_another_app(monkeypatch):
    monkeypatch.setattr(okta, "find_ldap_app", lambda client: {"id": "ldap"})
    monkeypatch.setattr(okta, "find_user", lambda client, login: {"id": "bind"})
    monkeypatch.setattr(okta, "find_group", lambda client, name: {"id": "linux"})
    calls = []
    class Client:
        def get_all(self, path):
            if path == "/api/v1/policies?type=ACCESS_POLICY":
                return [{"id": "policy", "name": "shared"}]
            if path == "/api/v1/policies/policy/mappings":
                return [{"_links": {"application": {"href": "https://example.okta.com/api/v1/apps/other"}}}]
            return []
        def must(self, method, path, body=None):
            calls.append((method, path))
            return {}
    args = type("Args", (), {"apply": True, "bind_login": "bind", "group": "linux",
                             "policy_name": "shared", "rule_name": "ldap password only",
                             "no_assign": False})()
    assert okta.cmd_signon_policy(Client(), args) == 1
    assert calls == []
