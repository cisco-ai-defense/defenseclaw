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

def test_network_scoped_rule_is_not_unrestricted_password_coverage(monkeypatch):
    monkeypatch.setattr(okta, "find_user", lambda client, login: {"id": "bind"})
    password = {"type": "ASSURANCE", "factorMode": "1FA",
                "constraints": [{"knowledge": {"types": ["password"]}}]}
    rule = {"id": "rule", "name": "bind rule", "status": "ACTIVE", "priority": 0,
            "conditions": {"people": {"users": {"include": ["bind"]}},
                           "network": {"connection": "ZONE", "include": ["trusted"]}},
            "actions": {"appSignOn": {"access": "ALLOW", "verificationMethod": password}}}
    writes = []

    class Client:
        def must(self, method, path, body=None):
            if method == "PUT":
                writes.append(body)
            return {"id": "policy", "name": "policy"}

        def get_all(self, path):
            return [rule]

    client = Client()
    report = okta.Report(False)
    okta.check_signon_policy(client, report, {"_links": {"accessPolicy": {"href": "/policy"}}}, "bind", [])
    assert report.problems == 1
    report = okta.Report(False)
    okta.ensure_rule(client, report, {"id": "policy"}, [rule], "bind rule", 0,
                     {"users": {"include": ["bind"]}}, "password only")
    assert writes and writes[0]["conditions"] == {"people": {"users": {"include": ["bind"]}}}

    # Okta adds these no-op defaults when returning an unrestricted rule.
    rule["conditions"] = {
        "people": {"users": {"include": ["bind"], "exclude": []}},
        "network": {"connection": "ANYWHERE"},
        "riskScore": {"level": "ANY"},
        "userType": {"include": [], "exclude": []},
    }
    writes.clear()
    report = okta.Report(False)
    okta.check_signon_policy(client, report, {"_links": {"accessPolicy": {"href": "/policy"}}}, "bind", [])
    assert report.problems == 0
    okta.ensure_rule(client, report, {"id": "policy"}, [rule], "bind rule", 0,
                     {"users": {"include": ["bind"]}}, "password only")
    assert writes == []


def test_existing_signon_rules_are_moved_to_requested_priorities(monkeypatch):
    password = {"type": "ASSURANCE", "factorMode": "1FA",
                "constraints": [{"knowledge": {"types": ["password"]}}]}

    def rule(name, priority, people, access="ALLOW"):
        return {"id": name, "name": name, "status": "ACTIVE", "priority": priority,
                "conditions": {"people": people},
                "actions": {"appSignOn": {"access": access, "verificationMethod": password}}}

    rules = [
        rule("deny", 0, {"groups": {"include": ["linux"]}}, "DENY"),
        rule("ldap password only (group)", 1, {"groups": {"include": ["linux"]}}),
        rule("ldap password only (bind user)", 2, {"users": {"include": ["bind"]}}),
    ]
    writes = []

    class Client:
        def get_all(self, path):
            if path == "/api/v1/policies?type=ACCESS_POLICY":
                return [{"id": "policy", "name": "ldap policy"}]
            if path == "/api/v1/policies/policy/mappings":
                return []
            if path == "/api/v1/policies/policy/rules":
                return [item.copy() for item in rules]
            raise AssertionError(path)

        def must(self, method, path, body=None):
            assert method == "PUT" and path.startswith("/api/v1/policies/policy/rules/")
            moved = next(item for item in rules if item["id"] == path.rsplit("/", 1)[-1])
            old, new = moved["priority"], body["priority"]
            for item in rules:
                if item is not moved and new <= item["priority"] < old:
                    item["priority"] += 1
            moved["priority"] = new
            writes.append((moved["id"], new))

    monkeypatch.setattr(okta, "find_ldap_app", lambda client: {"id": "ldap"})
    monkeypatch.setattr(okta, "find_user", lambda client, login: {"id": "bind"})
    monkeypatch.setattr(okta, "find_group", lambda client, name: {"id": "linux"})
    args = type("Args", (), {"apply": True, "bind_login": "bind", "group": "linux",
                             "policy_name": "ldap policy", "rule_name": "ldap password only",
                             "no_assign": True})()
    assert okta.cmd_signon_policy(Client(), args) == 0
    assert writes == [("ldap password only (bind user)", 0),
                      ("ldap password only (group)", 1)]
    assert {item["name"]: item["priority"] for item in rules} == {
        "ldap password only (bind user)": 0,
        "ldap password only (group)": 1,
        "deny": 2,
    }
