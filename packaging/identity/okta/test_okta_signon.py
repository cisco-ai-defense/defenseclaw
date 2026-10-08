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
