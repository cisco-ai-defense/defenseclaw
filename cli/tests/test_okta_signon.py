# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Okta LDAP signon regression."""
import importlib.util
import pathlib

KIT = pathlib.Path(__file__).resolve().parents[2] / "packaging" / "identity" / "okta"
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

def _group_signon_report(monkeypatch, rules, members, calls=None):
    """Check group engineering (G1) against rules; members maps a group id to its user ids."""
    monkeypatch.setattr(okta, "find_group", lambda client, name: {"id": "G1"})

    class Client:
        def must(self, method, path, body=None):
            return {"id": "policy", "name": "policy"}

        def get_all(self, path):
            if calls is not None:
                calls.append(path)
            parts = path.split("?")[0].split("/")
            if path.startswith("/api/v1/users/"):
                return [{"id": gid} for gid, users in members.items() if parts[4] in users]
            if path.startswith("/api/v1/groups/"):
                return [{"id": uid} for uid in members.get(parts[4], [])]
            return rules

    report = okta.Report(False)
    okta.check_signon_policy(Client(), report, {"_links": {"accessPolicy": {"href": "/policy"}}}, None, ["engineering"])
    return report


PASSWORD = {"type": "ASSURANCE", "factorMode": "1FA", "constraints": [{"knowledge": {"types": ["password"]}}]}


def _rule(name, priority, people, access="ALLOW"):
    action = {"access": access}
    if access == "ALLOW":
        action["verificationMethod"] = PASSWORD
    return {"name": name, "status": "ACTIVE", "priority": priority,
            "conditions": {"people": people} if people is not None else {},
            "actions": {"appSignOn": action}}


def test_group_coverage_accounts_for_an_earlier_user_deny(monkeypatch):
    """A member's own deny is not hidden by the group's later allow."""
    rules = [_rule("deny U1", 1, {"users": {"include": ["U1"]}}, "DENY"),
             _rule("group allow", 2, {"groups": {"include": ["G1"]}})]
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1"]}).problems == 1
    # A denied user who is not a member leaves the group covered.
    assert _group_signon_report(monkeypatch, rules, {"G9": ["U1"]}).problems == 0


def test_group_coverage_reads_membership_for_many_named_users(monkeypatch, capsys):
    """A rule naming more than 50 users is checked against the group's members, not assumed."""
    named = [f"U{i}" for i in range(60)]
    rules = [_rule("deny many", 1, {"users": {"include": named}}, "DENY"),
             _rule("group allow", 2, {"groups": {"include": ["G1"]}})]
    calls: list[str] = []
    assert _group_signon_report(monkeypatch, rules, {"G1": ["A", "B"]}, calls).problems == 0
    assert not any(path.startswith("/api/v1/users/") for path in calls)
    assert "covers group engineering" in capsys.readouterr().out
    assert _group_signon_report(monkeypatch, rules, {"G1": ["A", "U42"]}).problems == 1
    assert "applies another sign-on to some members" in capsys.readouterr().out


def test_group_coverage_accounts_for_an_earlier_other_group_deny(monkeypatch, capsys):
    """A deny for another group decides for the members the two groups share."""
    rules = [_rule("deny contractors", 1, {"groups": {"include": ["G2"]}}, "DENY"),
             _rule("group allow", 2, {"groups": {"include": ["G1"]}})]
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"], "G2": ["U2"]}).problems == 1
    assert "applies another sign-on to members also in other group(s)" in capsys.readouterr().out
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1"], "G2": ["U2"]}).problems == 0
    # Users and groups on one rule are ANDed: only a named member of both is matched.
    rules[0]["conditions"]["people"]["users"] = {"include": ["U3"]}
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"], "G2": ["U2", "U3"]}).problems == 0
    rules[0]["conditions"]["people"]["users"] = {"include": ["U2"]}
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"], "G2": ["U2"]}).problems == 1
    # The shared member is excluded from the deny, or the earlier rule is the same password-only allow.
    rules[0]["conditions"]["people"]["users"] = {"exclude": ["U2"]}
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"], "G2": ["U2"]}).problems == 0
    rules[0] = _rule("allow contractors", 1, {"groups": {"include": ["G2"]}})
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"], "G2": ["U2"]}).problems == 0


def test_group_coverage_accounts_for_excluded_groups(monkeypatch, capsys):
    """An allow that excludes another group covers the group only in part when they share members."""
    rules = [_rule("group allow", 1, {"groups": {"include": ["G1"], "exclude": ["G2"]}})]
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"], "G2": ["U2"]}).problems == 1
    assert "leaves out members who are also in other group(s)" in capsys.readouterr().out
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1"], "G2": ["U3"]}).problems == 0
    rules[0]["conditions"]["people"]["groups"]["exclude"] = []
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1"], "G2": ["U1"]}).problems == 0


def test_group_coverage_accounts_for_excluded_members(monkeypatch, capsys):
    """An allow that excludes a member covers the group only in part; a non-member does not count."""
    rules = [_rule("group allow", 1, {"groups": {"include": ["G1"]}, "users": {"exclude": ["U1"]}})]
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"]}).problems == 1
    assert "leaves out some members" in capsys.readouterr().out
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U2"]}).problems == 0


def test_group_coverage_names_every_reason_before_a_later_allow_for_everyone(monkeypatch, capsys):
    """An excluded member, an excluded group, an earlier user deny and a later allow for everyone."""
    rules = [
        _rule("deny U1", 1, {"users": {"include": ["U1"]}}, "DENY"),
        _rule("group allow", 2, {"groups": {"include": ["G1"], "exclude": ["G3"]},
                                 "users": {"exclude": ["U2"]}}),
        _rule("everyone", 3, None),
    ]
    members = {"G1": ["U1", "U2", "U3", "U4"], "G3": ["U3"]}
    assert _group_signon_report(monkeypatch, rules, members).problems == 1
    output = capsys.readouterr().out
    assert "covers group engineering only in part:" in output
    for reason in ("rule 'deny U1' applies another sign-on to some members",
                   "rule 'group allow' leaves out some members",
                   "rule 'group allow' leaves out members who are also in other group(s)"):
        assert reason in output


def test_group_coverage_skips_members_an_earlier_rule_allowed(monkeypatch, capsys):
    """Okta stops at a member's first matching rule: a later deny or exclusion never reaches them."""
    rules = [_rule("allow U1", 1, {"users": {"include": ["U1"]}}),
             _rule("deny contractors", 2, {"groups": {"include": ["G2"]}}, "DENY"),
             _rule("group allow", 3, {"groups": {"include": ["G1"]}})]
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"], "G2": ["U1"]}).problems == 0
    assert "covers group engineering" in capsys.readouterr().out
    # A member the earlier allow does not name still reaches the deny.
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"], "G2": ["U1", "U2"]}).problems == 1
    assert "rule 'deny contractors' applies another sign-on to members also in other group(s)" in capsys.readouterr().out
    # The covering rule's exclusions leave out no one an earlier rule allowed.
    rules = [_rule("allow U1", 1, {"users": {"include": ["U1"]}}),
             _rule("allow contractors", 2, {"groups": {"include": ["G2"]}}),
             _rule("group allow", 3, {"groups": {"include": ["G1"], "exclude": ["G2"]},
                                      "users": {"exclude": ["U1"]}})]
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2", "U3"], "G2": ["U3"]}).problems == 0
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2", "U3"], "G2": ["U2", "U3"]}).problems == 0
    rules[1]["actions"]["appSignOn"] = {"access": "DENY"}
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2", "U3"], "G2": ["U3"]}).problems == 1
    output = capsys.readouterr().out
    assert "rule 'deny" not in output and "rule 'allow contractors' applies another sign-on" in output
    assert "leaves out" not in output


def test_group_wide_deny_does_not_override_members_allowed_first(monkeypatch, capsys):
    """Every member already settled by an allow keeps its first Okta decision."""
    rules = [
        _rule("allow U1", 1, {"users": {"include": ["U1"]}}),
        _rule("allow U2", 2, {"users": {"include": ["U2"]}}),
        _rule("deny engineering", 3, {"groups": {"include": ["G1"]}}, "DENY"),
    ]
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"]}).problems == 0
    assert "password-only sign-on covers group engineering" in capsys.readouterr().out
    # An unsettled member still reaches the later deny.
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2", "U3"]}).problems == 1
    assert "no active password-only ALLOW rule covers group engineering" in capsys.readouterr().out


def test_group_coverage_names_a_member_once_for_its_first_deny(monkeypatch, capsys):
    """A member an earlier deny decided for is not counted again by a later rule."""
    rules = [_rule("deny U1", 1, {"users": {"include": ["U1"]}}, "DENY"),
             _rule("deny contractors", 2, {"groups": {"include": ["G2"]}}, "DENY"),
             _rule("group allow", 3, {"groups": {"include": ["G1"]}})]
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"], "G2": ["U1"]}).problems == 1
    output = capsys.readouterr().out
    assert "rule 'deny U1' applies another sign-on to some members" in output
    assert "deny contractors" not in output.split("only in part:")[1]


def test_group_coverage_conditional_password_allow_for_members_is_not_partial(monkeypatch):
    """A password-only allow limited to a network zone gives no member another sign-on."""
    zoned = _rule("allow U1 in office", 1, {"users": {"include": ["U1"]}})
    zoned["conditions"]["network"] = {"connection": "ZONE", "include": ["office"]}
    rules = [zoned, _rule("group allow", 2, {"groups": {"include": ["G1"]}})]
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"]}).problems == 0
    # Outside the zone the member still reaches a later deny.
    rules.insert(1, _rule("deny contractors", 2, {"groups": {"include": ["G2"]}}, "DENY"))
    rules[2]["priority"] = 3
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"], "G2": ["U1"]}).problems == 1

def test_group_coverage_follows_members_a_group_deny_leaves_out(monkeypatch, capsys):
    """A deny for the group decides only for the members it does not exclude."""
    rules = [_rule("deny engineering", 1, {"groups": {"include": ["G1"]}, "users": {"exclude": ["U1", "U2"]}}, "DENY"),
             _rule("group allow", 2, {"groups": {"include": ["G1"]}})]
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"]}).problems == 0
    assert "password-only sign-on covers group engineering" in capsys.readouterr().out
    # Every member left out through another group, or a deny for everyone.
    rules[0]["conditions"]["people"] = {"groups": {"include": ["G1"], "exclude": ["G2"]}}
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"], "G2": ["U1", "U2"]}).problems == 0
    rules[0]["conditions"]["people"] = {"users": {"exclude": ["U1", "U2"]}}
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"]}).problems == 0
    capsys.readouterr()
    # A member the deny still matches.
    rules[0]["conditions"]["people"] = {"groups": {"include": ["G1"], "exclude": ["G2"]}}
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"], "G2": ["U1"]}).problems == 1
    assert "rule 'deny engineering' applies another sign-on to some members" in capsys.readouterr().out
    # A deny that leaves out no member decides for the group.
    assert _group_signon_report(monkeypatch, rules, {"G1": ["U1", "U2"], "G2": ["U3"]}).problems == 1
    assert "no active password-only ALLOW rule covers group engineering" in capsys.readouterr().out


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
