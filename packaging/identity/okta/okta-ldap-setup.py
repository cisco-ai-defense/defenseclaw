#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Prepare an Okta org for Linux hosts that read it through the Okta LDAP Interface and SSSD.

Commands (each has its own --help):
  check          Read-only report: what is ready and what is missing.
  posix-schema   Add the POSIX profile attributes Linux needs (uidNumber, gidNumber, homeDirectory,
                 loginShell, unixUsername) to users and gidNumber to groups.
  assign-posix   Give users and groups their POSIX values and add the users to the primary group.
  bind-role      Give the SSSD bind user a custom admin role that can read users and groups.
  signon-policy  Give the LDAP Interface app a sign-on policy that lets the bind user and a group
                 sign in with a password only.

Credentials come from the environment, never from arguments:
  OKTA_ORG_URL    the org URL without a path, for example https://example.okta.com
  OKTA_API_TOKEN  an API token of a super administrator (asked on a terminal when unset)

The write commands change nothing unless you add --apply: without it they print the plan. Every command
can be run again: it changes only what differs. The LDAP Interface itself can only be turned on in the Admin
Console (Directory, Directory Integrations, Add LDAP Interface); Okta has no API for it. DefenseClaw
never calls Okta: this script is for the administrator who prepares the org.

Exit codes: 0 done or nothing to do, 1 a problem was found or a call failed, 2 bad arguments.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

APP_NAME = "ldap_interface"
READ_ONLY = [{"principal": "SELF", "action": "READ_ONLY"}]
USER_ATTRIBUTES: dict[str, dict[str, Any]] = {
    "uidNumber": {"title": "uidNumber", "type": "integer", "permissions": READ_ONLY},
    "gidNumber": {"title": "gidNumber", "type": "integer", "permissions": READ_ONLY},
    "homeDirectory": {"title": "homeDirectory", "type": "string", "permissions": READ_ONLY},
    "loginShell": {"title": "loginShell", "type": "string", "permissions": READ_ONLY},
    # SSSD's ldap_user_name. Okta logins are e-mail addresses; this is the Linux account name.
    "unixUsername": {
        "title": "unixUsername",
        "description": "POSIX login name (SSSD ldap_user_name)",
        "type": "string",
        "unique": "UNIQUE_VALIDATED",
        "minLength": 1,
        "maxLength": 32,
        "permissions": READ_ONLY,
    },
}
GROUP_ATTRIBUTES: dict[str, dict[str, Any]] = {
    "gidNumber": {"title": "gidNumber", "type": "integer", "permissions": READ_ONLY},
}
BIND_PERMISSIONS = ["okta.users.read", "okta.groups.read"]


class OktaError(Exception):
    """A failed Okta call, or a problem the operator has to fix."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the API token must not travel to another host."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class Okta:
    """Minimal Okta management API client (standard library only)."""

    def __init__(self, org_url: str, token: str) -> None:
        self.org_url = org_url
        self._token = token
        host = urllib.parse.urlsplit(org_url).hostname or ""
        label, _, domain = host.partition(".")
        self._hosts = {host, f"{label}-admin.{domain}"}
        self._opener = urllib.request.build_opener(_NoRedirect)

    def call(self, method: str, path: str, body: Any = None) -> tuple[int, Any, dict[str, str]]:
        url = path if path.startswith("https://") else self.org_url + path
        if urllib.parse.urlsplit(url).hostname not in self._hosts:
            raise OktaError("refusing to send the API token to " + str(urllib.parse.urlsplit(url).hostname))
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(5):
            request = urllib.request.Request(url, data=data, method=method)
            request.add_header("Authorization", "SSWS " + self._token)
            request.add_header("Accept", "application/json")
            request.add_header("Content-Type", "application/json")
            try:
                with self._opener.open(request, timeout=30) as response:
                    raw = response.read()
                    headers = dict(response.headers)
                    # Okta sends self and next as separate Link fields; dict() keeps only one.
                    links = response.headers.get_all("Link", [])
                    if links:
                        headers["Link"] = ", ".join(links)
                    return response.status, (json.loads(raw) if raw else None), headers
            except urllib.error.HTTPError as err:
                raw = err.read()
                headers = dict(err.headers)
                if err.code == 429 and attempt < 4:
                    lowered = {key.lower(): value for key, value in headers.items()}
                    reset = int(lowered.get("x-rate-limit-reset", "0") or 0)
                    time.sleep(min(max(reset - time.time(), 1), 60))
                    continue
                try:
                    parsed = json.loads(raw) if raw else None
                except ValueError:
                    parsed = {"errorSummary": raw.decode(errors="replace")[:200]}
                return err.code, parsed, headers
            except urllib.error.URLError as err:
                raise OktaError(f"cannot reach {self.org_url}: {err.reason}") from None
        raise OktaError("Okta kept answering 429 (rate limit); try again later")

    def must(self, method: str, path: str, body: Any = None) -> Any:
        status, parsed, _ = self.call(method, path, body)
        if status >= 300:
            raise OktaError(describe_error(method, path, status, parsed))
        return parsed

    def get_all(self, path: str, key: str | None = None) -> list[Any]:
        """GET a list and follow its next-page links."""
        items: list[Any] = []
        url = path
        while url:
            status, parsed, headers = self.call("GET", url)
            if status >= 300:
                raise OktaError(describe_error("GET", url, status, parsed))
            items.extend(parsed.get(key, []) if key and isinstance(parsed, dict) else (parsed or []))
            lowered = {k.lower(): v for k, v in headers.items()}
            url = next_link(lowered.get("link", ""))
            if not url and key and isinstance(parsed, dict):
                url = ((parsed.get("_links") or {}).get("next") or {}).get("href", "")
        return items


def describe_error(method: str, path: str, status: int, parsed: Any) -> str:
    detail = ""
    if isinstance(parsed, dict):
        detail = f" {parsed.get('errorCode', '')}: {parsed.get('errorSummary', '')}".rstrip(": ")
        causes = "; ".join(c.get("errorSummary", "") for c in parsed.get("errorCauses") or [] if isinstance(c, dict))
        if causes:
            detail += f" ({causes})"
    hint = ""
    if status == 401:
        hint = " The API token was refused: check OKTA_API_TOKEN and that it has not expired."
    elif status == 403:
        hint = " The token's administrator may not do this: use a super administrator's token."
    return f"{method} {path.split('?')[0]} answered {status}.{detail}{hint}"


def next_link(header: str) -> str:
    for part in header.split(","):
        match = re.match(r'\s*<([^>]+)>\s*;\s*rel="next"', part)
        if match:
            return match.group(1)
    return ""


class Report:
    """Prints one line per finding and counts the problems."""

    def __init__(self, dry_run: bool) -> None:
        self.dry_run = dry_run
        self.problems = 0

    def ok(self, text: str) -> None:
        print(f"  ok      {text}")

    def change(self, text: str) -> None:
        print(f"  {'would' if self.dry_run else 'done'}    {text}")

    def problem(self, text: str, hint: str = "") -> None:
        self.problems += 1
        print(f"  FAIL    {text}")
        if hint:
            print(f"          {hint}")

    def note(self, text: str) -> None:
        print(f"          {text}")

    def finish(self) -> int:
        if self.dry_run:
            print("\nPlan only: nothing was changed. Add --apply to make these changes.")
        return 1 if self.problems else 0


def find_user(client: Okta, login: str) -> dict[str, Any] | None:
    status, parsed, _ = client.call("GET", "/api/v1/users/" + urllib.parse.quote(login, safe=""))
    if status == 404:
        return None
    if status >= 300:
        raise OktaError(describe_error("GET", "/api/v1/users/<login>", status, parsed))
    return parsed


def find_group(client: Okta, name: str, attempts: int = 1) -> dict[str, Any] | None:
    """Find an Okta group by its exact name. Okta search is eventually consistent, so a group created
    a moment ago may need a few attempts."""
    query = urllib.parse.quote(f'profile.name eq "{name}"')
    for attempt in range(attempts):
        for group in client.must("GET", f"/api/v1/groups?search={query}") or []:
            if group.get("profile", {}).get("name") == name:
                return group
        if attempt + 1 < attempts:
            time.sleep(2)
    return None


def find_ldap_app(client: Okta) -> dict[str, Any] | None:
    for app in client.get_all("/api/v1/apps?q=ldap&limit=200"):
        if app.get("name") == APP_NAME:
            return app
    return None


def ldap_endpoints(org_url: str) -> tuple[str, str]:
    """The LDAP Interface host and base DN for an org URL such as https://example.okta.com."""
    host = urllib.parse.urlsplit(org_url).hostname or ""
    label, _, domain = host.partition(".")
    return f"{label}.ldap.{domain}", ",".join(["dc=" + label] + ["dc=" + part for part in domain.split(".")])


def schema_properties(client: Okta, kind: str) -> dict[str, Any]:
    return client.must("GET", f"/api/v1/meta/schemas/{kind}/default")["definitions"]["custom"]["properties"]


def named_int(value: str) -> tuple[str, int | None]:
    """Parse NAME or NAME=GID."""
    name, sep, number = value.partition("=")
    if not name or name != name.strip() or "=" in name or '"' in name or any(ord(ch) < 32 for ch in name):
        raise argparse.ArgumentTypeError(f"not a group name: {value!r}")
    if sep and not number.isdigit():
        raise argparse.ArgumentTypeError(f"the id after = must be a number: {value!r}")
    return name, (int(number) if sep else None)


def cmd_check(client: Okta, args: argparse.Namespace) -> int:
    report = Report(False)
    host, base = ldap_endpoints(client.org_url)
    print("LDAP Interface")
    app = find_ldap_app(client)
    if app is None:
        report.problem(
            "the LDAP Interface is not turned on in this org",
            "Turn it on in the Admin Console: Directory, Directory Integrations, Add LDAP Interface. "
            "Okta has no API for it.",
        )
    else:
        if app.get("status") == "ACTIVE":
            report.ok(f"app {APP_NAME} is ACTIVE: ldaps://{host}:636, base {base}")
        else:
            report.problem(f"app {APP_NAME} is {app.get('status') or 'unknown'}, not ACTIVE",
                           "Activate the LDAP Interface app in the Okta Admin Console.")
        if args.bind_login or args.group:
            check_signon_policy(client, report, app, args.bind_login, [name for name, _ in args.group or []])
        else:
            report.note("Pass --bind-login and --group to verify sign-on policy coverage.")

    print("Profile attributes")
    for kind, wanted in (("user", USER_ATTRIBUTES), ("group", GROUP_ATTRIBUTES)):
        have = schema_properties(client, kind)
        for name, definition in wanted.items():
            if name not in have:
                report.problem(f"{kind} attribute {name} is missing", "Run: okta-ldap-setup.py posix-schema")
            elif have[name].get("type") != definition["type"]:
                report.problem(f"{kind} attribute {name} has type {have[name].get('type')}, not {definition['type']}")
            elif not self_read_only(have[name]):
                report.problem(f"{kind} attribute {name} must be READ_ONLY for SELF",
                               "Change the attribute permission in Okta Profile Editor.")
            else:
                report.ok(f"{kind} attribute {name}")

    if args.bind_login:
        check_bind_user(client, report, args.bind_login)
    for name, gid in args.group or []:
        check_group(client, report, name, gid)
    check_duplicate_group_gids(client, report)
    uid_owners: dict[int, str] = {}
    for user in client.get_all("/api/v1/users?limit=200"):
        value = user.get("profile", {}).get("uidNumber")
        if value is None:
            continue
        uid = int(value)
        login = str(user.get("profile", {}).get("login", user.get("id")))
        if uid in uid_owners and uid_owners[uid] != login:
            report.problem(f"uidNumber {uid} is shared by {uid_owners[uid]} and {login}")
        uid_owners[uid] = login
    print("\nAll checks passed." if report.problems == 0 else f"\n{report.problems} problem(s) found.")
    return 1 if report.problems else 0



def password_only_method(method: dict[str, Any]) -> bool:
    constraints = method.get("constraints") or []
    return (
        method.get("type") == "ASSURANCE"
        and method.get("factorMode") == "1FA"
        and len(constraints) == 1
        and set(constraints[0]) == {"knowledge"}
        and constraints[0]["knowledge"].get("types") == ["password"]
        and constraints[0]["knowledge"].get("required") is not False
    )

def check_signon_policy(client: Okta, report: Report, app: dict[str, Any],
                        bind_login: str | None, group_names: list[str]) -> None:
    href = ((app.get("_links") or {}).get("accessPolicy") or {}).get("href", "")
    if not href:
        report.problem("the LDAP Interface app has no assigned sign-on policy")
        return
    policy = client.must("GET", "/api/v1/policies/" + href.rsplit("/", 1)[-1])
    print(f"sign-on policy: {policy.get('name')}")
    bind = find_user(client, bind_login) if bind_login else None
    groups = {name: find_group(client, name) for name in group_names}
    if bind_login and bind is None:
        report.problem(f"bind user {bind_login} does not exist; cannot verify its sign-on rule")
    for name, group in groups.items():
        if group is None:
            report.problem(f"group {name} does not exist; cannot verify its sign-on rule")

    bind_covered = False
    bind_decided = False
    group_covered = {name: False for name in groups}
    group_decided = {name: False for name in groups}
    rules = sorted(client.get_all(f"/api/v1/policies/{policy['id']}/rules"),
                   key=lambda rule: int(rule.get("priority", 2**31)))
    bind_groups: set[str] | None = None
    for rule in rules:
        action = (rule.get("actions") or {}).get("appSignOn") or {}
        method = action.get("verificationMethod") or {}
        factor = method.get("factorMode", "?")
        people = ((rule.get("conditions") or {}).get("people") or {})
        users = people.get("users") or {}
        scoped_groups = people.get("groups") or {}
        user_ids = set(users.get("include") or [])
        group_ids = set(scoped_groups.get("include") or [])
        excluded_users = set(users.get("exclude") or [])
        excluded_groups = set(scoped_groups.get("exclude") or [])
        scope = f"{len(user_ids)} user(s), {len(group_ids)} group(s)" if people else "everyone"
        report.note(f"rule '{rule.get('name')}' ({rule.get('status')}, priority {rule.get('priority')}): "
                    f"{factor}, {scope}")
        if rule.get("status") != "ACTIVE":
            continue
        password_allow = action.get("access") == "ALLOW" and password_only_method(method)
        # Okta evaluates active rules in priority order; users and groups on one rule are ANDed.
        if bind and not bind_decided and bind["id"] not in excluded_users:
            if bind_groups is None and (group_ids or excluded_groups):
                bind_groups = {item["id"] for item in client.get_all(
                    f"/api/v1/users/{bind['id']}/groups?limit=200")}
            if ((not user_ids or bind["id"] in user_ids)
                    and (not group_ids or bool(group_ids & (bind_groups or set())))
                    and not excluded_groups & (bind_groups or set())):
                bind_covered = password_allow
                bind_decided = True
        for name, group in groups.items():
            if group and not group_decided[name] and not user_ids and not excluded_users:
                if ((not group_ids or group["id"] in group_ids)
                        and group["id"] not in excluded_groups):
                    group_covered[name] = password_allow
                    group_decided[name] = True
    if bind and bind_covered:
        report.ok(f"password-only sign-on covers bind user {bind_login}")
    elif bind:
        report.problem(f"no active password-only ALLOW rule covers bind user {bind_login}",
                       "Run: okta-ldap-setup.py signon-policy --group GROUP --bind-login LOGIN")
    for name, group in groups.items():
        if group and group_covered[name]:
            report.ok(f"password-only sign-on covers group {name}")
        elif group:
            report.problem(f"no active password-only ALLOW rule covers group {name}",
                           "Run: okta-ldap-setup.py signon-policy --group GROUP --bind-login LOGIN")


def check_bind_user(client: Okta, report: Report, login: str) -> None:
    print(f"Bind user {login}")
    user = find_user(client, login)
    if user is None:
        report.problem("the user does not exist")
        return
    if user.get("status") != "ACTIVE":
        report.problem(f"bind user is {user.get('status') or 'unknown'}, not ACTIVE",
                       "Activate the bind user in Okta before using it for SSSD.")
    else:
        report.ok("exists, status ACTIVE")
    assigned = client.must("GET", f"/api/v1/users/{user['id']}/roles") or []
    if len(assigned) != 1 or assigned[0].get("type") != "CUSTOM":
        report.problem("bind user must have only one read-only custom role, with no privileged roles",
                       "Remove other roles in Okta, then run: okta-ldap-setup.py bind-role --bind-login LOGIN")
        return
    role_id = assigned[0].get("role")
    resource_set_id = assigned[0].get("resource-set")
    if not role_id or not resource_set_id:
        report.problem("bind user's custom role is missing its role or resource set")
        return
    granted = client.must("GET", f"/api/v1/iam/roles/{role_id}/permissions") or {}
    permissions = {entry.get("label") for entry in granted.get("permissions") or []}
    if permissions != set(BIND_PERMISSIONS):
        report.problem("bind user's role does not have exactly the user and group read permissions")
        return
    resources = client.get_all(f"/api/v1/iam/resource-sets/{resource_set_id}/resources", key="resources")
    covered = {((entry.get("_links") or {}).get("self") or {}).get("href") for entry in resources}
    required = {f"{client.org_url}/api/v1/{kind}" for kind in ("users", "groups")}
    if not required <= covered:
        report.problem("bind user's role does not cover all users and groups")
        return
    report.ok("only the read-only user and group role is assigned")



def check_duplicate_group_gids(client: Okta, report: Report) -> set[int]:
    """Report ambiguous POSIX group IDs and return the IDs already in use."""
    owners: dict[int, str] = {}
    for group in client.get_all("/api/v1/groups?limit=200"):
        value = group.get("profile", {}).get("gidNumber")
        if value is None:
            continue
        gid = int(value)
        name = str(group.get("profile", {}).get("name", group.get("id")))
        if gid in owners and owners[gid] != name:
            report.problem(f"gidNumber {gid} is shared by {owners[gid]} and {name}")
        else:
            owners[gid] = name
    return set(owners)

def check_group(client: Okta, report: Report, name: str, gid: int | None) -> None:
    print(f"Group {name}")
    group = find_group(client, name)
    if group is None:
        report.problem("the group does not exist")
        return
    have = group.get("profile", {}).get("gidNumber")
    if have is None:
        report.problem("no gidNumber: SSSD skips groups without one",
                       "Run: okta-ldap-setup.py assign-posix --group NAME")
    elif gid is not None and have != gid:
        report.problem(f"gidNumber is {have}, not {gid}")
    else:
        report.ok(f"gidNumber {have}")
    members = client.get_all(f"/api/v1/groups/{group['id']}/users?limit=200")
    incomplete = [(m.get("profile", {}).get("login"), [
        attr for attr in ("uidNumber", "gidNumber", "unixUsername")
        if m.get("profile", {}).get(attr) in (None, "")
    ]) for m in members]
    incomplete = [(login, missing) for login, missing in incomplete if missing]
    if incomplete:
        detail = ", ".join(f"{login} ({', '.join(missing)})" for login, missing in incomplete[:5])
        report.problem(f"{len(incomplete)} member(s) have incomplete POSIX attributes: {detail}")
    else:
        report.ok(f"{len(members)} member(s), all with POSIX identity attributes")


def self_read_only(attribute: dict[str, Any]) -> bool:
    permissions = attribute.get("permissions")
    return (isinstance(permissions, list)
            and [entry.get("action") for entry in permissions
                 if isinstance(entry, dict) and entry.get("principal") == "SELF"] == ["READ_ONLY"])


def ensure_attributes(client: Okta, report: Report, kind: str, wanted: dict[str, dict[str, Any]]) -> None:
    have = schema_properties(client, kind)
    missing = {name: definition for name, definition in wanted.items() if name not in have}
    for name, definition in wanted.items():
        if name in have and have[name].get("type") != definition["type"]:
            found = have[name].get("type")
            report.problem(f"{kind} attribute {name} exists with type {found}, not {definition['type']}")
        elif name in have and not self_read_only(have[name]):
            report.problem(f"{kind} attribute {name} must be READ_ONLY for SELF",
                           "Change the attribute permission in Okta Profile Editor.")
        elif name in have:
            report.ok(f"{kind} attribute {name} exists")
    if not missing:
        return
    report.change(f"add {kind} attribute(s): {', '.join(missing)}")
    if report.dry_run:
        return
    body = {"definitions": {"custom": {"id": "#custom", "type": "object", "properties": missing, "required": []}}}
    client.must("POST", f"/api/v1/meta/schemas/{kind}/default", body)
    for _ in range(5):
        if all(name in schema_properties(client, kind) for name in missing):
            return
        time.sleep(2)
    report.problem(f"{kind} attributes were added but are not visible yet; run check in a minute")


def cmd_posix_schema(client: Okta, args: argparse.Namespace) -> int:
    report = Report(dry_run=not args.apply)
    print("Profile attributes")
    ensure_attributes(client, report, "user", USER_ATTRIBUTES)
    ensure_attributes(client, report, "group", GROUP_ATTRIBUTES)
    return report.finish()


def ensure_group(client: Okta, report: Report, name: str, want_gid: int | None, used: set[int],
                 gid_base: int) -> tuple[dict[str, Any] | None, int | None]:
    """Make sure the Okta group exists and has a gidNumber.

    Returns the group and its gidNumber. The group is None when a dry run would create it (then
    the gidNumber is the planned one), or when it cannot carry a gidNumber."""
    group = find_group(client, name)
    if group is None:
        if want_gid is not None and want_gid in used:
            report.problem(f"gid {want_gid} for group {name} is already used by another group")
            return None, None
        report.change(f"create group {name}")
        if report.dry_run:
            return None, pick_gid(want_gid, used, gid_base)
        description = "Linux group (DefenseClaw Okta kit)"
        group = client.must("POST", "/api/v1/groups", {"profile": {"name": name, "description": description}})
        group = find_group(client, name, attempts=5) or group
    if group.get("type") not in (None, "OKTA_GROUP"):
        report.problem(f"group {name} is a {group.get('type')} group; only Okta groups can carry a gidNumber")
        return None, None
    profile = dict(group.get("profile", {}))
    have = profile.get("gidNumber")
    if have is not None:
        if want_gid is not None and int(have) != want_gid:
            report.problem(f"group {name} has gidNumber {have}, not {want_gid}; change it in Okta if that is wrong")
        else:
            report.ok(f"group {name} has gidNumber {have}")
        return group, int(have)
    if want_gid is not None and want_gid in used:
        report.problem(f"gid {want_gid} for group {name} is already used by another group")
        return group, None
    gid = pick_gid(want_gid, used, gid_base)
    report.change(f"set gidNumber {gid} on group {name}")
    if not report.dry_run:
        profile["gidNumber"] = gid
        client.must("PUT", f"/api/v1/groups/{group['id']}", {"profile": profile})
    return group, gid


def pick_gid(want: int | None, used: set[int], base: int) -> int:
    gid = want if want is not None else base
    while want is None and gid in used:
        gid += 1
    used.add(gid)
    return gid


def unix_name(login: str) -> str:
    name = re.sub(r"[^a-z0-9._-]", "-", login.split("@")[0].lower())
    if not re.match(r"[a-z_]", name):
        name = "u" + name
    return name[:32]


def cmd_assign_posix(client: Okta, args: argparse.Namespace) -> int:
    report = Report(dry_run=not args.apply)
    if not args.user and not args.users_from:
        raise OktaError("name the users: --user LOGIN (repeatable) or --users-from OKTA_GROUP")

    users = collect_users(client, report, args)
    directory_users = client.get_all("/api/v1/users?limit=200")
    uid_owners: dict[int, list[str]] = {}
    for other in directory_users:
        value = other.get("profile", {}).get("uidNumber")
        if value is not None:
            uid_owners.setdefault(int(value), []).append(other["id"])
    for user in users:
        value = user.get("profile", {}).get("uidNumber")
        if value is not None and len(uid_owners.get(int(value), [])) > 1:
            report.problem(
                f"{user.get('profile', {}).get('login', user['id'])}: uidNumber {value} is shared; "
                "clear uidNumber on one affected user in Okta Admin Console > Directory > People > Profile, "
                "then rerun assign-posix for that user"
            )
    if report.problems:
        return report.finish()
    names: dict[str, str] = {}
    for other in directory_users:
        existing = other.get("profile", {}).get("unixUsername")
        if existing:
            names.setdefault(existing, other["id"])
    for user in users:
        profile = user.get("profile", {})
        name = profile.get("unixUsername") or unix_name(profile.get("login", ""))
        if names.setdefault(name, user["id"]) != user["id"]:
            report.problem(f"account name {name} is taken by another user; choose a unique unixUsername")
    if report.problems:
        return report.finish()

    print("Groups")
    used_gids = check_duplicate_group_gids(client, report)
    if report.problems:
        return report.finish()
    primary, primary_gid = ensure_group(client, report, args.primary_group, args.primary_gid, used_gids, args.gid_base)
    for name, gid in args.group or []:
        ensure_group(client, report, name, gid, used_gids, args.gid_base)

    print("Users")
    used_uids: set[int] = set()
    if any(u.get("profile", {}).get("uidNumber") is None for u in users):
        for other in client.get_all("/api/v1/users?limit=200"):
            value = other.get("profile", {}).get("uidNumber")
            if value is not None:
                used_uids.add(int(value))
    next_uid = args.uid_base
    for user in users:
        profile = user.get("profile", {})
        login = profile.get("login", user["id"])
        name = profile.get("unixUsername") or unix_name(login)
        update: dict[str, Any] = {}
        if profile.get("unixUsername") is None:
            update["unixUsername"] = name
        if profile.get("uidNumber") is None:
            while next_uid in used_uids:
                next_uid += 1
            update["uidNumber"] = next_uid
            used_uids.add(next_uid)
        if profile.get("gidNumber") is None and primary_gid is not None:
            update["gidNumber"] = primary_gid
        elif profile.get("gidNumber") is not None and int(profile["gidNumber"]) != primary_gid:
            report.note(f"{login}: gidNumber {profile['gidNumber']} is not the primary group's; left alone")
        if profile.get("homeDirectory") is None:
            update["homeDirectory"] = args.home_template.replace("{name}", name)
        if profile.get("loginShell") is None:
            update["loginShell"] = args.shell
        if names.get(name) != user["id"]:
            continue
        if update and not report.dry_run:
            # Re-read before writing: another administrator may have taken the proposed uid.
            current = client.must("GET", f"/api/v1/users/{user['id']}")
            occupied = {
                int(other["profile"]["uidNumber"])
                for other in client.get_all("/api/v1/users?limit=200")
                if other["id"] != user["id"] and other.get("profile", {}).get("uidNumber") is not None
            }
            if "uidNumber" in update and update["uidNumber"] in occupied:
                report.problem(f"{login}: uidNumber {update['uidNumber']} was taken; rerun the preview")
                continue
            if current.get("profile", {}).get("unixUsername") not in (None, name):
                report.problem(f"{login}: unixUsername changed concurrently; rerun the preview")
                continue
            try:
                client.must("POST", f"/api/v1/users/{user['id']}", {"profile": update})
            except OktaError as exc:
                report.problem(f"{login}: POSIX update failed: {exc}")
                continue
            saved = client.must("GET", f"/api/v1/users/{user['id']}")
            if any(saved.get("profile", {}).get(key) != value for key, value in update.items()):
                report.problem(f"{login}: POSIX values did not match after writing")
                continue
            if "uidNumber" in update:
                duplicate = [
                    other for other in client.get_all("/api/v1/users?limit=200")
                    if other["id"] != user["id"]
                    and other.get("profile", {}).get("uidNumber") == update["uidNumber"]
                ]
                if duplicate:
                    report.problem(
                        f"{login}: uidNumber {update['uidNumber']} is now shared; serialize assign-posix runs"
                    )
                    continue
        if update:
            report.change(f"{login}: " + ", ".join(f"{key}={value}" for key, value in update.items()))
        else:
            report.ok(f"{login}: POSIX values already set")
        if primary is not None:
            members = client.get_all(f"/api/v1/groups/{primary['id']}/users?limit=200")
            if any(member["id"] == user["id"] for member in members):
                report.ok(f"{login}: already in {args.primary_group}")
            else:
                report.change(f"add {login} to {args.primary_group}")
                if not report.dry_run:
                    client.must("PUT", f"/api/v1/groups/{primary['id']}/users/{user['id']}")
        elif primary is None:
            report.note(f"{login}: would be added to {args.primary_group}")
    return report.finish()


def collect_users(client: Okta, report: Report, args: argparse.Namespace) -> list[dict[str, Any]]:
    users: list[dict[str, Any]] = []
    for login in args.user or []:
        found = find_user(client, login)
        if found is None:
            report.problem(f"user {login} does not exist")
        else:
            users.append(found)
    if args.users_from:
        source = find_group(client, args.users_from)
        if source is None:
            report.problem(f"group {args.users_from} does not exist")
        else:
            users.extend(client.get_all(f"/api/v1/groups/{source['id']}/users?limit=200"))
    seen: set[str] = set()
    unique = []
    for user in users:
        if user["id"] not in seen:
            seen.add(user["id"])
            unique.append(user)
    return unique


def cmd_bind_role(client: Okta, args: argparse.Namespace) -> int:
    report = Report(dry_run=not args.apply)
    print("Bind user role")
    user = find_user(client, args.bind_login)
    if user is None:
        raise OktaError(f"the bind user {args.bind_login} does not exist; create it in Okta first")
    assigned = client.must("GET", f"/api/v1/users/{user['id']}/roles") or []
    if any(entry.get("type") != "CUSTOM" for entry in assigned) or len(assigned) > 1:
        report.problem("bind user has another admin role; remove it in Okta before assigning the read-only role")
        return report.finish()

    roles = client.get_all("/api/v1/iam/roles", key="roles")
    role = next((r for r in roles if r.get("label") == args.role_label), None)
    if assigned and (role is None or assigned[0].get("role") != role["id"]):
        report.problem("bind user has a different admin role; remove it in Okta before assigning the read-only role")
        return report.finish()
    if role is None:
        report.change(f"create role '{args.role_label}' with {', '.join(BIND_PERMISSIONS)}")
        if not report.dry_run:
            role = client.must("POST", "/api/v1/iam/roles", {
                "label": args.role_label,
                "description": "Read users and groups for the LDAP Interface bind user (DefenseClaw Okta kit)",
                "permissions": BIND_PERMISSIONS,
            })
    else:
        granted = client.must("GET", f"/api/v1/iam/roles/{role['id']}/permissions") or {}
        labels = {p.get("label") for p in granted.get("permissions", [])}
        if labels == set(BIND_PERMISSIONS):
            report.ok(f"role '{args.role_label}' has only the read permissions")
        else:
            report.problem(f"role '{args.role_label}' has permissions {', '.join(sorted(labels))}; "
                           f"it must have only {', '.join(BIND_PERMISSIONS)}")
            role = None  # Never assign a role with unexpected permissions.
    if report.problems:
        report.note(f"{args.bind_login}: role not assigned")
        return report.finish()

    sets = client.get_all("/api/v1/iam/resource-sets", key="resource-sets")
    rset = next((s for s in sets if s.get("label") == args.resource_set_label), None)
    if assigned and (rset is None or assigned[0].get("resource-set") != rset["id"]):
        report.problem("bind user has a different resource set; remove that role in Okta first")
        return report.finish()
    if rset is None:
        report.change(f"create resource set '{args.resource_set_label}' (all users and all groups)")
        if not report.dry_run:
            rset = client.must("POST", "/api/v1/iam/resource-sets", {
                "label": args.resource_set_label,
                "description": "All users and groups (DefenseClaw Okta kit)",
                "resources": [f"{client.org_url}/api/v1/users", f"{client.org_url}/api/v1/groups"],
            })
    else:
        resources = client.get_all(f"/api/v1/iam/resource-sets/{rset['id']}/resources", key="resources")
        covered = {((entry.get("_links") or {}).get("self") or {}).get("href") for entry in resources}
        required = {f"{client.org_url}/api/v1/{kind}" for kind in ("users", "groups")}
        if required <= covered:
            report.ok(f"resource set '{args.resource_set_label}' covers all users and groups")
        else:
            report.problem(f"resource set '{args.resource_set_label}' does not cover all users and groups")
            rset = None  # Do not assign a resource set with incomplete coverage.

    if assigned and (len(assigned) != 1 or assigned[0].get("type") != "CUSTOM"
                     or not role or not rset or assigned[0].get("role") != role["id"]
                     or assigned[0].get("resource-set") != rset["id"]):
        report.problem("bind user has another admin role; remove it in Okta before assigning the read-only role")
        return report.finish()
    if role and rset and any(
        a.get("type") == "CUSTOM" and a.get("role") == role["id"] and a.get("resource-set") == rset["id"]
        for a in assigned
    ):
        report.ok(f"{args.bind_login} already has the role")
    elif report.problems:
        report.note(f"{args.bind_login}: role not assigned because the role or resource set was refused")
    elif report.dry_run:
        report.change(f"assign the role to {args.bind_login}")
    elif role and rset:
        client.must("POST", f"/api/v1/users/{user['id']}/roles",
                    {"type": "CUSTOM", "role": role["id"], "resource-set": rset["id"]})
        report.change(f"assign the role to {args.bind_login}")
    else:
        report.problem(f"{args.bind_login}: role was not assigned; rerun after the role and resource set exist")
    return report.finish()


def ensure_rule(client: Okta, report: Report, policy: dict[str, Any] | None, existing: list[Any], name: str,
                priority: int, people: dict[str, Any], purpose: str) -> None:
    """Create or update one password-only rule whose people condition is exactly `people`."""
    body = {
        "name": name,
        "type": "ACCESS_POLICY",
        "priority": priority,
        "conditions": {"people": people},
        "actions": {"appSignOn": {"access": "ALLOW", "verificationMethod": {
            "factorMode": "1FA", "type": "ASSURANCE", "reauthenticateIn": "PT2H",
            "constraints": [{"knowledge": {"types": ["password"]}}],
        }}},
    }
    rule = next((r for r in existing if r.get("name") == name), None)
    if rule is None:
        report.change(f"create rule '{name}': {purpose}")
        if not report.dry_run and policy is not None:
            client.must("POST", f"/api/v1/policies/{policy['id']}/rules", body)
        return
    have = (rule.get("conditions") or {}).get("people") or {}
    action = (rule.get("actions") or {}).get("appSignOn") or {}
    method = action.get("verificationMethod") or {}
    password_only = password_only_method(method)
    same = (
        all(
            set((have.get(kind) or {}).get("include") or []) == set((people.get(kind) or {}).get("include") or [])
            and not (have.get(kind) or {}).get("exclude")
            for kind in ("users", "groups")
        )
        and rule.get("status") == "ACTIVE"
        and action.get("access") == "ALLOW"
        and password_only
    )
    method = (rule.get("actions") or {}).get("appSignOn", {}).get("verificationMethod") or {}
    same = same and rule.get("status") == "ACTIVE" and method.get("factorMode") == "1FA"
    if same:
        report.ok(f"rule '{name}' already does this: {purpose}")
        return
    report.change(f"update rule '{name}': {purpose}")
    if not report.dry_run and policy is not None:
        path = f"/api/v1/policies/{policy['id']}/rules/{rule['id']}"
        client.must("PUT", path, body)
        if rule.get("status") != "ACTIVE":
            client.must("POST", path + "/lifecycle/activate")


def cmd_signon_policy(client: Okta, args: argparse.Namespace) -> int:
    report = Report(dry_run=not args.apply)
    print("LDAP Interface sign-on policy")
    app = find_ldap_app(client)
    if app is None:
        raise OktaError("the LDAP Interface is not turned on. Turn it on in the Admin Console "
                        "(Directory, Directory Integrations, Add LDAP Interface); Okta has no API for it")
    bind = find_user(client, args.bind_login)
    if bind is None:
        raise OktaError(f"the bind user {args.bind_login} does not exist")
    group = find_group(client, args.group)
    if group is None:
        raise OktaError(f"the group {args.group} does not exist")

    policy = next((p for p in client.get_all("/api/v1/policies?type=ACCESS_POLICY")
                   if p.get("name") == args.policy_name), None)
    if policy is None:
        report.change(f"create policy '{args.policy_name}'")
        if not report.dry_run:
            policy = client.must("POST", "/api/v1/policies", {
                "type": "ACCESS_POLICY",
                "name": args.policy_name,
                "description": "Password-only LDAP binds for Linux hosts (DefenseClaw Okta kit)",
            })
    else:
        report.ok(f"policy '{args.policy_name}' exists")

    # Okta ANDs the users and groups conditions of one rule, so the bind user and the group need a rule each.
    existing = client.get_all(f"/api/v1/policies/{policy['id']}/rules") if policy is not None else []
    ensure_rule(client, report, policy, existing, f"{args.rule_name} (bind user)", 0,
                {"users": {"include": [bind["id"]]}}, f"password only for {args.bind_login}")
    ensure_rule(client, report, policy, existing, f"{args.rule_name} (group)", 1,
                {"groups": {"include": [group["id"]]}}, f"password only for members of {args.group}")

    href = ((app.get("_links") or {}).get("accessPolicy") or {}).get("href", "")
    current = href.rsplit("/", 1)[-1] if href else ""
    if args.no_assign:
        report.note("not assigning the policy to the app (--no-assign)")
    elif policy is not None and current == policy["id"]:
        report.ok("the LDAP Interface app already uses this policy")
    else:
        report.change(f"assign policy '{args.policy_name}' to the LDAP Interface app (now: {current or 'none'})")
        if not report.dry_run and policy is not None:
            client.must("PUT", f"/api/v1/apps/{app['id']}/policies/{policy['id']}")
    report.note("The policy's catch-all rule still requires a second factor from everyone else.")
    return report.finish()


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--apply", action="store_true",
                        help="make the changes; without it the command only prints what it would do")

    parser = argparse.ArgumentParser(
        description="Prepare an Okta org for Linux hosts that read it through the Okta LDAP Interface and SSSD.",
        epilog="Credentials come from the environment, never from arguments: OKTA_ORG_URL "
               "(https://example.okta.com) and OKTA_API_TOKEN. Run COMMAND --help for options.",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    check = sub.add_parser("check", help="read-only report of what is ready and what is missing")
    check.add_argument("--bind-login", help="Okta login of the SSSD bind user")
    check.add_argument("--group", action="append", type=named_int, metavar="NAME[=GID]",
                       help="a Linux group to check (repeatable)")
    check.set_defaults(func=cmd_check)

    schema = sub.add_parser("posix-schema", parents=[common], help="add the POSIX profile attributes")
    schema.set_defaults(func=cmd_posix_schema)

    assign = sub.add_parser("assign-posix", parents=[common],
                            help="set uidNumber, gidNumber, unixUsername, homeDirectory and loginShell")
    assign.add_argument("--user", action="append", metavar="LOGIN",
                        help="an Okta login to give POSIX values (repeatable)")
    assign.add_argument("--users-from", metavar="OKTA_GROUP",
                        help="give POSIX values to every member of this Okta group (not the bind user)")
    assign.add_argument("--primary-group", default="linux-users", metavar="NAME",
                        help="the Okta group that is every user's primary Linux group and the SSH allow group "
                             "(default linux-users)")
    assign.add_argument("--primary-gid", type=int, metavar="GID", help="its gidNumber (default: the next free one)")
    assign.add_argument("--group", action="append", type=named_int, metavar="NAME[=GID]",
                        help="a team group that profile assignments will name; gets a gidNumber (repeatable)")
    assign.add_argument("--uid-base", type=int, default=1710000, metavar="N",
                        help="first uidNumber to hand out (default 1710000)")
    assign.add_argument("--gid-base", type=int, default=1720000, metavar="N",
                        help="first gidNumber to hand out (default 1720000)")
    assign.add_argument("--shell", default="/bin/bash", help="loginShell for users without one (default /bin/bash)")
    assign.add_argument("--home-template", default="/home/{name}", help="homeDirectory; {name} is the account name")
    assign.set_defaults(func=cmd_assign_posix)

    role = sub.add_parser("bind-role", parents=[common], help="give the bind user a read-only custom admin role")
    role.add_argument("--bind-login", required=True, help="Okta login of the SSSD bind user")
    role.add_argument("--role-label", default="defenseclaw-ldap-read", help="custom role name")
    role.add_argument("--resource-set-label", default="defenseclaw-ldap-all", help="resource set name")
    role.set_defaults(func=cmd_bind_role)

    policy = sub.add_parser("signon-policy", parents=[common],
                            help="password-only sign-on for the bind user and one group on the LDAP Interface")
    policy.add_argument("--bind-login", required=True, help="Okta login of the SSSD bind user")
    policy.add_argument("--group", required=True, metavar="OKTA_GROUP",
                        help="the Okta group whose members sign in to Linux hosts with their password")
    policy.add_argument("--policy-name", default="DefenseClaw LDAP Interface (password only)")
    policy.add_argument("--rule-name", default="ldap password only",
                        help="name prefix of the two rules (default: ldap password only)")
    policy.add_argument("--no-assign", action="store_true", help="create the policy but do not assign it to the app")
    policy.set_defaults(func=cmd_signon_policy)
    return parser


def read_credentials() -> tuple[str, str]:
    org_url = os.environ.get("OKTA_ORG_URL", "").strip().rstrip("/")
    if not org_url:
        raise OktaError("set OKTA_ORG_URL to the org URL, for example https://example.okta.com")
    parts = urllib.parse.urlsplit(org_url)
    if (parts.scheme != "https" or not parts.hostname or parts.path or parts.query or parts.username
            or "-admin." in parts.hostname):
        raise OktaError("OKTA_ORG_URL must be https://<org>.okta.com (not the -admin URL) with no path")
    token = os.environ.get("OKTA_API_TOKEN", "").strip()
    if not token:
        if not sys.stdin.isatty():
            raise OktaError("set OKTA_API_TOKEN (an API token of a super administrator)")
        token = getpass.getpass("Okta API token: ").strip()
    if not token:
        raise OktaError("no API token given")
    os.environ.pop("OKTA_API_TOKEN", None)
    return f"https://{parts.hostname}", token


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "assign-posix" and not args.user and not args.users_from:
        print("okta-ldap-setup.py: error: name --user LOGIN or --users-from OKTA_GROUP", file=sys.stderr)
        return 2
    try:
        org_url, token = read_credentials()
    except OktaError as err:
        print(f"okta-ldap-setup.py: error: {err}", file=sys.stderr)
        return 2
    try:
        return args.func(Okta(org_url, token), args)
    except OktaError as err:
        print(f"okta-ldap-setup.py: error: {err}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
