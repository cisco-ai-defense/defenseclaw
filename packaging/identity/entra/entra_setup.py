#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Prepare Microsoft Entra ID for DefenseClaw identity-based guardrail profiles.

DefenseClaw never calls Microsoft Graph or Entra ID: it learns who a user is from
the operating system. This helper is for the administrator who prepares the
tenant. It creates the security groups and users that a profile assignment will
name, and it reads the Windows SID (S-1-12-1-...) of a group or a user, which is
the only name an Entra-joined Windows computer gives an Entra group.

Commands (run with --help after the command name for its options):

  check               read-only: tenant, verified domains, security defaults
  sids                read-only: object id and Windows SID of groups and users
  sid-from-object-id  offline: compute the Windows SID from an object id
  apply               create groups, users and group membership from a JSON file;
                      only previews unless you pass --apply

Credentials come from the environment, never from arguments:

  GRAPH_ACCESS_TOKEN      a Microsoft Graph access token, delegated or app-only. For example, the
                          output of: az account get-access-token --resource-type ms-graph \\
                          --query accessToken -o tsv
  or
  AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
                          an app registration with the application permissions below.

Permissions: check needs Organization.Read.All (and Policy.Read.All for security
defaults); sids needs Group.Read.All and User.Read.All; apply needs
Group.ReadWrite.All, User.ReadWrite.All, and Organization.Read.All.

Exit codes: 0 success, 1 a Graph call or the plan failed, 2 bad usage, input file or
credentials. Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import secrets
import stat
import string
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

# region graph client
# Keep this region identical in packaging/identity/entra/entra_setup.py and
# packaging/mdm/intune/tenant/intune_tenant.py: each script ships on its own, so
# the client is copied, and cli/tests/test_identity_kit.py checks the copies.

GRAPH = "https://graph.microsoft.com"
LOGIN = "https://login.microsoftonline.com"
TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*$")


class GraphError(Exception):
    """A Graph or sign-in call failed. The message never holds a token or a secret."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{status} {code}: {message}".strip())
        self.status = status
        self.code = code


def _error_parts(raw: bytes) -> tuple[str, str]:
    text = raw.decode("utf-8", "replace")
    try:
        err = json.loads(text)
    except ValueError:
        return "", text[:200]
    if not isinstance(err, dict):
        return "", text[:200]
    if isinstance(err.get("error"), dict):
        return str(err["error"].get("code", "")), str(err["error"].get("message", ""))[:300]
    description = str(err.get("error_description", ""))
    return str(err.get("error", "")), (description.splitlines() or [""])[0][:300]


class Graph:
    """A small Microsoft Graph client: one bearer token, retries, paging."""

    def __init__(self, token: str) -> None:
        self._token = token

    @classmethod
    def from_env(cls) -> Graph:
        token = os.environ.get("GRAPH_ACCESS_TOKEN", "").strip()
        if token:
            return cls(token)
        names = ("AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET")
        values = {name: os.environ.get(name, "").strip() for name in names}
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise SystemExit(
                "error: no Microsoft Graph credentials. Set GRAPH_ACCESS_TOKEN, or set AZURE_TENANT_ID, "
                "AZURE_CLIENT_ID and AZURE_CLIENT_SECRET (missing: " + ", ".join(missing) + ")."
            )
        tenant = values["AZURE_TENANT_ID"]
        if not TENANT_RE.match(tenant):
            raise SystemExit("error: AZURE_TENANT_ID must be a tenant id or a tenant domain name.")
        form = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": values["AZURE_CLIENT_ID"],
                "client_secret": values["AZURE_CLIENT_SECRET"],
                "scope": GRAPH + "/.default",
            }
        ).encode("ascii")
        request = urllib.request.Request(f"{LOGIN}/{tenant}/oauth2/v2.0/token", data=form, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            code, message = _error_parts(exc.read())
            raise GraphError(exc.code, code or "token_error", message) from None
        except urllib.error.URLError as exc:
            raise SystemExit(f"error: cannot reach {LOGIN}: {exc.reason}") from None
        return cls(str(payload["access_token"]))

    def request(self, method: str, path: str, body: object | None = None, headers: dict[str, str] | None = None):
        url = path if path.startswith("http") else GRAPH + path
        if not url.startswith(GRAPH + "/"):
            raise ValueError("refusing to send the access token to " + url.split("?")[0])
        send = {"Authorization": "Bearer " + self._token, "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            send["Content-Type"] = "application/json"
        send.update(headers or {})
        retry = (429, 500, 502, 503, 504) if method == "GET" else (429, 503)
        for attempt in range(5):
            request = urllib.request.Request(url, data=data, method=method, headers=send)
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    raw = response.read()
                return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as exc:
                raw = exc.read()
                if exc.code in retry and attempt < 4:
                    after = exc.headers.get("Retry-After", "")
                    time.sleep(min(int(after) if after.isdigit() else 2**attempt, 30))
                    continue
                code, message = _error_parts(raw)
                raise GraphError(exc.code, code, message) from None
            except urllib.error.URLError as exc:
                if attempt < 4:
                    time.sleep(2**attempt)
                    continue
                raise SystemExit(f"error: cannot reach {GRAPH}: {exc.reason}") from None
        raise AssertionError("unreachable")

    def get(self, path: str, headers: dict[str, str] | None = None):
        return self.request("GET", path, headers=headers)

    def get_all(self, path: str, headers: dict[str, str] | None = None) -> list:
        """Follow @odata.nextLink and return every item of a collection."""
        items: list = []
        next_path: str | None = path
        while next_path:
            page = self.get(next_path, headers)
            items.extend(page.get("value", []))
            next_path = page.get("@odata.nextLink")
        return items

    def wait_for_named_object(self, path: str) -> list:
        """Before creating by name, allow a previous run's Graph index to catch up."""
        for _ in range(21):
            found = self.get_all(path)
            if found:
                return found
            time.sleep(3)
        return self.get_all(path)

    def get_after_create(self, path: str):
        """Read an object just created: Graph answers 404 for a few seconds."""
        for _ in range(15):
            try:
                return self.get(path)
            except GraphError as exc:
                if exc.status != 404:
                    raise
                time.sleep(3)
        raise GraphError(404, "NotFound", "still not readable 45 seconds after it was created: " + path)

    def add_member(self, group_id: str, object_id: str, group_name: str = "") -> bool:
        """Add a directory object to a group; False when it already was a member.

        The members list lags a fresh add by seconds, so a rerun can repeat an
        add Graph already made. Graph answers 400 "added object references
        already exist", which is the result asked for.
        """
        ref = {"@odata.id": f"{GRAPH}/v1.0/directoryObjects/{object_id}"}
        for attempt in range(11):
            try:
                self.request("POST", f"/v1.0/groups/{group_id}/members/$ref", ref)
                return True
            except GraphError as exc:
                if exc.status == 400 and "already exist" in str(exc):
                    return False
                if exc.status != 404:
                    raise
                if attempt == 10:
                    raise GraphError(404, exc.code, f"adding member to group {group_name or group_id}: "
                                     "Graph still cannot find the new group after about a minute") from None
                time.sleep(min(2**attempt, 8))
        raise AssertionError("unreachable")


def odata_eq(field: str, value: str) -> str:
    """A URL-encoded OData $filter expression: field eq 'value'."""
    return urllib.parse.quote(f"{field} eq '" + value.replace("'", "''") + "'", safe="")


# endregion graph client

SID_PREFIX = "S-1-12-1-"
GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
NICKNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$")


def sid_from_object_id(object_id: str) -> str:
    """The SID Windows shows for an Entra user or group: four 32-bit words of the object id."""
    if not GUID_RE.match(object_id):
        raise ValueError(f"{object_id!r} is not an object id (a GUID)")
    words = struct.unpack("<4I", uuid.UUID(object_id).bytes_le)
    return SID_PREFIX + "-".join(str(word) for word in words)


def find_group(graph: Graph, name: str, *, wait: bool = False) -> dict | None:
    """The security group named name, or None. wait allows a previous run's new group to become visible."""
    select = "id,displayName,securityIdentifier,securityEnabled"
    query = f"/v1.0/groups?$filter={odata_eq('displayName', name)}&$select={select}"
    found = graph.get_all(query)
    if not found and wait:
        found = graph.wait_for_named_object(query)
    if len(found) > 1:
        raise GraphError(409, "AmbiguousName", f"{len(found)} groups are named {name!r}; use a unique name")
    if found and found[0].get("securityEnabled") is not True:
        raise GraphError(400, "NotSecurityGroup", f"group {name!r} is not a security group; use a security group")
    return found[0] if found else None


def find_user(graph: Graph, upn: str) -> dict | None:
    try:
        select = "id,userPrincipalName,displayName,securityIdentifier"
        return graph.get(f"/v1.0/users/{urllib.parse.quote(upn, safe='@')}?$select={select}")
    except GraphError as exc:
        if exc.status == 404:
            return None
        raise


def sid_of(obj: dict) -> tuple[str, str]:
    """Return (SID, note). Graph's securityIdentifier wins; the computed SID is the cross-check."""
    computed = sid_from_object_id(obj["id"])
    reported = obj.get("securityIdentifier") or ""
    if not reported:
        return computed, "computed from the object id (Graph returned no securityIdentifier)"
    if reported.upper() != computed.upper():
        return reported, "differs from the SID computed from the object id; use this Graph value"
    return reported, ""


def cmd_check(graph: Graph, args: argparse.Namespace) -> int:
    orgs = graph.get_all("/v1.0/organization?$select=id,displayName,verifiedDomains")
    report: dict = {"organizations": []}
    for org in orgs:
        report["organizations"].append(
            {
                "name": org.get("displayName"),
                "id": org.get("id"),
                "domains": [d.get("name") for d in org.get("verifiedDomains", [])],
                "default_domain": next(
                    (d.get("name") for d in org.get("verifiedDomains", []) if d.get("isDefault")), None
                ),
            }
        )
    try:
        policy = graph.get("/v1.0/policies/identitySecurityDefaultsEnforcementPolicy")
        report["security_defaults"] = "enabled" if policy.get("isEnabled") else "disabled"
    except GraphError as exc:
        report["security_defaults"] = f"not readable ({exc.status} {exc.code})"
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    for org in report["organizations"]:
        print(f"tenant:          {org['name']} ({org['id']})")
        print(f"default domain:  {org['default_domain']}")
        print(f"verified:        {', '.join(org['domains'])}")
    print(f"security defaults: {report['security_defaults']}")
    if report["security_defaults"] == "enabled":
        print("Enabled security defaults ask every user to register for MFA, so a password-only sign-in test fails.")
    return 0


def cmd_sids(graph: Graph, args: argparse.Namespace) -> int:
    if not args.group and not args.user:
        raise SystemExit("error: name at least one --group or --user")
    rows: list[dict] = []
    missing = 0
    for name in args.group:
        group = find_group(graph, name)
        if group is None:
            print(f"group {name}: not found", file=sys.stderr)
            missing += 1
            continue
        sid, note = sid_of(group)
        rows.append({"kind": "group", "name": group["displayName"], "object_id": group["id"], "sid": sid, "note": note})
    for upn in args.user:
        user = find_user(graph, upn)
        if user is None:
            print(f"user {upn}: not found", file=sys.stderr)
            missing += 1
            continue
        sid, note = sid_of(user)
        rows.append(
            {"kind": "user", "name": user["userPrincipalName"], "object_id": user["id"], "sid": sid, "note": note}
        )
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for row in rows:
            print(f"{row['kind']:5} {row['name']}")
            print(f"      object id  {row['object_id']}")
            print(f"      SID        {row['sid']}")
            if row["note"]:
                print(f"      note       {row['note']}")
        groups = [row for row in rows if row["kind"] == "group"]
        if groups:
            print()
            print("A Windows computer names an Entra group only by this SID, and only for a group that a built-in")
            print("local group (Users, for example) lists. In the standalone enterprise config:")
            print()
            print("  profile_assignments:")
            for row in groups:
                print("    - profile: <profile name>")
                print(f'      match: {{groups: ["{row["sid"]}"]}}  # {row["name"]}')
    return 1 if missing else 0


def cmd_sid_from_object_id(_graph: Graph | None, args: argparse.Namespace) -> int:
    for object_id in args.object_id:
        print(f"{object_id}  {sid_from_object_id(object_id)}")
    return 0


def _generate_password() -> str:
    alphabet = string.ascii_letters + string.digits
    while True:
        password = (
            "".join(secrets.choice(alphabet) for _ in range(20))
            + secrets.choice("!#%+=")
            + secrets.choice(string.digits)
        )
        if any(c.islower() for c in password) and any(c.isupper() for c in password):
            return password


def _load_plan(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            plan = json.load(handle)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from None
    if not isinstance(plan, dict):
        raise SystemExit(f"error: {path} must hold a JSON object")
    domain = plan.get("domain", "")
    if not DOMAIN_RE.match(str(domain)):
        raise SystemExit("error: 'domain' must be a tenant domain such as contoso.onmicrosoft.com")
    groups = plan.get("groups", [])
    users = plan.get("users", [])
    if not isinstance(groups, list) or not isinstance(users, list):
        raise SystemExit("error: 'groups' and 'users' must be lists")
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("name"), str) or not group["name"]:
            raise SystemExit("error: every entry of 'groups' needs a 'name'")
        _nickname(group["name"])
    seen_users: set[str] = set()
    for user in users:
        if not isinstance(user, dict) or not NICKNAME_RE.match(str(user.get("name", ""))):
            raise SystemExit("error: every entry of 'users' needs a 'name' of letters, digits, '-' and '_'")
        user["name"] = user["name"].lower()
        if user["name"] in seen_users:
            print(f"error: duplicate user name {user['name']!r} in the plan", file=sys.stderr)
            raise SystemExit(2)
        seen_users.add(user["name"])
        if not isinstance(user.get("groups", []), list):
            raise SystemExit("error: each user's groups must be a list")
        for group in user.get("groups", []):
            if not isinstance(group, str) or not group:
                raise SystemExit("error: each user group must be a name")
    return plan


def _nickname(name: str) -> str:
    nickname = re.sub(r"[^A-Za-z0-9_-]", "", name)
    if not nickname:
        raise SystemExit(f"error: group name {name!r} has no letters or digits for a mail nickname")
    return nickname[:64]


def _open_password_file(path: str) -> int:
    """Open the password file for appending, only as a private regular file owned by this process."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise SystemExit(f"error: cannot open password file securely: {exc.strerror}") from None
    try:
        info = os.fstat(descriptor)
        owner_ok = not hasattr(os, "geteuid") or info.st_uid == os.geteuid()
        if not stat.S_ISREG(info.st_mode) or not owner_ok or info.st_nlink != 1 or info.st_mode & 0o077:
            raise SystemExit("error: password file must be a private regular file owned by the current user")
        if not hasattr(os, "O_NOFOLLOW"):
            path_info = os.lstat(path)
            if stat.S_ISLNK(path_info.st_mode) or (path_info.st_dev, path_info.st_ino) != (
                info.st_dev, info.st_ino
            ):
                raise SystemExit("error: password file must not be a symlink")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _record_password(path: str, upn: str, password: str) -> None:
    """Append a newly created user's password to the private password file."""
    descriptor = _open_password_file(path)
    try:
        handle = os.fdopen(descriptor, "a", encoding="ascii")
    except BaseException:
        os.close(descriptor)
        raise
    with handle:
        handle.write(f"{upn}\t{password}\n")


def cmd_apply(graph: Graph, args: argparse.Namespace) -> int:
    plan = _load_plan(args.config)
    apply = args.apply
    if apply and plan.get("users"):
        if not args.password_file:
            raise SystemExit("error: --password-file is required before creating users; passwords are never printed")
        # Check the file before any Graph write: the password is recorded
        # only after Graph creates the user.
        os.close(_open_password_file(args.password_file))
    orgs = graph.get_all("/v1.0/organization?$select=id,verifiedDomains")
    domain = plan["domain"].casefold()
    if not any(
        str(item.get("name", "")).casefold() == domain
        for org in orgs for item in org.get("verifiedDomains", [])
    ):
        raise SystemExit(f"error: {plan['domain']!r} is not a verified domain of the authenticated tenant")
    tag = "" if apply else "[plan] "
    usage = plan.get("usage_location", "US")
    force_change = bool(plan.get("force_password_change", True))
    created_groups: dict[str, dict | None] = {}
    planned_groups = {spec["name"] for spec in plan.get("groups", [])}
    for spec in plan.get("users", []):
        for name in spec.get("groups", []):
            if name not in planned_groups and find_group(graph, name) is None:
                raise SystemExit(f"error: user {spec['name']} names missing group {name!r}")

    for spec in plan.get("groups", []):
        name = spec["name"]
        group = find_group(graph, name, wait=apply)
        if group is not None:
            print(f"{tag}group {name}: exists")
        elif not apply:
            print(f"{tag}group {name}: would create")
        else:
            body = {
                "displayName": name,
                "description": spec.get("description", "DefenseClaw guardrail profile group"),
                "mailEnabled": False,
                "mailNickname": _nickname(name),
                "securityEnabled": True,
            }
            made = graph.request("POST", "/v1.0/groups", body)
            group = graph.get_after_create(f"/v1.0/groups/{made['id']}?$select=id,displayName,securityIdentifier")
            print(f"group {name}: created")
        created_groups[name] = group

    for spec in plan.get("users", []):
        upn = f"{spec['name']}@{plan['domain']}"
        user = find_user(graph, upn)
        if user is not None:
            print(f"{tag}user {upn}: exists (left unchanged)")
        elif not apply:
            print(f"{tag}user {upn}: would create; the generated password would go to --password-file")
        else:
            password = _generate_password()
            body = {
                "accountEnabled": True,
                "displayName": spec.get("display_name", spec["name"]),
                "mailNickname": spec["name"],
                "userPrincipalName": upn,
                "usageLocation": usage,
                "passwordProfile": {"forceChangePasswordNextSignIn": force_change, "password": password},
            }
            try:
                made = graph.request("POST", "/v1.0/users", body)
            except GraphError as exc:
                if exc.status != 400 or "already exist" not in str(exc).lower():
                    raise
                user = find_user(graph, upn)
                if user is None:
                    raise GraphError(
                        409, "ExistingUserNotVisible", f"{upn} exists but Graph cannot read it yet"
                    ) from None
                print(f"user {upn}: exists (left unchanged; no password recorded)")
            else:
                _record_password(args.password_file, upn, password)
                user = graph.get_after_create(
                    f"/v1.0/users/{made['id']}?$select=id,userPrincipalName,securityIdentifier"
                )
                print(f"user {upn}: created (password in {args.password_file})")

        for group_name in spec.get("groups", []):
            group = created_groups.get(group_name)
            if group_name not in created_groups:
                group = find_group(graph, group_name)
                if group is None:
                    raise SystemExit(
                        f"error: user {upn} names group {group_name!r}, which is not in the tenant or the file"
                    )
                created_groups[group_name] = group
            if group is None or user is None:
                print(f"{tag}add {upn} to {group_name}: would add")
                continue
            members = {m["id"] for m in graph.get_all(f"/v1.0/groups/{group['id']}/members?$select=id")}
            if user["id"] in members:
                print(f"{tag}{upn} is in {group_name}")
            elif not apply:
                print(f"{tag}add {upn} to {group_name}: would add")
            elif graph.add_member(group["id"], user["id"], group_name):
                print(f"added {upn} to {group_name}")
            else:
                print(f"{upn} is in {group_name}")

    if not apply:
        print("Nothing was changed. Run again with --apply to make these changes.")
    else:
        print("Done. Read the group SIDs with: entra_setup.py sids --group <name>")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="entra_setup.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="read-only: tenant, verified domains, security defaults")
    check.add_argument("--json", action="store_true", help="print JSON")
    check.set_defaults(func=cmd_check, needs_graph=True)

    sids = sub.add_parser("sids", help="read-only: object id and Windows SID of groups and users")
    sids.add_argument("--group", action="append", default=[], metavar="NAME", help="group display name (repeatable)")
    sids.add_argument("--user", action="append", default=[], metavar="UPN", help="user principal name (repeatable)")
    sids.add_argument("--json", action="store_true", help="print JSON")
    sids.set_defaults(func=cmd_sids, needs_graph=True)

    offline = sub.add_parser("sid-from-object-id", help="offline: compute the Windows SID from an object id")
    offline.add_argument("object_id", nargs="+", metavar="OBJECT_ID")
    offline.set_defaults(func=cmd_sid_from_object_id, needs_graph=False)

    apply = sub.add_parser(
        "apply",
        help="create groups, users and membership from a JSON file (preview unless --apply)",
        description="Create the security groups and users in a JSON file and put users in groups. "
        "Objects that exist are left unchanged, so it is safe to run again. "
        "Without --apply it only reads the tenant and prints what it would do.",
    )
    apply.add_argument("--config", required=True, metavar="FILE", help="JSON file; see tenant.example.json")
    apply.add_argument("--apply", action="store_true", help="make the changes (the default is a preview)")
    apply.add_argument("--dry-run", action="store_true", help="preview only (the default; accepted for clarity)")
    apply.add_argument(
        "--password-file", metavar="FILE", help="created with mode 0600; receives 'upn<TAB>password' lines"
    )
    apply.set_defaults(func=cmd_apply, needs_graph=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "apply", False) and getattr(args, "dry_run", False):
        print("error: --apply and --dry-run cannot be used together", file=sys.stderr)
        return 2
    try:
        graph = Graph.from_env() if args.needs_graph else None
        return args.func(graph, args)
    except GraphError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, http.client.HTTPException) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    except SystemExit as exc:
        if isinstance(exc.code, str):
            print(exc.code, file=sys.stderr)
            return 2
        raise


if __name__ == "__main__":
    sys.exit(main())
