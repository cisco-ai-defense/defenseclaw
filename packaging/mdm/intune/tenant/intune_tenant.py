#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Prepare and watch a Microsoft Intune tenant for the DefenseClaw MDM kit.

The DefenseClaw packages are delivered by Intune exactly as the pages under
docs/enterprise/mdm describe. This helper covers the tenant side with Microsoft Graph:
check that the tenant is ready, create the device groups, assign the DefenseClaw Win32
app, upload the Remediations package or a macOS shell script, and report the install and
compliance state. It never talks to a device, and DefenseClaw never calls Graph.

Commands (add --help after a command for its options):

  check         read-only: licences, MDM authority, MDM user scope, Windows Hello default,
                Apple push certificate, groups, device counts
  devices       read-only: managed devices with their compliance state
  status        read-only: install state of the DefenseClaw app, run state of a Remediations package
  groups        create static security groups and add devices to them
  assign-app    assign an app you uploaded in the admin center to a group
  remove-assignment  remove an app assignment from a group
  remediation   create or update a Windows Remediations package from the kit's scripts, assign it
  macos-script  create or update a macOS shell script from a file, assign it

Every command that changes the tenant only previews unless you pass --apply.

Credentials come from the environment, never from arguments:

  GRAPH_ACCESS_TOKEN      a Microsoft Graph access token with the permissions below (delegated or
                          app-only)
  or
  AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
                          an app registration with the application permissions below

Permissions (application or delegated): Organization.Read.All, Group.ReadWrite.All,
Device.Read.All, DeviceManagementServiceConfig.Read.All, DeviceManagementManagedDevices.Read.All,
DeviceManagementApps.ReadWrite.All, DeviceManagementScripts.ReadWrite.All.

Not everything can be read or set with an app-only token. The automatic enrollment MDM user
scope, the Windows Hello for Business default and the Apple push certificate upload are
admin-center steps; check reports what it can read and says so for the rest.

Validation status: check, devices, groups, assign-app, remediation, macos-script and status
were run against a test tenant with throwaway objects (see README.md). Delivery of the
DefenseClaw packages through Intune is tracked separately in the MDM certification round.

Exit codes: 0 success, 1 a check failed or a Graph call failed, 2 bad usage, input or credentials.
Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

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

    def wait_for_named_object(self, path: str, headers: dict[str, str] | None = None) -> list:
        """Before creating by name, allow a previous run's Graph index to catch up."""
        for _ in range(21):
            found = self.get_all(path, headers)
            if found:
                return found
            time.sleep(3)
        return self.get_all(path, headers)

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

BETA = "/beta"
V1 = "/v1.0"
PLATFORMS = ("windows", "macos", "linux")
HEALTH_SCRIPT_MAX_BYTES = 200 * 1024
SHELL_SCRIPT_MAX_BYTES = HEALTH_SCRIPT_MAX_BYTES
GROUP_NAME_MAX_CHARS = 256
GROUP_TARGET = "#microsoft.graph.groupAssignmentTarget"
STATUS_REPORT_ROWS = 1000

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"


# ---------------------------------------------------------------- helpers


def try_get(graph: Graph, path: str):
    """Return (data, None) or (None, 'status code: message') so a check can report instead of stop."""
    try:
        return graph.get(path), None
    except GraphError as exc:
        return None, str(exc)


def group_by_name(graph: Graph, name: str) -> dict:
    found = graph.get_all(f"{V1}/groups?$filter={odata_eq('displayName', name)}&$select=id,displayName,groupTypes")
    if not found:
        raise SystemExit(
            f"error: no group named {name!r}. Create it with: intune_tenant.py groups --name {name} --apply"
        )
    if len(found) > 1:
        raise SystemExit(f"error: {len(found)} groups are named {name!r}; use a unique name")
    return found[0]


def one_by_name(graph: Graph, path: str, name: str, what: str) -> dict:
    found = graph.get_all(f"{path}?$filter={odata_eq('displayName', name)}")
    if not found:
        raise SystemExit(f"error: no {what} named {name!r} in the tenant. Create it first (see README.md).")
    if len(found) > 1:
        raise SystemExit(f"error: {len(found)} {what}s are named {name!r}; rename all but one")
    return found[0]


def table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [max(len(str(x)) for x in [h] + [r[i] for r in rows]) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    lines.extend("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(r)).rstrip() for r in rows)
    return "\n".join(lines)


def read_script(path: str, limit: int) -> bytes:
    """Read a UTF-8 script to upload, rejecting byte-order marks."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}") from None
    if data.startswith(b"\xef\xbb\xbf"):
        raise SystemExit(f"error: {path} starts with a byte-order mark; save it as UTF-8 without one")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        raise SystemExit(f"error: {path} is not valid UTF-8") from None
    if len(data) > limit:
        raise SystemExit(f"error: {path} is {len(data)} bytes; the limit is {limit}")
    return data


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def kit_script(name: str) -> str:
    return str(Path(__file__).resolve().parents[1] / "windows" / name)


def plan_tag(apply: bool) -> str:
    return "" if apply else "[plan] "


# ---------------------------------------------------------------- check


def check_items(graph: Graph, platforms: list[str], groups: list[str]) -> list[dict]:
    items: list[dict] = []

    def add(status: str, item: str, detail: str) -> None:
        items.append({"status": status, "item": item, "detail": detail})

    orgs = graph.get_all(f"{V1}/organization?$select=id,displayName")
    if orgs:
        org = orgs[0]
        add(INFO, "tenant", str(org.get("displayName")))
        data, err = try_get(graph, f"{BETA}/organization/{org['id']}?$select=mobileDeviceManagementAuthority")
        if err:
            add(WARN, "MDM authority", f"cannot read: {err}")
        else:
            authority = str(data.get("mobileDeviceManagementAuthority"))
            add(PASS if authority.lower() == "intune" else FAIL, "MDM authority", authority)

    skus, err = try_get(graph, f"{V1}/subscribedSkus")
    if err:
        add(WARN, "licences", f"cannot read: {err}")
    else:
        enabled = [s for s in skus.get("value", []) if s.get("capabilityStatus") == "Enabled"]
        plans = {
            p.get("servicePlanName"): s
            for s in enabled for p in s.get("servicePlans", [])
            if p.get("provisioningStatus") == "Success"
        }
        names = ", ".join(
            f"{s['skuPartNumber']} ({s.get('consumedUnits', 0)}/{s.get('prepaidUnits', {}).get('enabled', 0)})"
            for s in enabled
        )
        add(INFO, "licences (used/total)", names or "none")
        intune = [p for p in plans if str(p).startswith("INTUNE_A")]
        add(
            PASS if intune else FAIL,
            "Intune licence",
            "found" if intune else "no enabled SKU has a provisioned Intune service plan",
        )
        entra = sorted(p for p in plans if str(p).startswith("AAD_PREMIUM"))
        add(
            PASS if entra else WARN,
            "Entra ID P1 or P2",
            ", ".join(entra) if entra else "none; Microsoft documents it for automatic MDM enrollment",
        )
        if "windows" in platforms:
            enterprise = "WIN10_PRO_ENT_SUB" in plans
            add(
                PASS if enterprise else WARN,
                "Windows Enterprise (Remediations)",
                "found" if enterprise else "none; Microsoft documents E3/E5 or VDA licences for Remediations",
            )

    if "windows" in platforms:
        data, err = try_get(graph, f"{BETA}/policies/mobileDeviceManagementPolicies")
        if err:
            add(
                WARN,
                "MDM user scope",
                "cannot be read with this token (" + err + "). Check Devices > Enrollment > Windows > "
                "Automatic Enrollment: MDM user scope must be Some or All.",
            )
        else:
            for policy in data.get("value", []):
                scope = str(policy.get("appliesTo"))
                add(
                    PASS if scope in ("all", "selected", "some") else FAIL,
                    f"MDM user scope ({policy.get('displayName')})",
                    scope,
                )

        data, err = try_get(graph, f"{BETA}/deviceManagement/deviceEnrollmentConfigurations")
        if err:
            add(WARN, "enrollment configurations", f"cannot read: {err}")
        else:
            hello = [c for c in data.get("value", []) if "WindowsHelloForBusiness" in str(c.get("@odata.type"))]
            for config in hello:
                state = str(config.get("state"))
                add(
                    INFO,
                    "Windows Hello for Business default",
                    state + (" (a new device asks for a PIN)" if state == "enabled" else ""),
                )
            add(INFO, "enrollment configurations", str(len(data.get("value", []))))

    if "macos" in platforms:
        data, err = try_get(graph, f"{BETA}/deviceManagement/applePushNotificationCertificate")
        if err or not data or not data.get("expirationDateTime"):
            add(FAIL, "Apple push certificate", err or "not uploaded; macOS enrollment needs it (admin center step)")
        else:
            left = (
                time.mktime(time.strptime(data["expirationDateTime"][:19], "%Y-%m-%dT%H:%M:%S")) - time.time()
            ) / 86400
            add(FAIL if left <= 0 else PASS if left > 30 else WARN, "Apple push certificate",
                f"expires in {int(left)} days")

    for name in groups:
        found = graph.get_all(f"{V1}/groups?$filter={odata_eq('displayName', name)}&$select=id,displayName")
        if len(found) != 1:
            add(FAIL, f"group {name}", "not found" if not found else f"{len(found)} groups share the name")
            continue
        members = graph.get_all(f"{V1}/groups/{found[0]['id']}/members?$select=id")
        add(PASS, f"group {name}", f"{len(members)} member(s)")

    try:
        devices = graph.get_all(f"{BETA}/deviceManagement/managedDevices?$select=operatingSystem,complianceState")
    except GraphError as exc:
        add(WARN, "managed devices", f"cannot read: {exc}")
    else:
        counts: dict[str, int] = {}
        for device in devices:
            key = f"{str(device.get('operatingSystem')).lower()}/{device.get('complianceState')}"
            counts[key] = counts.get(key, 0) + 1
        add(INFO, "managed devices", ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())) or "none")
    return items


def cmd_check(graph: Graph, args: argparse.Namespace) -> int:
    platforms = args.platform or list(PLATFORMS)
    items = check_items(graph, platforms, args.group)
    if args.json:
        print(json.dumps(items, indent=2))
    else:
        print(table([[i["status"], i["item"], i["detail"]] for i in items], ["", "check", "result"]))
    failed = [i for i in items if i["status"] == FAIL]
    if failed and not args.json:
        sys.stdout.flush()
        print(f"\n{len(failed)} check(s) failed.", file=sys.stderr)
    return 1 if failed else 0


# ---------------------------------------------------------------- devices and status


def cmd_devices(graph: Graph, args: argparse.Namespace) -> int:
    select = "id,azureADDeviceId,deviceName,operatingSystem,osVersion,complianceState,managementState,lastSyncDateTime"
    if args.show_users:
        select += ",userPrincipalName"
    devices = graph.get_all(f"{BETA}/deviceManagement/managedDevices?$select={select}")
    if args.group:
        group = group_by_name(graph, args.group)
        members = graph.get_all(
            f"{V1}/groups/{group['id']}/members/microsoft.graph.device?$select=deviceId&$count=true",
            {"ConsistencyLevel": "eventual"},
        )
        member_ids = {str(m["deviceId"]).casefold() for m in members if m.get("deviceId")}
        devices = [d for d in devices if str(d.get("azureADDeviceId", "")).casefold() in member_ids]
    if args.os:
        devices = [d for d in devices if str(d.get("operatingSystem", "")).lower().startswith(args.os)]
    if args.noncompliant:
        devices = [d for d in devices if d.get("complianceState") != "compliant"]
    rows = [
        [
            d.get("deviceName", ""),
            d.get("operatingSystem", ""),
            d.get("osVersion", ""),
            d.get("complianceState", ""),
            d.get("managementState", ""),
            str(d.get("lastSyncDateTime", ""))[:19],
            d.get("userPrincipalName", "") if args.show_users else "",
        ]
        for d in devices
    ]
    if args.json:
        output = devices if args.show_users else [
            {key: value for key, value in device.items() if key != "userPrincipalName"} for device in devices
        ]
        print(json.dumps(output, indent=2))
    else:
        headers = [
            "device",
            "os",
            "version",
            "compliance",
            "management",
            "last sync (UTC)",
            "primary user" if args.show_users else "",
        ]
        print(table(rows, headers) if rows else "no managed devices match")
    return 0


def cmd_status(graph: Graph, args: argparse.Namespace) -> int:
    if not args.app and not args.remediation:
        raise SystemExit("error: name --app and/or --remediation")
    if args.app:
        app = one_by_name(graph, f"{BETA}/deviceAppManagement/mobileApps", args.app, "app")
        # Graph no longer serves mobileApps/{id}/deviceStatuses ("Resource not found for the
        # segment"); the per-device install state comes from the report the admin center shows.
        path = f"{BETA}/deviceManagement/reports/retrieveDeviceAppInstallationStatusReport"
        query = {"filter": f"(ApplicationId eq '{app['id']}')", "top": STATUS_REPORT_ROWS, "skip": 0}
        report = graph.request("POST", path, dict(query))
        columns = [str(c.get("Column", "")) for c in report.get("Schema", [])]
        states = [dict(zip(columns, values)) for values in report.get("Values", [])]
        total = int(report.get("TotalRowCount") or len(states))
        while len(states) < total:
            query["skip"] = len(states)
            report = graph.request("POST", path, dict(query))
            values = report.get("Values", [])
            if not values:
                raise GraphError(502, "IncompleteReport", f"app status stopped after {len(states)} of {total} rows")
            states.extend(dict(zip(columns, row)) for row in values)
        print(f"app {args.app}: {len(states)} device(s) reported")
        rows = [
            [
                str(s.get("DeviceName") or ""),
                str(s.get("AppInstallState_loc") or s.get("AppInstallState") or ""),
                str(s.get("HexErrorCode") or s.get("ErrorCode") or ""),
                str(s.get("LastModifiedDateTime") or "")[:19],
            ]
            for s in states
        ]
        if rows:
            print(table(rows, ["device", "install state", "error", "last change (UTC)"]))
    if args.remediation:
        script = one_by_name(
            graph, f"{BETA}/deviceManagement/deviceHealthScripts", args.remediation, "Remediations package"
        )
        runs = graph.get_all(
            f"{BETA}/deviceManagement/deviceHealthScripts/{script['id']}/deviceRunStates?$expand=managedDevice($select=deviceName)"
        )
        print(f"remediation {args.remediation}: {len(runs)} run state(s)")
        rows = [
            [
                (r.get("managedDevice") or {}).get("deviceName", ""),
                r.get("detectionState", ""),
                r.get("remediationState", ""),
                str(r.get("lastStateUpdateDateTime", ""))[:19],
            ]
            for r in runs
        ]
        if rows:
            print(table(rows, ["device", "detection", "remediation", "updated (UTC)"]))
    return 0


# ---------------------------------------------------------------- groups


def group_mail_nickname(name: str) -> str:
    nickname = re.sub(r"[^A-Za-z0-9_-]", "", name)[:64]
    if nickname:
        return nickname
    if any(char.isalnum() for char in name):
        return "group-" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:20]
    raise SystemExit(f"error: group name {name!r} has no letters or digits for a mail nickname")


def cmd_groups(graph: Graph, args: argparse.Namespace) -> int:
    if not args.name and not args.add_device:
        raise SystemExit("error: name at least one --name GROUP or --add-device DEVICE:GROUP")
    # Resolve and validate every requested group before changing the tenant.
    planned_groups: list[tuple[str, dict | None, str | None]] = []
    for name in args.name:
        if len(name) > GROUP_NAME_MAX_CHARS:
            raise SystemExit(f"error: group name is {len(name)} characters; the limit is {GROUP_NAME_MAX_CHARS}")
        path = f"{V1}/groups?$filter={odata_eq('displayName', name)}&$select=id,securityEnabled,groupTypes"
        found = graph.get_all(path)
        if not found and args.apply:
            found = graph.wait_for_named_object(path)
        if len(found) > 1:
            raise SystemExit(f"error: {len(found)} groups are named {name!r}; use a unique name")
        if found and (
            not found[0].get("securityEnabled") or "DynamicMembership" in (found[0].get("groupTypes") or [])
        ):
            raise SystemExit(f"error: group {name!r} exists but is not a static security group")
        nickname = group_mail_nickname(name) if not found else None
        planned_groups.append((name, found[0] if found else None, nickname))
    tag = plan_tag(args.apply)
    known_groups: dict[str, dict] = {}
    for name, found, nickname in planned_groups:
        if found:
            known_groups[name] = found
            print(f"{tag}group {name}: exists")
        elif not args.apply:
            print(f"{tag}group {name}: would create a static security group")
        else:
            body = {
                "displayName": name,
                "description": "DefenseClaw MDM kit device group",
                "mailEnabled": False,
                "mailNickname": nickname,
                "securityEnabled": True,
            }
            made = graph.request("POST", f"{V1}/groups", body)
            known_groups[name] = graph.get_after_create(f"{V1}/groups/{made['id']}?$select=id")
            print(f"group {name}: created")
    for pair in args.add_device:
        device_name, sep, group_name = pair.partition(":")
        if not sep or not device_name or not group_name:
            raise SystemExit(f"error: --add-device wants DEVICE:GROUP, got {pair!r}")
        devices = graph.get_all(f"{V1}/devices?$filter={odata_eq('displayName', device_name)}&$select=id,displayName")
        if len(devices) != 1:
            raise SystemExit(f"error: {len(devices)} Entra devices are named {device_name!r}; need exactly one")
        # A group named with --name was checked above, or created as a static security group.
        checked = group_name in known_groups
        found = [known_groups[group_name]] if checked else graph.get_all(
            f"{V1}/groups?$filter={odata_eq('displayName', group_name)}&$select=id,securityEnabled,groupTypes"
        )
        if len(found) > 1:
            raise SystemExit(f"error: {len(found)} groups are named {group_name!r}; use a unique name")
        if found and not checked and (
            not found[0].get("securityEnabled") or "DynamicMembership" in (found[0].get("groupTypes") or [])
        ):
            raise SystemExit(f"error: group {group_name!r} is not a static security group")
        if not found:
            if args.apply:
                raise SystemExit(f"error: group {group_name!r} does not exist; create it with --name first")
            print(f"{tag}add {device_name} to {group_name}: would add (the group does not exist yet)")
            continue
        members = {m["id"] for m in graph.get_all(f"{V1}/groups/{found[0]['id']}/members?$select=id")}
        if devices[0]["id"] in members:
            print(f"{tag}{device_name} is in {group_name}")
        elif not args.apply:
            print(f"{tag}add {device_name} to {group_name}: would add")
        elif graph.add_member(found[0]["id"], devices[0]["id"], group_name):
            print(f"added {device_name} to {group_name}")
        else:
            print(f"{device_name} is in {group_name}")
    if not args.apply:
        print("Nothing was changed. Run again with --apply to make these changes.")
    return 0


# ---------------------------------------------------------------- assign-app


def cmd_assign_app(graph: Graph, args: argparse.Namespace) -> int:
    app = one_by_name(graph, f"{BETA}/deviceAppManagement/mobileApps", args.app, "app")
    state = app.get("publishingState")
    if state not in (None, "published"):
        # Intune refuses an assignment until the upload has finished ("PublishingState is not
        # Published"); say so instead of passing that error on.
        raise SystemExit(
            f"error: app {args.app!r} is not published yet (publishing state {state}); "
            "finish its upload in the Intune admin center, then run this again"
        )
    group = group_by_name(graph, args.group)
    collection = f"{BETA}/deviceAppManagement/mobileApps/{app['id']}/assignments"
    existing = graph.get_all(collection)
    matching = [a for a in existing if (a.get("target") or {}).get("groupId") == group["id"]]
    if len(matching) > 1:
        raise SystemExit(f"error: {len(matching)} assignments target group {args.group!r}; resolve them in Intune")
    assignment = matching[0] if matching else None
    included = assignment and (assignment.get("target") or {}).get("@odata.type") == GROUP_TARGET
    if included and assignment.get("intent") == args.intent:
        print(f"app {args.app} is already assigned to {args.group} as {args.intent}")
        return 0
    action = "delete the existing assignment and create a new one" if assignment else "assign"
    if not args.apply:
        print(f"[plan] would {action} app {args.app} for group {args.group} with intent {args.intent}")
        print("Nothing was changed. Run again with --apply to make this change.")
        return 0
    target = dict((assignment or {}).get("target") or {})
    target.update({"@odata.type": GROUP_TARGET, "groupId": group["id"]})
    body = {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "intent": args.intent,
        "target": target,
    }
    if assignment:
        if "settings" in assignment:
            body["settings"] = assignment["settings"]
        # Graph refuses a PATCH of an assignment intent, target or settings, so
        # an intent change deletes and recreates it. When the create fails, the
        # old assignment is put back so the app is never left unassigned
        # (GAP-1014).
        graph.request("DELETE", f"{collection}/{assignment['id']}")
        try:
            graph.request("POST", collection, body)
        except (GraphError, SystemExit):
            restore = {key: assignment[key] for key in ("intent", "target", "settings") if assignment.get(key)}
            restore["@odata.type"] = "#microsoft.graph.mobileAppAssignment"
            graph.request("POST", collection, restore)
            print(f"app {args.app}: the new assignment failed; the previous {assignment.get('intent')} "
                  f"assignment for group {args.group} was restored", file=sys.stderr)
            raise
    else:
        graph.request("POST", collection, body)
    print(f"app {args.app}: {action} completed for group {args.group} as {args.intent}")
    return 0


def cmd_remove_assignment(graph: Graph, args: argparse.Namespace) -> int:
    app = one_by_name(graph, f"{BETA}/deviceAppManagement/mobileApps", args.app, "app")
    group = group_by_name(graph, args.group)
    collection = f"{BETA}/deviceAppManagement/mobileApps/{app['id']}/assignments"
    targeting = [a for a in graph.get_all(collection) if (a.get("target") or {}).get("groupId") == group["id"]]
    matching = [a for a in targeting if (a.get("target") or {}).get("@odata.type") == GROUP_TARGET]
    if not matching:
        detail = "; exclusion target left in place" if targeting else ""
        print(f"app {args.app}: no included assignment to {args.group}{detail}")
        return 0
    for assignment in matching:
        if not args.apply:
            print(f"[plan] would remove {assignment.get('intent', 'unknown')} assignment of {args.app} to {args.group}")
        else:
            graph.request("DELETE", f"{collection}/{assignment['id']}")
            print(f"removed {assignment.get('intent', 'unknown')} assignment of {args.app} to {args.group}")
    return 0


# ---------------------------------------------------------------- remediation and macos-script


def same_run_schedule(stored: dict, requested: dict) -> bool:
    """Graph returns daily times with seven trailing fractional zeroes."""
    for key, value in requested.items():
        actual = stored.get(key)
        if key == "time":
            if isinstance(actual, str):
                actual = re.sub(r"\.0+$", "", actual)
            if isinstance(value, str):
                value = re.sub(r"\.0+$", "", value)
        if actual != value:
            return False
    return True


def _upsert(graph: Graph, collection: str, name: str, body: dict, apply: bool, what: str,
            create_body: dict | None = None) -> str | None:
    """Create or update an object by display name. Returns its id (None in a preview that would create)."""
    found = graph.get_all(f"{collection}?$filter={odata_eq('displayName', name)}&$select=id,displayName")
    if len(found) > 1:
        raise SystemExit(f"error: {len(found)} {what}s are named {name!r}; rename all but one")
    if not found:
        if not apply:
            print(f"[plan] would create {what} {name!r}")
            return None
        made = graph.request("POST", collection, create_body or body)
        print(f"created {what} {name!r}")
        return str(made["id"])
    object_id = str(found[0]["id"])
    current = graph.get(f"{collection}/{object_id}") if body else {}
    changes = {key: value for key, value in body.items() if key != "@odata.type" and current.get(key) != value}
    if not changes:
        print(f"{what} {name!r}: unchanged")
        return object_id
    if not apply:
        print(f"[plan] would update {what} {name!r}: {', '.join(sorted(changes))}")
        return object_id
    graph.request("PATCH", f"{collection}/{object_id}", changes)
    print(f"updated {what} {name!r}: {', '.join(sorted(changes))}")
    return object_id


def cmd_remediation(graph: Graph, args: argparse.Namespace) -> int:
    detect_path = args.detect or kit_script("Remediate-Detect.ps1")
    remediate_path = args.remediate or kit_script("Remediate-Fix.ps1")
    detect = read_script(detect_path, HEALTH_SCRIPT_MAX_BYTES)
    remediate = read_script(remediate_path, HEALTH_SCRIPT_MAX_BYTES)
    for label, path, data in (("detection", detect_path, detect), ("remediation", remediate_path, remediate)):
        digest = hashlib.sha256(data).hexdigest()[:16]
        print(f"{label} script: {path} ({len(data)} bytes, sha256 {digest}...)")
    create_body = {
        "@odata.type": "#microsoft.graph.deviceHealthScript",
        "displayName": args.name,
        "description": "DefenseClaw standalone enterprise: verify and repair from the installed payload",
        "publisher": "DefenseClaw MDM kit",
        "runAsAccount": "system",
        "runAs32Bit": False,
        "enforceSignatureCheck": False,
        "detectionScriptContent": b64(detect),
        "remediationScriptContent": b64(remediate),
    }
    body = {
        "detectionScriptContent": b64(detect),
        "remediationScriptContent": b64(remediate),
    }
    collection = f"{BETA}/deviceManagement/deviceHealthScripts"
    group = group_by_name(graph, args.group) if args.group else None

    def reject_exclusion(assignments: list[dict]) -> None:
        for assignment in assignments:
            target = assignment.get("target") or {}
            if target.get("groupId") == group["id"] and target.get("@odata.type") != GROUP_TARGET:
                raise SystemExit(
                    f"error: group {args.group!r} is an exclusion target for {args.name!r}; "
                    "remove the exclusion assignment in Intune first, then run remediation again"
                )

    if group:
        scripts = graph.get_all(f"{collection}?$filter={odata_eq('displayName', args.name)}&$select=id")
        if len(scripts) == 1:
            assignments = graph.get_all(f"{collection}/{scripts[0]['id']}/assignments")
            reject_exclusion(assignments)
    script_id = _upsert(graph, collection, args.name, body, args.apply, "Remediations package", create_body)
    if group:
        existing = graph.get_all(f"{collection}/{script_id}/assignments") if script_id else []
        reject_exclusion(existing)
        kept = [a for a in existing if a.get("target", {}).get("groupId") != group["id"]]
        matching = [a for a in existing if a.get("target", {}).get("groupId") == group["id"]]
        if len(matching) > 1:
            raise SystemExit(f"error: {len(matching)} assignments target {args.group!r}; resolve them in Intune")
        at = args.daily_at or "02:00"
        schedule = {
            "@odata.type": "#microsoft.graph.deviceHealthScriptDailySchedule",
            "interval": 1,
            "time": at + ":00",
            "useUtc": False,
        }
        if matching and args.daily_at is None:
            schedule = matching[0].get("runSchedule") or schedule
        wanted = {
            "target": matching[0]["target"] if matching else {"@odata.type": GROUP_TARGET, "groupId": group["id"]},
            "runRemediationScript": True,
            "runSchedule": schedule,
        }
        same_schedule = matching and matching[0].get("target") == wanted["target"] and same_run_schedule(
            matching[0].get("runSchedule") or {}, schedule
        )
        if same_schedule and matching[0].get("runRemediationScript") in (True, False):
            detail = (
                " (detection only: the tenant stored runRemediationScript=false; enable remediation "
                "for this assignment in the Intune admin center)"
                if matching[0]["runRemediationScript"] is False else ""
            )
            print(f"{args.name} assignment to {args.group}: unchanged{detail}")
        elif not args.apply or script_id is None:
            print(f"[plan] would assign {args.name!r} to group {args.group} with remediation enabled")
        else:
            keep = [{k: a[k] for k in ("target", "runRemediationScript", "runSchedule") if k in a} for a in kept]
            graph.request(
                "POST", f"{collection}/{script_id}/assign", {"deviceHealthScriptAssignments": keep + [wanted]}
            )
            stored = None
            for _ in range(5):
                current = graph.get_all(f"{collection}/{script_id}/assignments")
                stored = next(
                    (item for item in current if (item.get("target") or {}).get("groupId") == group["id"]), None
                )
                if stored and same_run_schedule(stored.get("runSchedule") or {}, schedule):
                    break
                time.sleep(2)
            if stored is None or not same_run_schedule(stored.get("runSchedule") or {}, schedule):
                raise SystemExit(
                    f"error: Intune did not return the assignment for {args.group!r}; check it in the admin center"
                )
            if stored.get("runRemediationScript") is False:
                print(f"assigned {args.name!r} to group {args.group} (detection only: the tenant stored "
                      "runRemediationScript=false; enable remediation for this assignment in the Intune admin center)")
            elif stored.get("runRemediationScript") is True:
                print(f"assigned {args.name!r} to group {args.group} with remediation enabled")
            else:
                raise SystemExit(
                    f"error: Intune did not return runRemediationScript for {args.group!r}; "
                    "check it in the admin center"
                )
    if not args.apply:
        print("Nothing was changed. Run again with --apply to make these changes.")
    return 0


def cmd_macos_script(graph: Graph, args: argparse.Namespace) -> int:
    if args.retries is not None and not 0 <= args.retries <= 3:
        raise SystemExit("error: --retries must be between 0 and 3")
    content = read_script(args.file, SHELL_SCRIPT_MAX_BYTES)
    if not content.startswith(b"#!"):
        raise SystemExit("error: macOS script must start with a #! interpreter line")
    settings = re.search(
        # Accept CRLF: a wrapper saved by a Windows editor must not skip the empty-block check.
        rb"(?ms)^dc_inline_config\(\) \{\r?\n\s*cat <<'DEFENSECLAW_CONFIG'\r?\n(.*?)^DEFENSECLAW_CONFIG\r?$",
        content,
    )
    if settings is not None and not settings.group(1).strip():
        raise SystemExit("error: fill in the macOS wrapper settings block before upload")
    if args.frequency is not None and not re.fullmatch(r"P(?:[1-9][0-9]*D|T(?:0S|[1-9][0-9]*[HMS]))", args.frequency):
        raise SystemExit("error: --frequency must be an ISO 8601 duration such as P1D, PT1H or PT0S")
    print(f"script: {args.file} ({len(content)} bytes, sha256 {hashlib.sha256(content).hexdigest()[:16]}...)")
    create_body = {
        "@odata.type": "#microsoft.graph.deviceShellScript",
        "displayName": args.name,
        "description": "DefenseClaw standalone enterprise: install or re-apply with the kit wrapper",
        "scriptContent": b64(content),
        "runAsAccount": "system",
        "fileName": Path(args.file).name,
        "blockExecutionNotifications": True,
    }
    collection = f"{BETA}/deviceManagement/deviceShellScripts"
    group = group_by_name(graph, args.group) if args.group else None
    create_body["retryCount"] = args.retries if args.retries is not None else 3
    create_body["executionFrequency"] = args.frequency or "P1D"
    body = {"scriptContent": b64(content)}
    if args.retries is not None:
        body["retryCount"] = args.retries
    if args.frequency is not None:
        body["executionFrequency"] = args.frequency
    script_id = _upsert(graph, collection, args.name, body, args.apply, "macOS shell script", create_body)
    if group:
        existing = graph.get_all(f"{collection}/{script_id}/groupAssignments") if script_id else []
        if any(a.get("targetGroupId") == group["id"] for a in existing):
            print(f"{plan_tag(args.apply)}{args.name!r} is already assigned to {args.group}")
        elif not args.apply or script_id is None:
            print(f"[plan] would assign {args.name!r} to group {args.group}")
        else:
            keep = [
                {
                    "@odata.type": "#microsoft.graph.deviceManagementScriptGroupAssignment",
                    "targetGroupId": a["targetGroupId"],
                }
                for a in existing
            ]
            keep.append(
                {"@odata.type": "#microsoft.graph.deviceManagementScriptGroupAssignment", "targetGroupId": group["id"]}
            )
            graph.request("POST", f"{collection}/{script_id}/assign", {"deviceManagementScriptGroupAssignments": keep})
            print(f"assigned {args.name!r} to group {args.group}")
    if not args.apply:
        print("Nothing was changed. Run again with --apply to make these changes.")
    return 0


# ---------------------------------------------------------------- command line


def _mutating(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--apply", action="store_true", help="make the changes (the default is a preview)")
    parser.add_argument("--dry-run", action="store_true", help="preview only (the default; accepted for clarity)")


def _time(value: str) -> str:
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", value):
        raise argparse.ArgumentTypeError("use HH:MM, for example 02:00")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="intune_tenant.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="read-only readiness report")
    check.add_argument("--platform", action="append", choices=PLATFORMS, help="only these platforms (repeatable)")
    check.add_argument(
        "--group", action="append", default=[], metavar="NAME", help="a device group that must exist (repeatable)"
    )
    check.add_argument("--json", action="store_true", help="print JSON")
    check.set_defaults(func=cmd_check)

    devices = sub.add_parser("devices", help="read-only: managed devices and their compliance")
    devices.add_argument("--os", choices=PLATFORMS, help="only this operating system")
    devices.add_argument("--group", metavar="NAME", help="only devices in this group")
    devices.add_argument("--noncompliant", action="store_true", help="only devices that are not compliant")
    devices.add_argument("--show-users", action="store_true", help="include each device's primary user")
    devices.add_argument("--json", action="store_true", help="print JSON")
    devices.set_defaults(func=cmd_devices)

    status = sub.add_parser("status", help="read-only: install state of an app, run state of a Remediations package")
    status.add_argument("--app", metavar="NAME", help="display name of the Win32 app")
    status.add_argument("--remediation", metavar="NAME", help="display name of the Remediations package")
    status.set_defaults(func=cmd_status)

    groups = sub.add_parser("groups", help="create static security groups and add devices (preview unless --apply)")
    groups.add_argument("--name", action="append", default=[], metavar="GROUP", help="group to create (repeatable)")
    groups.add_argument(
        "--add-device",
        action="append",
        default=[],
        metavar="DEVICE:GROUP",
        help="Entra device name and group (repeatable)",
    )
    _mutating(groups)
    groups.set_defaults(func=cmd_groups)

    remove = sub.add_parser("remove-assignment", help="remove an app assignment from a group (preview unless --apply)")
    remove.add_argument("--app", required=True, metavar="NAME")
    remove.add_argument("--group", required=True, metavar="NAME")
    _mutating(remove)
    remove.set_defaults(func=cmd_remove_assignment)

    assign = sub.add_parser("assign-app", help="assign an uploaded app to a group (preview unless --apply)")
    assign.add_argument("--app", required=True, metavar="NAME", help="display name of the app")
    assign.add_argument("--group", required=True, metavar="NAME", help="group to assign it to")
    assign.add_argument("--intent", choices=("required", "available", "uninstall"), default="required")
    _mutating(assign)
    assign.set_defaults(func=cmd_assign_app)

    remediation = sub.add_parser(
        "remediation", help="create or update a Windows Remediations package (preview unless --apply)"
    )
    remediation.add_argument("--name", default="DefenseClaw Enterprise health", metavar="NAME")
    remediation.add_argument(
        "--detect", metavar="FILE", help="detection script (kit default on every run)"
    )
    remediation.add_argument(
        "--remediate", metavar="FILE", help="remediation script (kit default on every run)"
    )
    remediation.add_argument("--group", metavar="NAME", help="assign it to this group")
    remediation.add_argument(
        "--daily-at", type=_time, metavar="HH:MM", help="daily schedule, device local time (default 02:00 on create)"
    )
    _mutating(remediation)
    remediation.set_defaults(func=cmd_remediation)

    macos = sub.add_parser("macos-script", help="create or update a macOS shell script (preview unless --apply)")
    macos.add_argument("--name", required=True, metavar="NAME")
    macos.add_argument("--file", required=True, metavar="FILE", help="the script, with its settings block filled in")
    macos.add_argument("--group", metavar="NAME", help="assign it to this group")
    macos.add_argument(
        "--frequency", metavar="ISO8601", help="how often it runs; PT0S runs once (default P1D on create)"
    )
    macos.add_argument("--retries", type=int, help="retries after a failure, 0 to 3 (default 3 on create)")
    _mutating(macos)
    macos.set_defaults(func=cmd_macos_script)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "apply", False) and getattr(args, "dry_run", False):
        print("error: --apply and --dry-run cannot be used together", file=sys.stderr)
        return 2
    try:
        return args.func(Graph.from_env(), args)
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
