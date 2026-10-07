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

"""Operator block/allow lists in config.yaml ``asset_policy``.

Since config_version 9 the ``asset_policy.<type>.denied/allowed`` lists (and
``asset_policy.tool``) are the only operator block/allow source; the audit.db
``actions`` table is the enforcement journal (scan-verdict blocks, quarantine,
runtime disable). The CLI changes the lists through the single config writer;
a managed standalone device refuses, because its admin config comes from the
management plane. Secure Client hosts keep the actions table unchanged.

Mirrors internal/config/asset_policy_lists.go and internal/gateway/enforce_config.go.
"""

from __future__ import annotations

import contextlib
import functools
import http.client
import json
import os
import socket
from typing import Any

import click

from defenseclaw import connector_paths
from defenseclaw.audit_actions import ACTION_ACTION

LIST_DENY = "deny"
LIST_ALLOW = "allow"

OP_BLOCK = "block"
OP_ALLOW = "allow"
OP_UNBLOCK = "unblock"
OP_CLEAR = "clear"

TARGET_TYPES = ("skill", "mcp", "plugin", "tool")

MANAGED_REFUSAL = (
    "This device is managed: add it to asset_policy in the admin config "
    "(MDM or management plane)"
)


class ManagedDeviceError(click.ClickException):
    """A local policy write on a managed standalone device (exit 3)."""

    exit_code = 3

    def __init__(self, message: str = MANAGED_REFUSAL) -> None:
        super().__init__(message)


def enterprise_profile(cfg: Any) -> str:
    """The managed_enterprise profile ("" when unmanaged)."""
    from defenseclaw.commands.cmd_status import _enterprise_profile

    return _enterprise_profile(cfg)


def is_secure_client(cfg: Any) -> bool:
    return cfg is not None and enterprise_profile(cfg) == "secure_client"


def is_managed_standalone(cfg: Any) -> bool:
    """A managed standalone device: the config says so, or this computer's
    machine marker does (a standard user's per-user config does not)."""
    from defenseclaw import config_writer

    return cfg is not None and (enterprise_profile(cfg) == "standalone" or config_writer.machine_managed_standalone())


_REFUSAL_ACTIONS = {
    ("skill", OP_BLOCK): "skill-block", ("skill", OP_ALLOW): "skill-allow", ("skill", OP_UNBLOCK): "skill-unblock",
    ("plugin", OP_BLOCK): "plugin-block", ("plugin", OP_ALLOW): "plugin-allow",
    ("plugin", OP_UNBLOCK): "plugin-unblock",
    ("mcp", OP_BLOCK): "block-mcp", ("mcp", OP_ALLOW): "allow-mcp", ("mcp", OP_UNBLOCK): "mcp-unblock",
    ("tool", OP_BLOCK): "tool-block", ("tool", OP_ALLOW): "tool-allow", ("tool", OP_UNBLOCK): "tool-unblock",
}


def refuse_if_managed(cfg: Any, *, target_type: str = "", op: str = "", name: str = "") -> None:
    """Raise ManagedDeviceError on a managed standalone device, after
    auditing the refused attempt."""
    if is_managed_standalone(cfg):
        action = _REFUSAL_ACTIONS.get((target_type, OP_UNBLOCK if op == OP_CLEAR else op), ACTION_ACTION)
        audit_managed_refusal(action, name or target_type or "config", f"type={target_type}" if target_type else "")
        raise ManagedDeviceError()


def refuse_on_managed_device(target_type: str, op: str, name_arg: str = "name"):
    """Decorator for a block, allow or unblock command (under ``@pass_ctx``).

    A managed device refuses, audited and with exit 3, before the command
    checks its connector, its arguments or the stored state. Without this the
    command answered first, telling a standard user to run ``defenseclaw setup
    <connector>`` (a per-user setup the managed install forbids) or that there
    was nothing to clear."""

    def decorate(command):
        @functools.wraps(command)
        def wrapper(app, *args, **kwargs):
            refuse_if_managed(
                getattr(app, "cfg", None), target_type=target_type, op=op, name=str(kwargs.get(name_arg) or "")
            )
            return command(app, *args, **kwargs)

        return wrapper

    return decorate


def audit_managed_config_refusal(target: str, command: str) -> None:
    """Record a refused config writer (``config set``/``unset`` and the
    guardrail writers) as the generic ``action`` row. ``config-update`` would
    not do: the gateway turns every one into a config.change.applied event
    and drops the details, so a refused write would read as an applied one."""
    audit_managed_refusal(ACTION_ACTION, target, f"command={command}")


MANAGED_REFUSAL_PATH = "/api/v1/managed/refusal"


class _HookSocketConnection(http.client.HTTPConnection):
    """HTTP over the managed gateway unix hook socket."""

    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


def _managed_hook_socket() -> str:
    """The hook socket of this host managed gateway, from the runtime
    descriptor the enterprise lifecycle publishes ("" on Windows, which has
    none, and on an unmanaged host)."""
    from defenseclaw.upgrade_shim import managed_descriptor

    descriptor = managed_descriptor()
    if not descriptor:
        return ""
    try:
        with open(descriptor, encoding="utf-8") as stream:
            path = str(json.load(stream).get("hook_socket") or "")
    except (OSError, ValueError, AttributeError):
        return ""
    return path if os.path.isabs(path) else ""


def _clip(text: str, limit: int) -> str:
    return text.encode("utf-8")[:limit].decode("utf-8", "ignore")


def _report_refusal_to_managed_gateway(action: str, target: str, details: str) -> bool:
    """Hand a refusal to the managed gateway over its hook socket, which
    names the caller from the kernel: a standard user has no gateway token,
    so the token-authenticated audit path never records its refusals."""
    socket_path = _managed_hook_socket()
    if not socket_path:
        return False
    body = json.dumps({"action": action, "target": _clip(target, 256), "details": _clip(details, 512)})
    connection = _HookSocketConnection(socket_path, timeout=3)
    try:
        connection.request(
            "POST", MANAGED_REFUSAL_PATH, body,
            {"Content-Type": "application/json", "X-DefenseClaw-Client": "defenseclaw-cli"},
        )
        return 200 <= connection.getresponse().status < 300
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def audit_managed_refusal(action: str, target: str, details: str = "") -> None:
    """Record a refused local policy write on a managed device in the audit
    trail (best effort: the refusal stands even when the gateway that
    records CLI events is down). The managed gateway hook socket takes it
    for every account, a standard user included; the token-authenticated
    CLI path is the fallback."""
    try:
        if _report_refusal_to_managed_gateway(action, target, details):
            return
        ctx = click.get_current_context(silent=True)
        app = getattr(ctx, "obj", None) if ctx is not None else None
        logger = getattr(app, "logger", None)
        if logger is None and ctx is not None:
            # ``config`` skips the startup load, so it has no logger yet.
            from defenseclaw import config as config_module
            from defenseclaw.logger import Logger

            logger = Logger.from_config(getattr(app, "cfg", None) or config_module.load())
        if logger is not None:
            logger.log_action(action, target, f"outcome=refused reason=managed_device {details}".strip())
    except Exception:  # noqa: BLE001 - auditing must not turn the refusal into a crash
        pass


#: ``guardrail`` verbs that write policy (the rest read: status, list-packs, validate-pack).
_GUARDRAIL_WRITERS = frozenset({
    "alert-at", "allow-private-upstream", "block-at", "block-message", "disable", "enable", "fail-mode", "hilt",
    "judge", "mode", "protection", "rule", "suppress", "use-pack",
})
_POLICY_WRITERS = frozenset({"activate", "create", "delete", "edit"})


def _first_argument(command: click.Command, name: str, args: list[str]) -> str:
    """The value of the command's first positional argument ("" when it has none)."""
    try:
        with command.make_context(name, list(args), resilient_parsing=True) as ctx:
            for param in command.params:
                if isinstance(param, click.Argument):
                    return str(ctx.params.get(param.name) or "")
    except Exception:  # noqa: BLE001 - the target is a nicety; the refusal stands without it
        pass
    return ""


def audit_first_run_refusal(root: click.Command, argv: list[str]) -> None:
    """Audit a policy write that a managed device refused before the command ran.

    An account with no per-user config is stopped at startup (exit 3), ahead of
    the command's own managed gate that audits, so its refusals left no row
    (GAP-0205). Resolve *argv* against the command tree and record the row the
    gate would: the block/allow/unblock action for skill, mcp, plugin and tool,
    the generic action row for the guardrail and policy writers. Reads and
    unknown commands record nothing."""
    command, path, rest = root, [], list(argv)
    while isinstance(command, click.Group) and rest and not rest[0].startswith("-"):
        child = command.commands.get(rest[0])
        if child is None:
            break
        command, path, rest = child, [*path, rest[0]], rest[1:]
    group, verb = (path + ["", ""])[:2]
    if len(path) == 2 and group in TARGET_TYPES and verb in (OP_BLOCK, OP_ALLOW, OP_UNBLOCK):
        target = _first_argument(command, verb, rest) or group
        audit_managed_refusal(_REFUSAL_ACTIONS[(group, verb)], target, f"type={group}")
    elif (group == "guardrail" and verb in _GUARDRAIL_WRITERS and path[2:3] != ["list"]) or (
        group == "policy" and verb in _POLICY_WRITERS
    ):
        words = " ".join(path)
        audit_managed_refusal(ACTION_ACTION, words, f"command={words}")


def _type_policy(asset_policy: Any, target_type: str) -> Any | None:
    if asset_policy is None or target_type not in ("skill", "mcp", "plugin"):
        return None
    return getattr(asset_policy, target_type, None)


def list_decision(
    asset_policy: Any,
    target_type: str,
    name: str,
    connector: str = "",
    *,
    source_path: str = "",
    url: str = "",
    command: str = "",
    args: list[str] | None = None,
    transport: str = "",
) -> tuple[str, Any | None]:
    """Match the explicit lists for one asset: ``("deny"|"allow"|"", rule)``.

    The lists apply whether or not asset_policy is enabled and in either
    mode. A rule scoped to the connector decides before an unscoped one, and
    at the same scope denied wins (Go ``Config.AssetListDecision``).
    """
    from defenseclaw.enforce.admission import _find_asset_rule

    policy = _type_policy(asset_policy, target_type)
    if policy is None:
        return "", None
    for scope in ("scoped", "global"):
        lists = ((LIST_DENY, getattr(policy, "denied", [])), (LIST_ALLOW, getattr(policy, "allowed", [])))
        for verdict, rules in lists:
            for rule in rules or []:
                if _find_asset_rule(
                    [rule], name, connector, source_path, url, command, args or [], transport,
                    connector_scope=scope,
                ) is None:
                    continue
                if verdict == LIST_ALLOW and not _allow_pin_matches(rule, source_path):
                    continue
                return verdict, rule
    return "", None


def path_has_components(path: str, marker: str) -> bool:
    """True when ``path`` contains ``marker`` as a contiguous run of whole
    path components, case-insensitively and with either slash (F-0543). Go
    ``config.PathHasComponents``."""
    def parts(value: str) -> list[str]:
        return [p for p in str(value or "").lower().replace("\\", "/").split("/") if p]

    path_parts, marker_parts = parts(path), parts(marker)
    n = len(marker_parts)
    if not n or len(path_parts) < n:
        return False
    return any(path_parts[i : i + n] == marker_parts for i in range(len(path_parts) - n + 1))


def _allow_pin_matches(rule: Any, source_path: str) -> bool:
    """A pinned allow matches only the pinned path, by whole components, so
    a look-alike sibling never inherits it (F-0941)."""
    pins = getattr(rule, "source_path_contains", []) or []
    return not pins or any(path_has_components(source_path, pin) for pin in pins)


def tool_decision(asset_policy: Any, tool: str, connector: str = "") -> tuple[str, Any | None]:
    """Match ``asset_policy.tool`` for a tool call on connector (Go
    ``Config.ToolListDecision``)."""
    tools = getattr(asset_policy, "tool", None) if asset_policy is not None else None
    tool = (tool or "").strip()
    if tools is None or not tool:
        return "", None
    want = connector_paths.normalize(connector) if connector else ""
    for scoped in (True, False):
        for verdict, rules in ((LIST_DENY, tools.denied), (LIST_ALLOW, tools.allowed)):
            for rule in rules:
                rule_connector = (rule.connector or "").strip()
                if (rule.name or "").strip() != tool or bool(rule_connector) != scoped:
                    continue
                if scoped and connector_paths.normalize(rule_connector) != want:
                    continue
                return verdict, rule
    return "", None


def _connector_key(connector: str) -> str:
    connector = (connector or "").strip()
    return connector_paths.normalize(connector) if connector else ""


def _same_asset(rule: Any, name: str, connector: str) -> bool:
    return (getattr(rule, "name", "") or "").strip() == name and _connector_key(
        getattr(rule, "connector", "")
    ) == _connector_key(connector)


def write_operator_decision(
    cfg: Any,
    *,
    op: str,
    target_type: str,
    name: str,
    connector: str = "",
    reason: str = "",
    source_path: str = "",
) -> None:
    """Write one operator block/allow/unblock/clear to config.yaml.

    A block or allow first drops every rule for the same name and connector
    from both lists, then appends the new rule (an allow is pinned to
    ``source_path`` when given); an unblock drops only the denied rule and a
    clear drops both. The edit is made under the config writer lock against
    the lists on disk, not the ones loaded when this process started, so a
    concurrent block or allow (another CLI, the REST API, the TUI) is never
    lost; ``Config.save()`` then writes it. Refuses on a managed standalone
    device.
    """
    from defenseclaw import config_writer
    from defenseclaw.config import AssetPolicyRule, AssetPolicyToolRule, config_path_for_data_dir

    if getattr(cfg, "asset_policy", None) is None:
        raise ValueError("an operator block or allow needs the loaded config.yaml")
    refuse_if_managed(cfg, target_type=target_type, op=op, name=name)
    if target_type not in TARGET_TYPES:
        raise ValueError(f"target type must be one of {', '.join(TARGET_TYPES)}")
    data_dir = getattr(cfg, "data_dir", "")
    path = str(config_path_for_data_dir(data_dir)) if data_dir else ""
    with config_writer.hold_lock(path) if path else contextlib.nullcontext():
        holder = getattr(cfg.asset_policy, target_type)
        if path:
            _reload_lists_from_disk(cfg, holder, target_type, path)
        denied = [r for r in holder.denied if not _same_asset(r, name, connector)]
        allowed = [r for r in holder.allowed if not _same_asset(r, name, connector)]
        if target_type == "tool":
            rule: Any = AssetPolicyToolRule(name=name, connector=connector, reason=reason)
        else:
            rule = AssetPolicyRule(
                name=name, connector=connector, reason=reason,
                source_path_contains=[source_path] if source_path and op == OP_ALLOW else [],
            )
        if op == OP_BLOCK:
            denied.append(rule)
        elif op == OP_ALLOW:
            allowed.append(rule)
        elif op == OP_UNBLOCK:
            allowed = list(holder.allowed)
        holder.denied, holder.allowed = denied, allowed
        cfg.save()


def _reload_lists_from_disk(cfg: Any, holder: Any, target_type: str, path: str) -> None:
    """Replace ``holder``'s denied/allowed lists, and their save baseline,
    with the ones in config.yaml now (the caller holds the writer lock)."""
    import copy
    import os

    from defenseclaw.config import (
        _config_to_dict,
        _load_existing_config_yaml,
        _merge_asset_rules,
        _merge_asset_tool_policy,
        default_asset_policy_baseline,
    )

    if not os.path.isfile(path):
        return
    raw = _load_existing_config_yaml(path).get("asset_policy")
    section = raw.get(target_type) if isinstance(raw, dict) else None
    section = section if isinstance(section, dict) else {}
    if target_type == "tool":
        fresh = _merge_asset_tool_policy(section)
        holder.denied, holder.allowed = fresh.denied, fresh.allowed
    else:
        holder.denied = _merge_asset_rules(section.get("denied"))
        holder.allowed = _merge_asset_rules(section.get("allowed"))
    snapshot = getattr(cfg, "_loaded_v8_modeled_snapshot", None)
    if isinstance(snapshot, dict):
        current = _config_to_dict(cfg).get("asset_policy", {}).get(target_type, {})
        # A load that saw no asset_policy left the key out of the snapshot; seed the
        # defaults so the save writes this rule alone, not every default (GAP-0060).
        if not isinstance(snapshot.get("asset_policy"), dict):
            snapshot["asset_policy"] = default_asset_policy_baseline()
        base = snapshot["asset_policy"].setdefault(target_type, {})
        for key in ("denied", "allowed"):
            base[key] = copy.deepcopy(current.get(key, []))


def has_entry(cfg: Any, store: Any, target_type: str, name: str, connector: str, decision: str) -> bool:
    """True when the operator list holds a rule for ``name`` at exactly this
    connector scope ("" is the unscoped rule): ``decision`` "block" reads
    denied, "allow" reads allowed. Secure Client hosts read the actions row."""
    if is_secure_client(cfg):
        return bool(store) and store.has_action(target_type, name, "install", decision, connector)
    asset_policy = getattr(cfg, "asset_policy", None)
    holder = getattr(asset_policy, target_type, None) if asset_policy is not None else None
    rules = getattr(holder, "denied" if decision == "block" else "allowed", []) if holder is not None else []
    want = connector_paths.normalize(connector) if connector else ""
    for rule in rules or []:
        rule_connector = (getattr(rule, "connector", "") or "").strip()
        if (getattr(rule, "name", "") or "").strip() != name:
            continue
        if (connector_paths.normalize(rule_connector) if rule_connector else "") == want:
            return True
    return False


def install_counts(store: Any, cfg: Any) -> tuple[int, int, int, int]:
    """(blocked skills, allowed skills, blocked MCPs, allowed MCPs) as the list
    views show them: journal rows with the operator decisions of asset_policy
    folded in, so a decision made in config.yaml is counted."""
    counts: list[int] = []
    for target_type in ("skill", "mcp"):
        entries = merge_operator_entries(store.list_actions_by_type(target_type), cfg, target_type)
        for install in ("block", "allow"):
            counts.append(sum(1 for entry in entries if entry.actions.install == install))
    return counts[0], counts[1], counts[2], counts[3]


def merge_operator_entries(entries: list[Any], cfg: Any, target_type: str) -> list[Any]:
    """Journal rows with the operator decisions from asset_policy folded in.

    Each named rule in ``asset_policy.<type>.denied``/``allowed`` sets the
    ``install`` field (block/allow) of the journal row for the same name and
    connector, or becomes a row of its own, so list and info views show what
    config.yaml blocks and allows. Secure Client hosts keep the table as is.
    """
    import dataclasses

    from defenseclaw.models import ActionEntry, ActionState

    out = list(entries)
    asset_policy = getattr(cfg, "asset_policy", None) if cfg is not None else None
    holder = getattr(asset_policy, target_type, None) if asset_policy is not None else None
    if holder is None or is_secure_client(cfg):
        return out
    for decision, rules in (("allow", holder.allowed), ("block", holder.denied)):
        for rule in rules or []:
            name = (getattr(rule, "name", "") or "").strip()
            if not name:
                continue
            connector = (getattr(rule, "connector", "") or "").strip()
            for i, entry in enumerate(out):
                if entry.target_name == name and _connector_key(entry.connector) == _connector_key(connector):
                    out[i] = dataclasses.replace(
                        entry,
                        actions=dataclasses.replace(entry.actions, install=decision),
                        reason=rule.reason or entry.reason,
                    )
                    break
            else:
                suffix = f"@{connector}" if connector else ""
                out.append(ActionEntry(
                    id=f"asset_policy:{target_type}:{name}{suffix}", target_type=target_type,
                    target_name=name, actions=ActionState(install=decision),
                    reason=rule.reason, connector=connector,
                ))
    return out
