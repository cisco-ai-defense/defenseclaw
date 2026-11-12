# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""defenseclaw routing — semantic model routing from config.yaml.

Every command reads and writes config.yaml only: writes go through the same
writer and validation as ``defenseclaw config set`` (the gateway's
config-v8 validate) and are refused on a managed device, where the
administrator's bundle owns the file. Reads that need the running gateway
(``test``, ``explain``, ``usage``, budget spend) ask it; users see only
their own decisions, usage and budgets, administrators see everyone's.
"""

from __future__ import annotations

import copy
import datetime as _dt
import json
import os
import sys
from typing import Any

import click

from defenseclaw import config_writer, ux
from defenseclaw.context import AppContext, pass_ctx

ADMIN_RULES_KEY = "routing.admin.rules"
ADMIN_BUDGETS_KEY = "routing.admin.budgets"
CLASSIFIERS = ("rules", "systemone", "vllm_sr")
# Absent routing.classifier keeps the 1.0.9 meaning (the vLLM Semantic Router).
DEFAULT_CLASSIFIER = "vllm_sr"
PERIODS = ("day", "week", "month")
SCOPES = ("user", "group", "connector")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
USAGE_BY = ("model", "connector", "route", "user", "group", "profile")
# Provider -> conventional API key environment variable, for setup hints.
KEY_ENV_HINTS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "azure": "AZURE_OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
}


# --------------------------------------------------------------------------
# config access


def _managed() -> bool:
    return config_writer.machine_managed_standalone()


# sha256 of the config.yaml bytes the last _document() read: every write
# passes it, so a change made by another writer meanwhile is refused instead
# of lost.
_READ_SHA256: str | None = None


def _document() -> dict[str, Any]:
    """config.yaml as written (unmasked: lists are written back whole, and a
    masked value would replace the real one); {} when it does not exist yet."""
    import hashlib

    import yaml

    from defenseclaw import config as config_module
    from defenseclaw.observability.v8_config import load_validate_v8

    global _READ_SHA256
    path = config_module.config_path()
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        _READ_SHA256 = None
        return {}
    except PermissionError as exc:
        if _managed():
            raise click.ClickException(
                "config.yaml on this managed device is readable only by administrators; "
                "defenseclaw routing status shows your own routing"
            ) from exc
        raise click.ClickException(f"cannot read {path}: {exc}") from exc
    try:
        load_validate_v8(raw, source_name=str(path))
        doc = yaml.safe_load(raw) or {}
    except Exception as exc:  # noqa: BLE001 - shown as one plain line
        raise click.ClickException(
            "config.yaml does not validate; run defenseclaw config validate to see why"
        ) from exc
    if not isinstance(doc, dict):
        raise click.ClickException("config.yaml is not a mapping; run defenseclaw config validate")
    _READ_SHA256 = hashlib.sha256(raw).hexdigest()
    return doc


def _routing(doc: dict[str, Any]) -> dict[str, Any]:
    value = doc.get("routing")
    return value if isinstance(value, dict) else {}


def _admin(doc: dict[str, Any]) -> dict[str, Any]:
    value = _routing(doc).get("admin")
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def _locked(doc: dict[str, Any]) -> set[str]:
    """Routing keys the user may not change: all of them on a managed device,
    else the ones routing.admin.locked names."""
    if _managed():
        return {"*"}
    return {str(k) for k in _list(_admin(doc).get("locked"))}


def _is_locked(locked: set[str], key: str) -> bool:
    return "*" in locked or key in locked


def _refuse_on_managed(keys: list[str]) -> None:
    """Refuse a write on a managed device before touching the file (users
    cannot read it there; exit 3 like config set)."""
    if not _managed():
        return
    from defenseclaw.commands.cmd_config import MANAGED_EXIT_CODE
    from defenseclaw.enforce.asset_lists import audit_managed_config_refusal

    audit_managed_config_refusal(", ".join(keys), "routing")
    ux.echo(f"error: {config_writer.MANAGED_REFUSAL}. {', '.join(keys)} is set by your administrator.", err=True)
    raise SystemExit(MANAGED_EXIT_CODE)


def _write(app: AppContext, changes: dict[str, Any], *, unset: list[str] | None = None) -> bool:
    """One validated write of the dotted keys in changes (and unset keys)."""
    from defenseclaw.commands.cmd_config import _write_config_change
    from defenseclaw.config_writer import Change, parse_path

    keys = list(changes) + list(unset or [])
    _refuse_on_managed(keys)
    written = False
    expect = _READ_SHA256
    if changes:
        written = _write_config_change(app, [Change(k, v) for k, v in changes.items()], expect, "set")
        expect = None if written else expect
    if unset:
        for key in unset:
            parse_path(key)
        written = _write_config_change(app, [Change(k, unset=True) for k in unset], expect, "unset") or written
    return written


def _aliases(doc: dict[str, Any]) -> list[str]:
    return [str(m.get("name")) for m in _list(_routing(doc).get("models")) if isinstance(m, dict) and m.get("name")]


def _split(values: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for value in values:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def _emit_json(data: Any) -> None:
    click.echo(json.dumps(data, indent=2, sort_keys=False, default=str))


# --------------------------------------------------------------------------
# gateway access


def _client(app: AppContext, timeout: float = 5):
    from defenseclaw import config as config_module
    from defenseclaw.gateway import OrchestratorClient, gateway_api_client_host

    cfg = app.cfg if app.cfg is not None else config_module.load()
    app.cfg = cfg
    return OrchestratorClient(
        host=gateway_api_client_host(cfg),
        port=cfg.gateway.api_port,
        token=cfg.gateway.resolved_token(),
        timeout=timeout,
    )


def _ask_gateway(app: AppContext, method: str, path: str, *, timeout: float = 5, **kwargs: Any) -> tuple[Any, str]:
    """(answer, error): the gateway's JSON answer, or a plain error."""
    try:
        client = _client(app, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - config unreadable or gateway settings missing
        return None, f"cannot reach the gateway: {exc}"
    try:
        return client.routing_request(method, path, **kwargs), ""
    except Exception as exc:  # noqa: BLE001 - transport or HTTP failure, shown plainly
        from defenseclaw.gateway import RoutingAPIError

        if isinstance(exc, RoutingAPIError):
            return None, exc.plain()
        return None, "the gateway is not running or did not answer (start it with: defenseclaw-gateway start)"
    finally:
        client.close()


def _health_routing(app: AppContext) -> dict[str, Any]:
    try:
        client = _client(app, timeout=3)
    except Exception:  # noqa: BLE001
        return {}
    try:
        health = client.health()
    except Exception:  # noqa: BLE001 - gateway down: status says so
        return {"state": "unreachable"}
    finally:
        client.close()
    live = health.get("routing") if isinstance(health, dict) else None
    return live if isinstance(live, dict) else {}


# --------------------------------------------------------------------------
# the group


@click.group("routing")
def routing_cmd() -> None:
    """Route model calls to the model you choose, by task, user and budget.

    Settings live in config.yaml under routing:. Writes use the same
    validation as defenseclaw config set; on a managed device they are set by
    your administrator.
    """


# ---------------- status


def _status_data(app: AppContext) -> dict[str, Any]:
    data: dict[str, Any] = {"managed": _managed()}
    warnings: list[str] = []
    try:
        doc = _document()
    except click.ClickException as exc:
        doc = None
        if not data["managed"]:
            raise
        warnings.append("config.yaml is set by your administrator; showing what the gateway reports for you")
        del exc
    if doc is not None:
        routing = _routing(doc)
        admin = _admin(doc)
        locked = _locked(doc)
        default = str(routing.get("default_alias") or admin.get("default_alias") or "")
        data.update(
            enabled=bool(routing.get("enabled")),
            classifier=str(routing.get("classifier") or DEFAULT_CLASSIFIER),
            default_alias=default,
            models=[
                {
                    "alias": str(m.get("name", "")),
                    "provider": str(m.get("provider", "")),
                    "model": str(m.get("model", "")),
                    "default": str(m.get("name", "")) == default,
                    "locked": _is_locked(locked, "models"),
                }
                for m in _list(routing.get("models"))
                if isinstance(m, dict)
            ],
            rules=len(_list(admin.get("rules"))),
            budgets=len(_list(admin.get("budgets"))),
            rule_list=_list(admin.get("rules")),
            budget_list=_list(admin.get("budgets")),
            route_only=[str(c) for c in _list((routing.get("route_only") or {}).get("connectors"))],
            locked=sorted(locked),
        )
        if data["enabled"] and not data["models"]:
            warnings.append("routing is on but routing.models is empty: add one with defenseclaw routing models add")
        if (data["rules"] or data["budgets"]) and not data["enabled"]:
            warnings.append("routing.admin rules or budgets are set but routing is off: nothing is applied")
    data["health"] = _health_routing(app) if data.get("enabled", True) else {"state": "disabled"}
    effective, error = _ask_gateway(app, "GET", "/api/v1/routing/effective", params={"recent": 5})
    data["effective"] = effective if isinstance(effective, dict) else None
    if error and data.get("enabled"):
        warnings.append(f"no live routing view: {error}")
    for budget in (effective or {}).get("budgets", []) if isinstance(effective, dict) else []:
        if isinstance(budget, dict) and budget.get("exceeded"):
            warnings.append(
                f"budget {budget.get('id')} is used up for this {budget.get('period')} "
                f"({budget.get('on_exceed')}; resets {budget.get('resets_at')})"
            )
    data["warnings"] = warnings
    return data


@routing_cmd.command("status")
@click.option("--json", "as_json", is_flag=True, help="Print JSON.")
@pass_ctx
def routing_status(app: AppContext, as_json: bool) -> None:
    """Show whether routing is on, its models, rules, health and your last decisions."""
    data = _status_data(app)
    if as_json:
        _emit_json(data)
        return
    if "enabled" in data:
        state = "on" if data["enabled"] else "off"
        health = str((data.get("health") or {}).get("state") or "unknown")
        click.echo(f"Routing:    {state}  classifier {data['classifier']}  health {health}")
        click.echo(
            f"Models:     {len(data['models'])}"
            + (f"  default {data['default_alias']}" if data["default_alias"] else "")
        )
        for m in data["models"]:
            marks = " ".join(x for x in ("default" if m["default"] else "", "locked" if m["locked"] else "") if x)
            click.echo(f"  {m['alias']:<16} {m['provider']}/{m['model']}" + (f"  ({marks})" if marks else ""))
        click.echo(f"Rules:      {data['rules']}   Budgets: {data['budgets']}")
        if data["route_only"]:
            click.echo(f"Route-only: {', '.join(data['route_only'])}")
        if data["managed"]:
            click.echo("Managed:    routing settings are set by your administrator")
    effective = data.get("effective") or {}
    if effective:
        allowed = effective.get("allowed_aliases")
        click.echo(
            "For you:    "
            + (f"allowed {', '.join(allowed)}" if allowed else "all models allowed")
            + (f"; profile {effective['profile']}" if effective.get("profile") else "")
        )
        for d in effective.get("recent", [])[:5]:
            click.echo(
                f"  {str(d.get('time', ''))[11:19]} {d.get('connector', ''):<11} {d.get('category') or '-':<10} "
                f"{d.get('requested_model') or '?'} -> {d.get('selected_alias') or d.get('outcome')}"
            )
    for w in data["warnings"]:
        ux.warn(w)


# ---------------- enable / disable


def _route_only():
    """The route-only helpers (routing_route_only.py, owned by the routing core)."""
    try:
        from defenseclaw import routing_route_only
    except ImportError as exc:
        raise click.ClickException("routing a hook connector needs a DefenseClaw build with route-only mode") from exc
    return routing_route_only


@routing_cmd.command("enable")
@click.option("--connector", default="", help="Route this hook connector's model calls (claudecode or codex).")
@pass_ctx
def routing_enable(app: AppContext, connector: str) -> None:
    """Turn routing on (or route one connector's model calls)."""
    _refuse_on_managed(["routing.route_only" if connector else "routing.enabled"])
    if connector:
        _route_only().enable(app, connector)
        return
    doc = _document()
    if not _aliases(doc):
        raise click.ClickException(
            "routing needs at least one model; add one first: defenseclaw "
            "routing models add NAME --provider P --model M"
        )
    _write(app, {"routing.enabled": True})


@routing_cmd.command("disable")
@click.option("--connector", default="", help="Stop routing this connector and restore its own model settings.")
@pass_ctx
def routing_disable(app: AppContext, connector: str) -> None:
    """Turn routing off (or stop routing one connector; works with the gateway stopped)."""
    _refuse_on_managed(["routing.route_only" if connector else "routing.enabled"])
    if connector:
        _route_only().disable(app, connector)
        return
    _document()
    _write(app, {"routing.enabled": False})


# ---------------- models


@routing_cmd.group("models")
def routing_models() -> None:
    """List and edit the model aliases routing can choose from."""


@routing_models.command("list")
@click.option("--json", "as_json", is_flag=True, help="Print JSON.")
def routing_models_list(as_json: bool) -> None:
    """List the model aliases."""
    doc = _document()
    routing = _routing(doc)
    default = str(routing.get("default_alias") or "")
    locked = _locked(doc)
    rows = [
        dict(m, default=m.get("name") == default, locked=_is_locked(locked, "models"))
        for m in _list(routing.get("models"))
        if isinstance(m, dict)
    ]
    if as_json:
        _emit_json(rows)
        return
    if not rows:
        click.echo("No models. Add one: defenseclaw routing models add NAME --provider P --model M")
        return
    for m in rows:
        marks = " ".join(x for x in ("default" if m["default"] else "", "locked" if m["locked"] else "") if x)
        key = f"  key {m['api_key_env']}" if m.get("api_key_env") else ""
        click.echo(
            f"{m.get('name', ''):<16} {m.get('provider', '')}/{m.get('model', '')}{key}"
            + (f"  ({marks})" if marks else "")
        )


@routing_models.command("add")
@click.argument("name")
@click.option("--provider", required=True, help="Provider, for example anthropic, openai or bedrock.")
@click.option("--model", "model_id", required=True, help="Model id at the provider.")
@click.option("--base-url", default="", help="Provider base URL (leave out for the provider default).")
@click.option("--api-key-env", default="", help="Environment variable that holds the API key.")
@click.option(
    "--api", "apis", multiple=True, help="API family the model serves (chat, messages, responses, converse, invoke)."
)
@click.option("--capability", "capabilities", multiple=True, help="tools, vision, thinking or long_context.")
@pass_ctx
def routing_models_add(
    app: AppContext,
    name: str,
    provider: str,
    model_id: str,
    base_url: str,
    api_key_env: str,
    apis: tuple[str, ...],
    capabilities: tuple[str, ...],
) -> None:
    """Add a model alias."""
    _refuse_on_managed(["routing.models"])
    doc = _document()
    models = copy.deepcopy(_list(_routing(doc).get("models")))
    if name in _aliases(doc):
        raise click.ClickException(f"routing.models already has {name}; remove it first or pick another name")
    entry: dict[str, Any] = {"name": name, "provider": provider, "model": model_id}
    if base_url:
        entry["base_url"] = base_url
    if api_key_env:
        entry["api_key_env"] = api_key_env
    if apis:
        entry["apis"] = _split(apis)
    if capabilities:
        entry["capabilities"] = _split(capabilities)
    models.append(entry)
    if _write(app, {"routing.models": models}):
        _key_hint(app, api_key_env)


def _key_hint(app: AppContext, env_name: str) -> None:
    """Say how to add a routed model's key when neither the environment nor
    the DefenseClaw .env has it."""
    if not env_name or os.environ.get(env_name):
        return
    from defenseclaw import config as config_module
    from defenseclaw import credentials

    try:
        data_dir = str(getattr(app.cfg, "data_dir", "") or config_module.default_data_path())
        present = credentials.resolve(env_name, data_dir).is_set
    except Exception:  # noqa: BLE001 - a hint only
        return
    if not present:
        ux.warn(f"{env_name} is not set; add it with: defenseclaw keys set {env_name}")


@routing_models.command("remove")
@click.argument("name")
@pass_ctx
def routing_models_remove(app: AppContext, name: str) -> None:
    """Remove a model alias (refused while a rule, budget or default uses it)."""
    _refuse_on_managed(["routing.models"])
    doc = _document()
    models = [m for m in _list(_routing(doc).get("models")) if not (isinstance(m, dict) and m.get("name") == name)]
    if len(models) == len(_list(_routing(doc).get("models"))):
        raise click.ClickException(f"routing.models has no alias {name}")
    _write(app, {"routing.models": models})


@routing_models.command("set-default")
@click.argument("name")
@click.option("--admin", is_flag=True, help="Set the organization default (routing.admin.default_alias).")
@pass_ctx
def routing_models_set_default(app: AppContext, name: str, admin: bool) -> None:
    """Use NAME when the classifier picks nothing."""
    key = "routing.admin.default_alias" if admin else "routing.default_alias"
    _refuse_on_managed([key])
    doc = _document()
    if name not in _aliases(doc):
        raise click.ClickException(f"routing.models has no alias {name}; see defenseclaw routing models list")
    if not admin and _is_locked(_locked(doc), "default_alias"):
        raise click.ClickException(
            "default_alias is locked by routing.admin.locked; change routing.admin.default_alias instead (--admin)"
        )
    _write(app, {key: name})


# ---------------- rules


@routing_cmd.group("rules")
def routing_rules() -> None:
    """List and edit the routing rules (routing.admin.rules, or a profile's routing with --profile)."""


def _rule_text(rule: dict[str, Any]) -> str:
    match = rule.get("match") or {}
    parts = [f"{k}={','.join(v) if isinstance(v, list) else v}" for k, v in match.items()]
    if rule.get("action") == "deny":
        action = "deny"
    else:
        action = " ".join(
            x
            for x in (
                f"allow {','.join(rule['allow'])}" if rule.get("allow") else "",
                f"default {rule['default']}" if rule.get("default") else "",
            )
            if x
        )
    return f"{rule.get('id', ''):<20} {' '.join(parts) or '-'} -> {action}"


@routing_rules.command("list")
@click.option("--profile", default="", help="Show this guardrail profile's routing overlay instead.")
@click.option("--json", "as_json", is_flag=True, help="Print JSON.")
@pass_ctx
def routing_rules_list(app: AppContext, profile: str, as_json: bool) -> None:
    """List the rules in the order they are written (all matching rules apply)."""
    try:
        doc = _document()
    except click.ClickException:
        if not _managed():
            raise
        doc = None
    if doc is None:
        # A user on a managed device sees only the rules that apply to them.
        answer, error = _ask_gateway(app, "GET", "/api/v1/routing/effective")
        if error:
            raise click.ClickException(error)
        rules = answer.get("rules", []) if isinstance(answer, dict) else []
        if as_json:
            _emit_json({"rules": rules, "scope": "own"})
        else:
            for r in rules:
                click.echo(_rule_text(r))
        return
    if profile:
        overlay = (((doc.get("guardrail") or {}).get("profiles") or {}).get(profile) or {}).get("routing") or {}
        if as_json:
            _emit_json(overlay)
        else:
            click.echo(json.dumps(overlay, indent=2) if overlay else f"Profile {profile} has no routing overlay.")
        return
    rules = _list(_admin(doc).get("rules"))
    locked = _is_locked(_locked(doc), "rules")
    if as_json:
        _emit_json({"rules": rules, "locked": locked, "lint": _lint(doc)})
        return
    if not rules:
        click.echo("No rules. Add one: defenseclaw routing rules add ID --groups G --allow ALIAS")
    for i, rule in enumerate(rules):
        click.echo(f"{i + 1:>3}. " + _rule_text(rule) + ("  (locked)" if locked else ""))
    for note in _lint(doc):
        ux.warn(note)


def _lint(doc: dict[str, Any]) -> list[str]:
    """Plain warnings about rules and budgets that do less than they look."""
    routing, admin = _routing(doc), _admin(doc)
    rules, budgets = _list(admin.get("rules")), _list(admin.get("budgets"))
    notes: list[str] = []
    if (rules or budgets) and not routing.get("enabled"):
        notes.append("routing is off: no rule or budget is applied until defenseclaw routing enable")
    managed = _managed()
    route_only = _list((routing.get("route_only") or {}).get("connectors"))
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        match = rule.get("match") or {}
        if match.get("severity_at_least") and route_only:
            notes.append(
                f"rule {rule.get('id')}: severity rules never apply to route-only connectors "
                f"({', '.join(route_only)}), which run no guardrail scan"
            )
        if rule.get("action") == "deny" and not managed:
            notes.append(f"rule {rule.get('id')}: deny is reported, not enforced, on this (unmanaged) device")
        if (
            managed
            and rule.get("action") == "deny"
            and match.get("connectors")
            and not (match.get("users") or match.get("groups"))
        ):
            notes.append(
                f"rule {rule.get('id')}: a connector is chosen by the user, "
                "so a connector-only deny is policy, not a boundary"
            )
    for budget in budgets:
        if not isinstance(budget, dict):
            continue
        if str(budget.get("on_exceed")) == "deny" and not managed:
            notes.append(f"budget {budget.get('id')}: deny is reported, not enforced, on this (unmanaged) device")
        if budget.get("scope") == "group" and not managed:
            notes.append(f"budget {budget.get('id')}: a group budget counts only this device's user here")
    obs = doc.get("observability") or {}
    tokenomics = obs.get("tokenomics") or {}
    if budgets and not (tokenomics.get("enabled") and (tokenomics.get("local_store") or {}).get("enabled")):
        notes.append("budgets need observability.tokenomics.enabled and observability.tokenomics.local_store.enabled")
    priced = {
        (str(p.get("provider")), str(p.get("model")))
        for p in _list((obs.get("pricing") or {}).get("models"))
        if isinstance(p, dict)
    }
    for m in _list(routing.get("models")):
        if isinstance(m, dict) and budgets and not _priced(priced, str(m.get("provider")), str(m.get("model"))):
            notes.append(
                f"model {m.get('name')} has no price in observability.pricing: its calls do not count toward budgets"
            )
    return notes


def _priced(priced: set[tuple[str, str]], provider: str, model: str) -> bool:
    for p, m in priced:
        if p == provider and (m == model or (m.endswith("*") and model.startswith(m[:-1]))):
            return True
    return False


@routing_rules.command("add")
@click.argument("rule_id")
@click.option("--groups", multiple=True, help="Directory groups (comma separated or repeated).")
@click.option("--users", multiple=True, help="Users (UPN, DOMAIN\\user, account name, uid or SID).")
@click.option("--connectors", multiple=True, help="Connectors, for example codex.")
@click.option("--agents", multiple=True, help="Agent identities (agt-...).")
@click.option("--categories", multiple=True, help="Classifier categories, for example code.")
@click.option(
    "--severity-at-least",
    type=click.Choice(SEVERITIES, case_sensitive=False),
    default=None,
    help="Match when the guardrail rates the prompt at least this severe.",
)
@click.option("--allow", "allow", multiple=True, help="Aliases the matched requests may use.")
@click.option("--default", "default", default="", help="Alias to use when nothing else allowed was chosen.")
@click.option("--deny", is_flag=True, help="Refuse the matched requests (managed devices only).")
@click.option("--message", default="", help="Refusal text of a deny rule.")
@click.option("--at", "position", type=int, default=0, help="Insert at this 1-based position (default: last).")
@click.option("--profile", default="", help="Edit guardrail.profiles.<name>.routing instead (allow/default only).")
@pass_ctx
def routing_rules_add(
    app: AppContext,
    rule_id: str,
    groups,
    users,
    connectors,
    agents,
    categories,
    severity_at_least,
    allow,
    default: str,
    deny: bool,
    message: str,
    position: int,
    profile: str,
) -> None:
    """Add a rule. Every matching rule applies: a deny wins and allow lists intersect."""
    if profile:
        key = f"guardrail.profiles.{profile}.routing"
        _refuse_on_managed([key])
        overlay: dict[str, Any] = {}
        if allow:
            overlay["allowed_aliases"] = _split(allow)
        if default:
            overlay["default_alias"] = default
        if not overlay or deny:
            raise click.UsageError(
                "a profile overlay takes --allow and/or --default (its profile assignment does the matching)"
            )
        _write(app, {key + "." + k: v for k, v in overlay.items()})
        return
    _refuse_on_managed([ADMIN_RULES_KEY])
    match = {
        k: _split(v)
        for k, v in (
            ("groups", groups),
            ("users", users),
            ("connectors", connectors),
            ("agents", agents),
            ("categories", categories),
        )
        if v
    }
    if severity_at_least:
        match["severity_at_least"] = severity_at_least.upper()
    if not match:
        raise click.UsageError(
            "name what the rule matches: --groups, --users, --connectors, --agents, --categories or --severity-at-least"
        )
    rule: dict[str, Any] = {"id": rule_id, "match": match}
    if deny:
        if allow or default:
            raise click.UsageError("--deny refuses the request; leave out --allow and --default")
        rule["action"] = "deny"
        if message:
            rule["message"] = message
    else:
        if message:
            raise click.UsageError("--message is only for --deny")
        if allow:
            rule["allow"] = _split(allow)
        if default:
            rule["default"] = default
    doc = _document()
    rules = copy.deepcopy(_list(_admin(doc).get("rules")))
    if any(isinstance(r, dict) and r.get("id") == rule_id for r in rules):
        raise click.ClickException(f"routing.admin.rules already has {rule_id}")
    index = len(rules) if position <= 0 else min(position - 1, len(rules))
    rules.insert(index, rule)
    _write(app, {ADMIN_RULES_KEY: rules})


@routing_rules.command("remove")
@click.argument("rule_id")
@click.option("--profile", default="", help="Remove guardrail.profiles.<name>.routing instead.")
@pass_ctx
def routing_rules_remove(app: AppContext, rule_id: str, profile: str) -> None:
    """Remove a rule (or, with --profile, a profile's routing overlay; RULE_ID is ignored)."""
    if profile:
        _write(app, {}, unset=[f"guardrail.profiles.{profile}.routing"])
        return
    _refuse_on_managed([ADMIN_RULES_KEY])
    rules = _list(_admin(_document()).get("rules"))
    kept = [r for r in rules if not (isinstance(r, dict) and r.get("id") == rule_id)]
    if len(kept) == len(rules):
        raise click.ClickException(f"routing.admin.rules has no rule {rule_id}")
    if kept:
        _write(app, {ADMIN_RULES_KEY: kept})
    else:
        _write(app, {}, unset=[ADMIN_RULES_KEY])


@routing_rules.command("move")
@click.argument("rule_id")
@click.option("--to", "position", type=int, required=True, help="New 1-based position.")
@pass_ctx
def routing_rules_move(app: AppContext, rule_id: str, position: int) -> None:
    """Move a rule (order picks the default when several rules match)."""
    _refuse_on_managed([ADMIN_RULES_KEY])
    rules = copy.deepcopy(_list(_admin(_document()).get("rules")))
    found = [i for i, r in enumerate(rules) if isinstance(r, dict) and r.get("id") == rule_id]
    if not found:
        raise click.ClickException(f"routing.admin.rules has no rule {rule_id}")
    rule = rules.pop(found[0])
    rules.insert(max(0, min(position - 1, len(rules))), rule)
    _write(app, {ADMIN_RULES_KEY: rules})


# ---------------- budgets


@routing_cmd.group("budgets")
def routing_budgets() -> None:
    """List and edit spend budgets (routing.admin.budgets); spend is counted on this device."""


@routing_budgets.command("list")
@click.option("--json", "as_json", is_flag=True, help="Print JSON.")
@pass_ctx
def routing_budgets_list(app: AppContext, as_json: bool) -> None:
    """List budgets with the spend so far in this period (yours, or everyone's for an administrator)."""
    answer, error = _ask_gateway(app, "GET", "/api/v1/routing/budgets")
    spend = {b.get("id"): b for b in (answer or {}).get("budgets", [])} if isinstance(answer, dict) else {}
    try:
        configured = _list(_admin(_document()).get("budgets"))
    except click.ClickException:
        if not _managed():
            raise
        configured = list(spend.values())
    rows = []
    for b in configured:
        if not isinstance(b, dict):
            continue
        live = spend.get(b.get("id")) or {}
        rows.append({**b, **{k: live[k] for k in ("spent_usd", "percent_used", "resets_at", "exceeded", "seed") if k in live}})
    if as_json:
        _emit_json({"budgets": rows, "live": not error, "error": error or None})
        return
    if not rows:
        click.echo(
            "No budgets. Add one: defenseclaw routing budgets add ID --scope user "
            "--subject '*' --period day --limit-usd 20 --on-exceed warn"
        )
    for r in rows:
        used = (
            f"{r['spent_usd']:.2f}"
            if isinstance(r.get("spent_usd"), (int, float))
            else (f"{r['percent_used']:.0f}%" if isinstance(r.get("percent_used"), (int, float)) else "?")
        )
        click.echo(
            f"{r.get('id', ''):<16} {r.get('scope')}:{r.get('subject'):<14} "
            f"{used}/{r.get('limit_usd')} USD per {r.get('period')}"
            f" -> {r.get('on_exceed')}" + (f"  resets {r['resets_at']}" if r.get("resets_at") else "")
        )
    if error:
        ux.warn(f"spend not shown: {error}")
    for r in rows:
        seed = str(r.get("seed") or "")
        if seed and seed != "seeded":
            ux.warn(f"budget {r.get('id')}: spend {seed}")


@routing_budgets.command("add")
@click.argument("budget_id")
@click.option("--scope", type=click.Choice(SCOPES), required=True)
@click.option(
    "--subject", required=True, help="user: a user or * (each user); group: one group; connector: a connector or *."
)
@click.option("--period", type=click.Choice(PERIODS), required=True, help="UTC calendar window; a week starts Monday.")
@click.option("--limit-usd", type=float, required=True)
@click.option("--on-exceed", required=True, help="warn, deny (managed devices only) or downgrade:<alias>[,<alias>].")
@pass_ctx
def routing_budgets_add(
    app: AppContext, budget_id: str, scope: str, subject: str, period: str, limit_usd: float, on_exceed: str
) -> None:
    """Add a budget."""
    _refuse_on_managed([ADMIN_BUDGETS_KEY])
    doc = _document()
    budgets = copy.deepcopy(_list(_admin(doc).get("budgets")))
    if any(isinstance(b, dict) and b.get("id") == budget_id for b in budgets):
        raise click.ClickException(f"routing.admin.budgets already has {budget_id}")
    budgets.append(
        {
            "id": budget_id,
            "scope": scope,
            "subject": subject,
            "period": period,
            "limit_usd": limit_usd,
            "on_exceed": on_exceed,
        }
    )
    if _write(app, {ADMIN_BUDGETS_KEY: budgets}) and on_exceed == "deny" and not _managed():
        ux.warn("deny budgets are reported, not enforced, on an unmanaged device")


@routing_budgets.command("remove")
@click.argument("budget_id")
@pass_ctx
def routing_budgets_remove(app: AppContext, budget_id: str) -> None:
    """Remove a budget."""
    _refuse_on_managed([ADMIN_BUDGETS_KEY])
    budgets = _list(_admin(_document()).get("budgets"))
    kept = [b for b in budgets if not (isinstance(b, dict) and b.get("id") == budget_id)]
    if len(kept) == len(budgets):
        raise click.ClickException(f"routing.admin.budgets has no budget {budget_id}")
    if kept:
        _write(app, {ADMIN_BUDGETS_KEY: kept})
    else:
        _write(app, {}, unset=[ADMIN_BUDGETS_KEY])


# ---------------- pricing


@routing_cmd.group("pricing")
def routing_pricing() -> None:
    """Show and edit the price table (observability.pricing) that computes cost."""


@routing_pricing.command("show")
@click.option("--json", "as_json", is_flag=True, help="Print JSON.")
def routing_pricing_show(as_json: bool) -> None:
    """Show the price table."""
    pricing = (_document().get("observability") or {}).get("pricing") or {}
    if as_json:
        _emit_json(pricing)
        return
    if not pricing:
        click.echo(
            "No price table: cost is not computed. Set one: defenseclaw "
            "routing pricing set PROVIDER/MODEL --input X --output Y"
        )
        return
    click.echo(f"Version {pricing.get('version', '?')}  (USD per million tokens)")
    for p in _list(pricing.get("models")):
        if isinstance(p, dict):
            click.echo(
                f"  {p.get('provider')}/{p.get('model'):<32} in {p.get('input_per_mtok')} "
                f" out {p.get('output_per_mtok')}"
                + (f"  cache read {p['cache_read_per_mtok']}" if p.get("cache_read_per_mtok") is not None else "")
            )


def _next_version(current: str, today: _dt.date | None = None) -> str:
    """<YYYY-MM-DD>.<n>: n counts edits on the same day."""
    stamp = (today or _dt.datetime.now(_dt.timezone.utc).date()).isoformat()
    head, _, tail = str(current or "").partition(".")
    if head == stamp and tail.isdigit():
        return f"{stamp}.{int(tail) + 1}"
    return f"{stamp}.1"


@routing_pricing.command("set")
@click.argument("target", metavar="PROVIDER/MODEL")
@click.option("--input", "input_price", type=float, required=True, help="USD per million input tokens.")
@click.option("--output", "output_price", type=float, required=True, help="USD per million output tokens.")
@click.option("--cache-read", type=float, default=None)
@click.option("--cache-write", type=float, default=None)
@click.option("--reasoning", type=float, default=None)
@pass_ctx
def routing_pricing_set(
    app: AppContext,
    target: str,
    input_price: float,
    output_price: float,
    cache_read: float | None,
    cache_write: float | None,
    reasoning: float | None,
) -> None:
    """Add or change one model's prices (bumps the table version)."""
    _refuse_on_managed(["observability.pricing"])
    provider, sep, model = target.partition("/")
    if not sep or not provider or not model:
        raise click.UsageError("name the model as PROVIDER/MODEL, for example anthropic/claude-sonnet-5-5")
    pricing = copy.deepcopy((_document().get("observability") or {}).get("pricing") or {})
    entry: dict[str, Any] = {
        "provider": provider,
        "model": model,
        "input_per_mtok": input_price,
        "output_per_mtok": output_price,
    }
    for key, value in (
        ("cache_read_per_mtok", cache_read),
        ("cache_write_per_mtok", cache_write),
        ("reasoning_per_mtok", reasoning),
    ):
        if value is not None:
            entry[key] = value
    models = [
        p
        for p in _list(pricing.get("models"))
        if not (isinstance(p, dict) and p.get("provider") == provider and p.get("model") == model)
    ]
    models.append(entry)
    _write(
        app,
        {
            "observability.pricing.models": models,
            "observability.pricing.version": _next_version(str(pricing.get("version") or "")),
        },
    )


@routing_pricing.command("import")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@pass_ctx
def routing_pricing_import(app: AppContext, path: str) -> None:
    """Replace the price table with a YAML or JSON file shaped like observability.pricing."""
    import yaml

    _refuse_on_managed(["observability.pricing"])
    with open(path, encoding="utf-8") as stream:
        table = yaml.safe_load(stream)
    if isinstance(table, dict) and "pricing" in table and isinstance(table["pricing"], dict):
        table = table["pricing"]
    if not isinstance(table, dict) or not isinstance(table.get("models"), list):
        raise click.ClickException(
            f"{path} must hold a mapping with a models list (the shape of observability.pricing)"
        )
    current = str(((_document().get("observability") or {}).get("pricing") or {}).get("version") or "")
    table.setdefault("version", _next_version(current))
    _write(app, {"observability.pricing": table})


# ---------------- test / explain / usage


@routing_cmd.command("test")
@click.argument("prompt")
@click.option("--connector", default="", help="Test as this connector (default: none).")
@click.option("--as-profile", default="", help="Test with this guardrail profile's overlay.")
@click.option("--as-user", default="", help="Test as this user (administrators only; facts are simulated).")
@click.option("--json", "as_json", is_flag=True, help="Print JSON.")
@pass_ctx
def routing_test(app: AppContext, prompt: str, connector: str, as_profile: str, as_user: str, as_json: bool) -> None:
    """Dry run: which model PROMPT would go to and why. No model is called."""
    if len(prompt.encode("utf-8")) > 8192:
        raise click.UsageError("the prompt must be at most 8 KiB")
    payload = {"prompt": prompt, "connector": connector, "profile": as_profile, "user": as_user}
    answer, error = _ask_gateway(app, "POST", "/api/v1/routing/test", json=payload, timeout=10)
    if error:
        raise click.ClickException(error)
    if as_json:
        _emit_json(answer)
        return
    a = answer or {}
    click.echo(
        f"Category:   {a.get('category') or '-'}"
        + (
            f" (confidence {a['confidence']:.2f})"
            if isinstance(a.get("confidence"), (int, float)) and a.get("confidence", -1) >= 0
            else ""
        )
    )
    click.echo(f"Candidate:  {a.get('candidate_alias') or '-'}")
    if a.get("filtered_by"):
        click.echo(
            f"Narrowed:   by {a['filtered_by']}" + (f" (rules {', '.join(a['rule_ids'])})" if a.get("rule_ids") else "")
        )
    click.echo(
        f"Result:     {a.get('outcome')}"
        + (f" -> {a['selected_alias']} ({a.get('selected_model', '')})" if a.get("selected_alias") else "")
    )
    if a.get("estimated_cost_usd") is not None:
        click.echo(
            f"Est. cost:  {a['estimated_cost_usd']:.4f} USD (estimate from the prompt length; no model was called)"
        )
    if a.get("simulated"):
        click.echo(f"Simulated:  {', '.join(a['simulated'])}")
    for w in a.get("warnings", []):
        ux.warn(w)


@routing_cmd.command("explain")
@click.argument("request_id")
@click.option("--json", "as_json", is_flag=True, help="Print JSON.")
@pass_ctx
def routing_explain(app: AppContext, request_id: str, as_json: bool) -> None:
    """Why a recent call went where it went (the gateway keeps the last 256 decisions)."""
    from urllib.parse import quote

    answer, error = _ask_gateway(app, "GET", "/api/v1/routing/explain/" + quote(request_id, safe=""))
    if error:
        raise click.ClickException(error)
    if as_json:
        _emit_json(answer)
        return
    a = answer or {}
    click.echo(f"{a.get('time')}  {a.get('connector', '')}  {a.get('api_family', '')}")
    click.echo(f"Requested:  {a.get('requested_model') or '-'}")
    click.echo(
        f"Outcome:    {a.get('outcome')}"
        + (f" -> {a['selected_alias']} ({a.get('selected_model', '')})" if a.get("selected_alias") else "")
    )
    for label, key in (("Category", "category"), ("Source", "source")):
        if a.get(key):
            click.echo(f"{label + ':':<12}{a[key]}")
    for label, key in (("Reasons", "reasons"), ("Rules", "rule_ids"), ("Warnings", "warnings")):
        if a.get(key):
            click.echo(f"{label + ':':<12}{', '.join(a[key])}")


def _since(value: str) -> str:
    if value and value[-1] in "hd" and value[:-1].isdigit():
        return value
    raise click.BadParameter("use a number of hours or days, for example 24h or 7d")


@routing_cmd.command("usage")
@click.option("--by", "group_by", type=click.Choice(USAGE_BY), default="model", show_default=True)
@click.option("--since", default="7d", show_default=True, callback=lambda _c, _p, v: _since(v), help="24h, 7d, 30d ...")
@click.option("--json", "as_json", is_flag=True, help="Print JSON.")
@pass_ctx
def routing_usage(app: AppContext, group_by: str, since: str, as_json: bool) -> None:
    """Tokens, calls and cost (yours, or everyone's for an administrator)."""
    answer, error = _ask_gateway(app, "GET", "/api/v1/usage", params={"by": group_by, "since": since})
    if error:
        raise click.ClickException(error)
    if as_json:
        _emit_json(answer)
        return
    rows = (answer or {}).get("rows", []) if isinstance(answer, dict) else []
    scope = (answer or {}).get("scope", "own") if isinstance(answer, dict) else "own"
    click.echo(f"Usage by {group_by}, last {since} ({'everyone' if scope == 'all' else 'yours'}):")
    if not rows:
        click.echo("  no recorded calls (usage recording is observability.tokenomics)")
    for r in rows:
        cost = r.get("cost_usd")
        cost_text = f"{cost:.4f} USD" if isinstance(cost, (int, float)) else "cost unknown"
        basis = f" ({r['cost_basis']})" if r.get("cost_basis") else ""
        click.echo(
            f"  {str(r.get('key', '-')):<28} {r.get('calls', 0):>6} calls  in {r.get('input_tokens', 0):>9}  "
            f"out {r.get('output_tokens', 0):>8}  {cost_text}{basis}"
        )


# ---------------- setup (guided)


@routing_cmd.command("setup")
@click.option(
    "--classifier", type=click.Choice(CLASSIFIERS), default=None, help="rules (built in), systemone or vllm_sr."
)
@click.option("--yes", "-y", is_flag=True, help="Accept the defaults and the models already configured.")
@click.option("--model", "add_models", multiple=True, metavar="ALIAS=PROVIDER/MODEL",
              help="Add a model alias without prompting (repeat for more).")
@pass_ctx
def routing_setup(app: AppContext, classifier: str | None, yes: bool, add_models: tuple[str, ...]) -> None:
    """Guided setup: models, classifier and default model, then a test."""
    _refuse_on_managed(["routing"])
    doc = _document()
    routing = _routing(doc)
    models = copy.deepcopy(_list(routing.get("models")))
    for spec in add_models:
        alias, _, target = spec.partition("=")
        provider, _, model_id = target.partition("/")
        if not (alias and provider and model_id):
            raise click.UsageError(
                f"--model {spec}: use ALIAS=PROVIDER/MODEL, for example fast=anthropic/claude-haiku-4-5"
            )
        if alias not in [str(m.get("name")) for m in models if isinstance(m, dict)]:
            models.append({"name": alias, "provider": provider, "model": model_id})
    interactive = not yes and sys.stdin.isatty()
    if classifier is None:
        classifier = (
            click.prompt("Classifier", type=click.Choice(CLASSIFIERS), default="rules")
            if interactive
            else str(routing.get("classifier") or "rules")
        )
    while interactive and click.confirm("Add a model alias?", default=not models):
        name = click.prompt("  Alias (for example fast or coder)")
        provider = click.prompt("  Provider", default="anthropic")
        model_id = click.prompt("  Model id")
        env = click.prompt("  API key environment variable", default=KEY_ENV_HINTS.get(provider, ""), show_default=True)
        entry = {"name": name, "provider": provider, "model": model_id}
        if env:
            entry["api_key_env"] = env
            _key_hint(app, env)
        models.append(entry)
    if not models:
        raise click.ClickException(
            "routing needs at least one model: rerun setup, or defenseclaw "
            "routing models add NAME --provider P --model M"
        )
    aliases = [str(m.get("name")) for m in models]
    default = str(routing.get("default_alias") or aliases[0])
    if interactive:
        default = click.prompt(
            "Default model", type=click.Choice(aliases), default=default if default in aliases else aliases[0]
        )
    changes: dict[str, Any] = {
        "routing.classifier": classifier,
        "routing.models": models,
        "routing.default_alias": default,
        "routing.enabled": True,
    }
    if not _write(app, changes):
        click.echo("Routing already has these settings.")
    answer, error = _ask_gateway(
        app,
        "POST",
        "/api/v1/routing/test",
        json={"prompt": "Write a Python function that reverses a list."},
        timeout=10,
    )
    if error:
        click.echo(f'Test skipped: {error}. Run later: defenseclaw routing test "<prompt>"')
    elif isinstance(answer, dict):
        click.echo(f"Test: a coding prompt goes to {answer.get('selected_alias') or answer.get('outcome')}.")


# ---------------- doctor


def doctor_rows() -> list[tuple[str, str]]:
    """(status, detail) rows for defenseclaw doctor: one pass row, or one warn
    row per Lint note; [] when no routing.admin rules or budgets exist."""
    try:
        doc = _document()
    except click.ClickException:
        return []
    admin = _admin(doc)
    rules, budgets = _list(admin.get("rules")), _list(admin.get("budgets"))
    if not rules and not budgets:
        return []
    notes = _lint(doc)
    if not notes:
        return [("pass", f"{len(rules)} rule(s), {len(budgets)} budget(s)")]
    return [("warn", note) for note in notes]
