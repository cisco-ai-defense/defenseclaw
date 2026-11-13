# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Read-only check of OpenClaw's DefenseClaw plugin config against its manifest."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from jsonschema import Draft202012Validator, SchemaError

from defenseclaw import openclaw_json5

# Start of the issue for an openclaw.json that is neither JSON nor JSON5. The
# fix is in the file, not in the plugin config, so callers pick their next
# step with openclaw_plugin_config_unreadable.
UNREADABLE_CONFIG = "OpenClaw config cannot be read as JSON5"


def openclaw_plugin_config_unreadable(issue: str | None) -> bool:
    """True when ``issue`` says openclaw.json has a syntax error or cannot be opened."""
    return bool(issue) and issue.startswith(UNREADABLE_CONFIG)


def _has_external_schema_reference(value: object) -> bool:
    if isinstance(value, dict):
        if "$ref" in value or "$dynamicRef" in value:
            return True
        return any(_has_external_schema_reference(child) for child in value.values())
    if isinstance(value, list):
        return any(_has_external_schema_reference(child) for child in value)
    return False


def openclaw_plugin_config_issue(config_file: str, openclaw_home: str) -> str | None:
    """Return a plain issue when OpenClaw would reject the plugin config.

    The installed plugin manifest is the schema owner. A missing manifest is
    handled by the separate plugin installation check.
    """
    config_path = Path(os.path.expanduser(config_file))
    try:
        document = openclaw_json5.load_file(str(config_path))
    except FileNotFoundError:
        return None
    except openclaw_json5.OpenClawConfigSyntaxError as exc:
        # OpenClaw reads openclaw.json as JSON5, so only a real syntax error
        # lands here; name where it is (never the text around it).
        return f"{UNREADABLE_CONFIG}: {exc}"
    except (OSError, UnicodeError):
        return f"{UNREADABLE_CONFIG}: the file cannot be opened or is not UTF-8"

    if not isinstance(document, dict):
        return "OpenClaw config is not a JSON object"
    plugins = document.get("plugins")
    entries = plugins.get("entries") if isinstance(plugins, dict) else None
    entry = entries.get("defenseclaw") if isinstance(entries, dict) else None
    if not isinstance(entry, dict) or "config" not in entry:
        return None

    manifest_path = Path(os.path.expanduser(openclaw_home)) / "extensions" / "defenseclaw" / "openclaw.plugin.json"
    try:
        info = manifest_path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        return "OpenClaw plugin manifest cannot be read"
    if not stat.S_ISREG(info.st_mode) or info.st_size > 256 * 1024:
        return "OpenClaw plugin manifest is not a regular file within the size limit"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        schema = manifest["configSchema"] if manifest["id"] == "defenseclaw" else None
        if _has_external_schema_reference(schema):
            return "OpenClaw plugin manifest config schema has unsupported references"
        Draft202012Validator.check_schema(schema)
        if not Draft202012Validator(schema).is_valid(entry["config"]):
            return "plugins.entries.defenseclaw.config has values the installed plugin schema rejects"
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError, SchemaError):
        return "OpenClaw plugin manifest has no usable DefenseClaw config schema"
    return None


def configured_openclaw_plugin_config_issue(cfg: object) -> str | None:
    """Check the OpenClaw paths selected by DefenseClaw's current config."""
    claw = getattr(cfg, "claw", None)
    home = str(getattr(claw, "home_dir", "") or "~/.openclaw")
    config_file = str(getattr(claw, "config_file", "") or os.path.join(home, "openclaw.json"))
    return openclaw_plugin_config_issue(config_file, home)


# Plugin hook modes setup writes to plugins.entries.defenseclaw.config.hookMode
# (internal/gateway/connector/openclaw_hook_mode.go). No key is the proxy mode.
OPENCLAW_HOOK_MODES = ("hybrid", "native")


def configured_openclaw_hook_mode(cfg: object) -> str:
    # The OpenClaw plugin hook mode in openclaw.json: hybrid, native or proxy.
    claw = getattr(cfg, "claw", None)
    home = str(getattr(claw, "home_dir", "") or "~/.openclaw")
    config_file = str(getattr(claw, "config_file", "") or os.path.join(home, "openclaw.json"))
    try:
        document = openclaw_json5.load_file(os.path.expanduser(config_file))
    except (OSError, UnicodeError, openclaw_json5.OpenClawConfigSyntaxError):
        return "proxy"
    plugins = document.get("plugins") if isinstance(document, dict) else None
    entries = plugins.get("entries") if isinstance(plugins, dict) else None
    entry = entries.get("defenseclaw") if isinstance(entries, dict) else None
    if entry is None:
        # Setup has not written the plugin entry yet (the gateway writes it
        # after setup saves): the mode it will write (rel-1-0-10 GAP-0113).
        return expected_openclaw_hook_mode(cfg)
    plugin_cfg = entry.get("config") if isinstance(entry, dict) else None
    mode = plugin_cfg.get("hookMode") if isinstance(plugin_cfg, dict) else None
    return mode if mode in OPENCLAW_HOOK_MODES else "proxy"


def expected_openclaw_hook_mode(cfg: object) -> str:
    # Mirrors Go connector.ResolveOpenClawHookMode: hooks.mode proxy wins;
    # Windows is native; an OpenClaw known to be older than 2026.8.35, or of
    # unknown version, is proxy; otherwise hybrid.
    from defenseclaw.connector_contracts import openclaw_lacks_native_hooks
    from defenseclaw.platform_support import uses_guardrail_proxy

    if str(_openclaw_connector_block().get("hooks", {}).get("mode", "") or "").strip().lower() == "proxy":
        return "proxy"
    if not uses_guardrail_proxy("openclaw"):
        return "native"
    version = _cached_openclaw_version(cfg)
    if not version or openclaw_lacks_native_hooks(version):
        return "proxy"
    return "hybrid"


def _cached_openclaw_version(cfg: object) -> str:
    # The OpenClaw version setup and doctor last probed (agent_discovery.json).
    import json

    data_dir = str(getattr(cfg, "data_dir", "") or "")
    if not data_dir:
        return ""
    try:
        with open(os.path.join(data_dir, "agent_discovery.json"), encoding="utf-8") as stream:
            agents = json.load(stream).get("agents") or {}
        return str((agents.get("openclaw") or {}).get("version") or "")
    except (OSError, ValueError, AttributeError):
        return ""


def openclaw_hook_mode_detail(mode: str) -> str:
    # One line for doctor and status.
    return {
        "hybrid": "native plugin hooks and the guardrail proxy",
        "native": "native plugin hooks only (no guardrail proxy on this host)",
    }.get(mode, "guardrail proxy with the tool check (OpenClaw before 2026.8.35, or hooks.mode proxy)")


def _openclaw_document(cfg: object) -> dict:
    claw = getattr(cfg, "claw", None)
    home = str(getattr(claw, "home_dir", "") or "~/.openclaw")
    config_file = str(getattr(claw, "config_file", "") or os.path.join(home, "openclaw.json"))
    try:
        document = openclaw_json5.load_file(os.path.expanduser(config_file))
    except (OSError, UnicodeError, openclaw_json5.OpenClawConfigSyntaxError):
        return {}
    return document if isinstance(document, dict) else {}


def openclaw_install_policy_state(cfg: object) -> str:
    # ours: security.installPolicy runs the DefenseClaw admission command;
    # operator: another installPolicy is configured; none: no installPolicy.
    security = _openclaw_document(cfg).get("security")
    policy = security.get("installPolicy") if isinstance(security, dict) else None
    if not isinstance(policy, dict) or not policy.get("enabled"):
        return "none"
    exec_cfg = policy.get("exec") if isinstance(policy.get("exec"), dict) else {}
    args = exec_cfg.get("args") if isinstance(exec_cfg.get("args"), list) else []
    return "ours" if args[-3:] == ["connector", "openclaw", "install-policy"] else "operator"


def _openclaw_connector_block() -> dict:
    # connectors.openclaw in config.yaml, or {} when it cannot be read.
    from defenseclaw.config import config_path

    try:
        import yaml

        with open(config_path(), encoding="utf-8") as stream:
            raw = yaml.safe_load(stream) or {}
        connectors = raw.get("connectors") if isinstance(raw, dict) else None
        openclaw = connectors.get("openclaw") if isinstance(connectors, dict) else None
    except Exception:  # noqa: BLE001 - doctor reads what it can
        return {}
    return openclaw if isinstance(openclaw, dict) else {}


def openclaw_operator_admin_off() -> bool:
    # Mirrors Go Config.OpenClawOperatorAdmin: only an explicit false turns it
    # off; OpenClaw is then not told to disable a blocked skill, plugin or MCP
    # server (DefenseClaw admission and inspect still enforce the block).
    return _openclaw_connector_block().get("operator_admin") is False


def openclaw_install_policy_wanted(cfg: object) -> bool:
    # Mirrors Go Config.OpenClawInstallPolicyOn: on and off are what they
    # say; auto is on in the strict tier and on managed installs.
    setting = str(_openclaw_connector_block().get("install_policy") or "").strip().lower()
    if setting in ("on", "off"):
        return setting == "on"
    from defenseclaw.config import _is_managed_enterprise_mode

    if _is_managed_enterprise_mode(getattr(cfg, "deployment_mode", "")):
        return True
    guardrail = getattr(cfg, "guardrail", None)
    tier = ""
    if guardrail is not None and hasattr(guardrail, "hook_policy_tier"):
        tier = guardrail.hook_policy_tier("openclaw")
    return tier == "strict"
