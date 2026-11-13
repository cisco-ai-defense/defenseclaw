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
    if str(_openclaw_connector_block().get("plugin_account") or "").strip():
        try:
            with open(os.path.expanduser(config_file), "rb"):
                pass
        except PermissionError:
            # Separate-user layout: openclaw.json belongs to the OpenClaw
            # account and is usually 0600; not an issue (rel-1-0-10 GAP-0180).
            return None
        except OSError:
            pass
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
    except PermissionError:
        # Separate-user layout: openclaw.json belongs to the OpenClaw account
        # (rel-1-0-10 GAP-0116). The mode is the one setup put in the block.
        return expected_openclaw_hook_mode(cfg)
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

    if not uses_guardrail_proxy("openclaw"):
        return "native"
    hooks = _openclaw_connector_block().get("hooks")
    if isinstance(hooks, dict) and str(hooks.get("mode") or "").strip().lower() == "proxy":
        return "proxy"
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


def openclaw_separate_user_notes(cfg: object) -> list[str]:
    # What setup says in the separate-user layout (connectors.openclaw
    # plugin_account) that the gateway cannot say itself: an openclaw.json
    # this account cannot read is not checked (GAP-0116), and an OpenClaw
    # this account cannot run gets the proxy mode (GAP-0139).
    block = _openclaw_connector_block()
    if not str(block.get("plugin_account") or "").strip():
        return []
    notes = []
    claw = getattr(cfg, "claw", None)
    home = str(getattr(claw, "home_dir", "") or "~/.openclaw")
    config_file = os.path.expanduser(str(getattr(claw, "config_file", "") or os.path.join(home, "openclaw.json")))
    merge = os.path.join(str(getattr(cfg, "data_dir", "") or ""), "openclaw-merge.json")
    try:
        with open(config_file, "rb"):
            pass
    except PermissionError:
        notes.append(
            f"This account cannot read {config_file}, so setup did not check it. When the gateway sets OpenClaw "
            f"up it saves the block to merge in {merge}: merge it and restart the OpenClaw gateway. "
            "defenseclaw status shows the hook mode as unverified until the plugin calls in."
        )
    except OSError:
        pass
    hooks = block.get("hooks") if isinstance(block.get("hooks"), dict) else {}  # hooks: null is {}
    if str(hooks.get("mode") or "").strip().lower() != "proxy" and not _cached_openclaw_version(cfg):
        notes.append(
            "This account could not run openclaw to read its version, so the block uses the proxy mode, without "
            "the native hooks or the prompt gate. Install OpenClaw where both accounts can run it (such as "
            "/usr/local/bin) and run setup again."
        )
    return notes


def openclaw_plugin_package_candidates(cfg: object | None = None) -> list[str]:
    # Where the OpenClaw plugin's package.json is: the administrator-installed
    # plugin_dir, then <claw.home_dir>/extensions/defenseclaw (GAP-0140).
    block = _openclaw_connector_block()
    plugin_dir = str(block.get("plugin_dir") or "").strip()
    if str(block.get("plugin_install") or "").strip().lower() == "external":
        # Only the administrator-installed folder: the OpenClaw home may
        # belong to another account, which could plant the evidence
        # (rel-1-0-10 REVIEW-4 P2-3).
        return [os.path.join(os.path.expanduser(plugin_dir), "package.json")] if plugin_dir else []
    out = []
    claw = getattr(cfg, "claw", None) if cfg is not None else None
    home = str(getattr(claw, "home_dir", "") or "") if claw is not None else ""
    if not home:
        home = _configured_claw_home()
    out.append(os.path.join(os.path.expanduser(home or "~/.openclaw"), "extensions", "defenseclaw", "package.json"))
    return out


def _configured_claw_home() -> str:
    # claw.home_dir in config.yaml, or "".
    from defenseclaw.config import config_path

    try:
        import yaml

        with open(config_path(), encoding="utf-8") as stream:
            raw = yaml.safe_load(stream) or {}
        claw = raw.get("claw") if isinstance(raw, dict) else None
        return str(claw.get("home_dir") or "") if isinstance(claw, dict) else ""
    except Exception:  # noqa: BLE001 - a lookup only
        return ""


# The plugin asks the gateway for its runtime settings every minute; three
# missed rounds mean OpenClaw no longer runs it.
OPENCLAW_PLUGIN_SEEN_FRESH_S = 180


def openclaw_plugin_evidence(cfg: object, health: object) -> tuple[str, str, bool]:
    """The OpenClaw hook mode as the running plugin reports it.

    Returns (mode, detail, seen). With the gateway down (no health document)
    it is the configured mode. With the gateway up, the mode counts only when
    the plugin called in within OPENCLAW_PLUGIN_SEEN_FRESH_S; otherwise the
    mode is "unverified" and the detail says what setup expects and what to
    do (rel-1-0-10 REVIEW-4 P1-1, P2-4).
    """
    from datetime import datetime, timezone

    expected = configured_openclaw_hook_mode(cfg)
    if not isinstance(health, dict):
        return expected, openclaw_hook_mode_detail(expected), False
    seen = health.get("openclaw_plugin")
    last = str(seen.get("last_seen_at") or "") if isinstance(seen, dict) else ""
    age = None
    if last:
        try:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(last.replace("Z", "+00:00"))).total_seconds()
        except ValueError:
            age = None
    if age is not None and age <= OPENCLAW_PLUGIN_SEEN_FRESH_S:
        mode = str(seen.get("hook_mode") or "") or expected
        return mode, openclaw_hook_mode_detail(mode), True
    step = "restart the OpenClaw gateway so it loads the DefenseClaw plugin"
    if str(_openclaw_connector_block().get("plugin_account") or "").strip():
        merge = os.path.join(str(getattr(cfg, "data_dir", "") or ""), "openclaw-merge.json")
        step = f"merge the block in {merge} into openclaw.json and " + step
    when = "has not called in since the gateway started" if age is None else f"last called in {int(age // 60)} min ago"
    return "unverified", f"expected {expected}; the OpenClaw plugin {when}: {step}", False


def openclaw_separate_user_teardown_note(cfg: object) -> str:
    # What the administrator removes from openclaw.json after setup remove in
    # the separate-user layout; the gateway prints it only to its own log
    # (rel-1-0-10 GAP-0083).
    block = _openclaw_connector_block()
    if not str(block.get("plugin_account") or "").strip():
        return ""
    claw = getattr(cfg, "claw", None)
    home = str(getattr(claw, "home_dir", "") or "~/.openclaw")
    config_file = str(getattr(claw, "config_file", "") or os.path.join(home, "openclaw.json"))
    plugin_dir = str(block.get("plugin_dir") or "").strip()
    return (
        f"DefenseClaw does not write {config_file} in the separate-user layout. As the OpenClaw account or an "
        "administrator, remove plugins.entries.defenseclaw, defenseclaw from plugins.allow if you added it, "
        f"{plugin_dir or 'the plugin_dir path'} from plugins.load.paths and a security.installPolicy that runs "
        "defenseclaw-gateway, then restart the OpenClaw gateway. Until then the plugin has no credential and blocks "
        "every tool call."
    )
