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

"""Guardrail integration — OpenClaw config patching for the Go guardrail proxy.

Patches ~/.openclaw/openclaw.json to route LLM traffic through the
DefenseClaw guardrail proxy (a pure Go reverse proxy).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path


def patch_openclaw_config(
    openclaw_config_file: str,
    model_name: str,  # kept for API compat — no longer used (fetch interceptor handles routing)
    proxy_port: int,  # kept for API compat — no longer used
    master_key: str,  # kept for API compat — no longer used
    original_model: str,
) -> str | None:
    """Register the DefenseClaw plugin in openclaw.json.

    The fetch interceptor handles all traffic routing transparently —
    no provider entry or model redirection is needed. This function only
    registers the plugin so OpenClaw loads it on startup.
    """
    _ = model_name, proxy_port, master_key  # unused — fetch interceptor handles routing
    path = _expand(openclaw_config_file)

    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    _backup(path)

    prev_model = (
        cfg.get("agents", {}).get("defaults", {}).get("model", {}).get("primary", "")
    )

    # Clear model history — OpenClaw shows all entries in agents.defaults.models
    # as selectable models in the UI. Since the fetch interceptor handles all
    # traffic regardless of model, there is no need to show the history.
    # OpenClaw repopulates this as models are used, so we clear on each setup.
    cfg.setdefault("agents", {}).setdefault("defaults", {}).pop("models", None)

    plugins = cfg.setdefault("plugins", {})
    allow = plugins.setdefault("allow", [])
    if "defenseclaw" not in allow:
        allow.append("defenseclaw")

    # Re-enable plugin entry (may have been disabled by restore_openclaw_config).
    entries = plugins.setdefault("entries", {})
    if "defenseclaw" not in entries:
        entries["defenseclaw"] = {"enabled": True}
    else:
        entries["defenseclaw"]["enabled"] = True

    oc_home = os.path.dirname(path)
    install_path = os.path.join(oc_home, "extensions", "defenseclaw")
    load = plugins.setdefault("load", {})
    paths = load.setdefault("paths", [])
    if install_path not in paths:
        paths.append(install_path)

    with open(path, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")

    _install_codeguard_skill_deferred(openclaw_config_file)

    return prev_model or original_model


def restore_openclaw_config(openclaw_config_file: str, original_model: str) -> bool:
    """Remove the DefenseClaw plugin registration from openclaw.json.

    The fetch interceptor required no model or provider changes, so there is
    nothing to revert — just remove the plugin entries.
    """
    path = _expand(openclaw_config_file)

    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False

    _backup(path)

    # Remove leftover defenseclaw provider entry if present from older setups.
    if "models" in cfg and "providers" in cfg["models"]:
        cfg["models"]["providers"].pop("defenseclaw", None)
        cfg["models"]["providers"].pop("litellm", None)

    if "plugins" in cfg:
        plugins = cfg["plugins"]
        # Remove from allow list
        allow = plugins.get("allow", [])
        if "defenseclaw" in allow:
            allow.remove("defenseclaw")
        # Disable in entries (stops fetch interceptor from loading)
        entries = plugins.get("entries", {})
        if "defenseclaw" in entries:
            entries["defenseclaw"]["enabled"] = False
        # Remove from load paths
        oc_home = os.path.dirname(path)
        install_path = os.path.join(oc_home, "extensions", "defenseclaw")
        paths = plugins.get("load", {}).get("paths", [])
        if install_path in paths:
            paths.remove(install_path)

    with open(path, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")

    return True


def install_openclaw_plugin(source_dir: str, openclaw_home: str) -> tuple[str, str]:
    """Install the built DefenseClaw plugin into OpenClaw.

    The *source_dir* is typically ``~/.defenseclaw/extensions/defenseclaw``
    (a stable staging directory populated by ``make plugin-install`` or
    future PyPI packaging).

    Tries ``openclaw plugins install <source_dir>`` first (copies files
    into OpenClaw's extensions directory and registers in openclaw.json).
    Falls back to a manual file copy + config patching if the ``openclaw``
    CLI is not available.

    Returns:
        ("cli", "")          — installed via openclaw CLI
        ("manual", reason)   — fell back to manual copy, reason explains why
        ("error", reason)    — both methods failed
        ("", "")             — plugin not built (dist/index.js missing)
    """
    dist_entry = os.path.join(source_dir, "dist", "index.js")
    if not os.path.isfile(dist_entry):
        return ("", "")

    oc_home = _expand(openclaw_home)
    oc_config = os.path.join(oc_home, "openclaw.json")

    # --- Try openclaw CLI (no -l: copies files, registers in config) ---
    cli_error = ""
    try:
        target_dir = os.path.join(oc_home, "extensions", "defenseclaw")
        if os.path.isdir(target_dir):
            shutil.rmtree(target_dir)

        _remove_from_plugins_allow(oc_config, "defenseclaw")

        result = subprocess.run(
            ["openclaw", "plugins", "install", source_dir],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            return ("cli", "")
        cli_error = (result.stderr or result.stdout or "").strip()
    except FileNotFoundError:
        cli_error = "openclaw CLI not found on PATH"
    except subprocess.TimeoutExpired:
        cli_error = "timed out"

    # --- Fallback: manual copy + config registration ---
    target_dir = os.path.join(oc_home, "extensions", "defenseclaw")

    try:
        if os.path.isdir(target_dir):
            shutil.rmtree(target_dir)
        os.makedirs(target_dir, exist_ok=True)

        shutil.copy2(os.path.join(source_dir, "package.json"), target_dir)

        manifest = os.path.join(source_dir, "openclaw.plugin.json")
        if os.path.isfile(manifest):
            shutil.copy2(manifest, target_dir)

        shutil.copytree(os.path.join(source_dir, "dist"), os.path.join(target_dir, "dist"))

        src_nm = os.path.join(source_dir, "node_modules")
        if os.path.isdir(src_nm):
            dst_nm = os.path.join(target_dir, "node_modules")
            os.makedirs(dst_nm, exist_ok=True)
            for dep in ("js-yaml", "argparse"):
                src = os.path.join(src_nm, dep)
                if os.path.isdir(src):
                    shutil.copytree(src, os.path.join(dst_nm, dep))

        _register_plugin_in_config(oc_config, source_dir)

        return ("manual", cli_error)
    except OSError as exc:
        return ("error", f"manual copy failed: {exc}")


def uninstall_openclaw_plugin(openclaw_home: str) -> str:
    """Uninstall the DefenseClaw plugin from OpenClaw.

    Tries ``openclaw plugins uninstall defenseclaw`` first, falls back
    to removing the extensions directory and config entries manually.

    Returns:
        "cli"    — uninstalled via openclaw CLI
        "manual" — removed directory manually
        ""       — plugin was not installed
        "error"  — removal failed (permissions, etc.)
    """
    oc_home = _expand(openclaw_home)
    target_dir = os.path.join(oc_home, "extensions", "defenseclaw")
    oc_config = os.path.join(oc_home, "openclaw.json")
    is_installed = os.path.isdir(target_dir) or os.path.islink(target_dir)

    if not is_installed:
        _unregister_plugin_from_config(oc_config)
        return ""

    _remove_from_plugins_allow(oc_config, "defenseclaw")

    try:
        result = subprocess.run(
            ["openclaw", "plugins", "uninstall", "defenseclaw"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return "cli"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: remove directory + config entries
    try:
        if os.path.islink(target_dir):
            os.unlink(target_dir)
        elif os.path.isdir(target_dir):
            shutil.rmtree(target_dir)
        _unregister_plugin_from_config(oc_config)
        return "manual"
    except OSError:
        return "error"


def detect_azure_endpoints(openclaw_config_file: str) -> dict[str, str]:
    """Read Azure OpenAI base URLs from openclaw.json providers.

    Returns {provider_name: base_url} for any provider whose baseUrl contains
    'openai.azure.com'. Written to ~/.defenseclaw/.env during setup so the
    guardrail proxy can forward Azure requests to the correct endpoint without
    any manual configuration.
    """
    path = _expand(openclaw_config_file)
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}

    result = {}
    for name, prov in cfg.get("models", {}).get("providers", {}).items():
        base_url = prov.get("baseUrl", "")
        if "openai.azure.com" in base_url:
            result[name] = base_url
    return result


def detect_current_model(openclaw_config_file: str) -> tuple[str, str]:
    """Read the current model from openclaw.json. Returns (model_id, provider_prefix)."""
    path = _expand(openclaw_config_file)
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return "", ""

    primary = (
        cfg.get("agents", {}).get("defaults", {}).get("model", {}).get("primary", "")
    )
    if "/" in primary:
        provider, model_id = primary.split("/", 1)
        return primary, provider
    return primary, ""



def detect_api_key_env(model: str) -> str:
    """Guess the API key env var from the model string."""
    lower = model.lower()
    if "anthropic" in lower or "claude" in lower:
        return "ANTHROPIC_API_KEY"
    if "azure" in lower:
        return "AZURE_OPENAI_API_KEY"
    if "openrouter" in lower:
        return "OPENROUTER_API_KEY"
    if "openai" in lower or "gpt" in lower or "o1" in lower:
        return "OPENAI_API_KEY"
    if "gemini" in lower or "google" in lower:
        return "GOOGLE_API_KEY"
    if "bedrock" in lower:
        return "AWS_ACCESS_KEY_ID"
    return "LLM_API_KEY"


def model_to_proxy_name(model: str) -> str:
    """Derive a short model alias from a full model string like 'anthropic/claude-opus-4-5'."""
    name = model.split("/")[-1] if "/" in model else model
    for prefix in ("anthropic-", "openai-", "google-", "azure-", "openrouter-", "gemini-", "gemini-openai-"):
        name = name.removeprefix(prefix)
    return name




# Known provider prefixes for model name heuristics.
KNOWN_PROVIDERS = ["anthropic", "openai", "openrouter", "azure", "gemini", "gemini-openai"]


def guess_provider(model: str) -> str:
    """Best-effort guess of the provider from a bare model name (no / prefix)."""
    lower = model.lower()
    if lower.startswith("claude"):
        return "anthropic"
    if lower.startswith(("gpt", "o1", "o3", "o4")):
        return "openai"
    if lower.startswith("gemini"):
        return "gemini"
    return ""



# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _derive_master_key(device_key_file: str) -> str:
    """Derive a deterministic master key from the device key file.

    Tries the given path first, then the default ~/.defenseclaw/device.key.
    Only falls back to a static key if neither exists.
    """
    candidates = [device_key_file]
    default_path = os.path.join(str(Path.home()), ".defenseclaw", "device.key")
    if _expand(device_key_file) != default_path:
        candidates.append(default_path)

    import hmac

    for candidate in candidates:
        path = _expand(candidate)
        try:
            with open(path, "rb") as f:
                data = f.read()
            digest = hmac.new(b"defenseclaw-proxy-master-key", data, hashlib.sha256).hexdigest()[:32]
            return f"sk-dc-{digest}"
        except OSError:
            continue
    raise RuntimeError(
        f"Device key not found: {device_key_file}\n"
        f"  Run 'defenseclaw init' to generate a device key."
    )


def _unregister_plugin_from_config(openclaw_config: str) -> None:
    """Remove defenseclaw plugin entries from openclaw.json."""
    path = _expand(openclaw_config)
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return

    plugins = cfg.get("plugins", {})
    changed = False

    entries = plugins.get("entries", {})
    if "defenseclaw" in entries:
        del entries["defenseclaw"]
        changed = True

    installs = plugins.get("installs", {})
    if "defenseclaw" in installs:
        install_path = installs["defenseclaw"].get("installPath", "")
        del installs["defenseclaw"]
        changed = True

        paths = plugins.get("load", {}).get("paths", [])
        if install_path in paths:
            paths.remove(install_path)

    if changed:
        with open(path, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
            f.write("\n")


def _register_plugin_in_config(openclaw_config: str, source_dir: str) -> None:
    """Register the defenseclaw plugin in openclaw.json (manual fallback).

    Mirrors what ``openclaw plugins install`` does: adds entries to
    plugins.load.paths, plugins.installs, and plugins.entries so
    OpenClaw discovers and loads the plugin.
    """
    path = _expand(openclaw_config)
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return

    plugins = cfg.setdefault("plugins", {})

    # plugins.entries — enable the plugin
    entries = plugins.setdefault("entries", {})
    if "defenseclaw" not in entries:
        entries["defenseclaw"] = {"enabled": True}

    # plugins.load.paths — tell OpenClaw where to find the code
    oc_home = os.path.dirname(path)
    install_path = os.path.join(oc_home, "extensions", "defenseclaw")
    load = plugins.setdefault("load", {})
    paths = load.setdefault("paths", [])
    if install_path not in paths:
        paths.append(install_path)

    # plugins.installs — record install metadata
    version = "0.0.0"
    try:
        pkg_json = os.path.join(source_dir, "package.json")
        with open(pkg_json) as f:
            version = json.load(f).get("version", version)
    except (OSError, json.JSONDecodeError):
        pass

    from datetime import datetime, timezone
    installs = plugins.setdefault("installs", {})
    installs["defenseclaw"] = {
        "source": "path",
        "sourcePath": source_dir,
        "installPath": install_path,
        "version": version,
        "installedAt": datetime.now(timezone.utc).isoformat(),
    }

    with open(path, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _remove_from_plugins_allow(openclaw_config: str, plugin_id: str) -> None:
    """Remove a plugin id from plugins.allow in openclaw.json (if present)."""
    path = _expand(openclaw_config)
    try:
        with open(path) as f:
            cfg = json.load(f)
    except (OSError, json.JSONDecodeError):
        return

    allow = cfg.get("plugins", {}).get("allow", [])
    if plugin_id not in allow:
        return

    allow.remove(plugin_id)
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _expand(p: str) -> str:
    if p.startswith("~/"):
        return str(Path.home() / p[2:])
    return p


def _backup(path: str) -> None:
    """Create a numbered backup of a file."""
    if not os.path.isfile(path):
        return
    bak = path + ".bak"
    if os.path.exists(bak):
        found = False
        for i in range(1, 100):
            candidate = f"{path}.bak.{i}"
            if not os.path.exists(candidate):
                bak = candidate
                found = True
                break
        if not found:
            import time
            bak = f"{path}.bak.{int(time.time() * 1000)}.{os.getpid()}"
    shutil.copy2(path, bak)


def _install_codeguard_skill_deferred(openclaw_config_file: str) -> None:
    """Install the CodeGuard skill when guardrail connects to OpenClaw.

    This handles the case where the user ran ``defenseclaw init`` before
    OpenClaw was installed, then later runs ``defenseclaw guardrail enable``.
    """
    try:
        from defenseclaw.codeguard_skill import ensure_codeguard_skill
        from defenseclaw.config import load

        cfg = load()
        ensure_codeguard_skill(cfg.claw_home_dir(), openclaw_config_file)
    except Exception:
        pass
