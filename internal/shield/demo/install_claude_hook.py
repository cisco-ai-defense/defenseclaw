#!/usr/bin/env python3
"""Install/uninstall the DefenseClaw Shield hook into Claude Code settings."""

import json
import os
import sys
import shutil

SETTINGS_PATH = os.path.expanduser("~/.claude/settings.json")
HOOK_SCRIPT = os.path.join(os.path.dirname(__file__), "claude_shield_hook.sh")

HOOK_ENTRY = {
    "hooks": [
        {
            "type": "command",
            "command": os.path.abspath(HOOK_SCRIPT),
            "timeout": 5,
        }
    ]
}


def load_settings():
    if os.path.exists(SETTINGS_PATH):
        with open(SETTINGS_PATH) as f:
            return json.load(f)
    return {}


def save_settings(data):
    backup = SETTINGS_PATH + ".shield-backup"
    if os.path.exists(SETTINGS_PATH) and not os.path.exists(backup):
        shutil.copy2(SETTINGS_PATH, backup)
        print(f"  Backup saved: {backup}")

    with open(SETTINGS_PATH, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def is_installed(settings):
    hooks = settings.get("hooks", {}).get("UserPromptSubmit", [])
    for entry in hooks:
        for h in entry.get("hooks", []):
            if "claude_shield_hook" in h.get("command", ""):
                return True
    return False


def install():
    settings = load_settings()

    if is_installed(settings):
        print("  Shield hook already installed in Claude Code.")
        return

    hooks = settings.setdefault("hooks", {})
    user_prompt_hooks = hooks.setdefault("UserPromptSubmit", [])
    user_prompt_hooks.append(HOOK_ENTRY)

    save_settings(settings)
    print(f"  Shield hook installed into Claude Code.")
    print(f"  Hook script: {os.path.abspath(HOOK_SCRIPT)}")
    print(f"  Settings:    {SETTINGS_PATH}")


def uninstall():
    settings = load_settings()

    if not is_installed(settings):
        print("  Shield hook not found in Claude Code settings.")
        return

    hooks = settings.get("hooks", {}).get("UserPromptSubmit", [])
    filtered = []
    for entry in hooks:
        entry_hooks = entry.get("hooks", [])
        clean = [h for h in entry_hooks if "claude_shield_hook" not in h.get("command", "")]
        if clean:
            entry["hooks"] = clean
            filtered.append(entry)
    settings["hooks"]["UserPromptSubmit"] = filtered

    if not settings["hooks"]["UserPromptSubmit"]:
        del settings["hooks"]["UserPromptSubmit"]

    save_settings(settings)
    print("  Shield hook removed from Claude Code.")

    backup = SETTINGS_PATH + ".shield-backup"
    if os.path.exists(backup):
        print(f"  Backup available: {backup}")


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "install"

    if action == "install":
        print("\n▸ Installing shield hook into Claude Code...")
        install()
    elif action == "uninstall":
        print("\n▸ Removing shield hook from Claude Code...")
        uninstall()
    else:
        print(f"Usage: {sys.argv[0]} [install|uninstall]")
        sys.exit(1)
    print()
