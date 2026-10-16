#!/usr/bin/env python3
"""
DefenseClaw Shield — Frida-based SSL interception launcher.

Spawns a target process, injects Frida hooks on SSL_write/SSL_read,
and routes intercepted plaintext to the shield daemon for inspection.

NO TLS termination. NO CA certificates. NO proxy configuration.
Reads plaintext directly from process memory.

Usage:
  python3 shield_inject.py -- python3 my_agent.py
  python3 shield_inject.py -- claude "fix the bug"
  python3 shield_inject.py -- curl https://api.anthropic.com/...
"""

import frida
import os
import subprocess
import sys
import time

HOOKS_JS = os.path.join(os.path.dirname(__file__), "ssl_hooks.js")
SOCKET_PATH = os.environ.get(
    "SHIELD_SOCKET",
    os.path.expanduser("~/.defenseclaw-shield/shield.sock"),
)


def on_message(message, data):
    if message["type"] == "send":
        payload = message["payload"]
        if isinstance(payload, dict):
            if payload.get("action") == "BLOCKED":
                print(f"[shield] BLOCKED {payload.get('direction', '?')} to {payload.get('peer', '?')}", file=sys.stderr)
            elif "status" in payload:
                print(f"[shield] {payload['status']}", file=sys.stderr)
    elif message["type"] == "error":
        print(f"[shield] Frida error: {message.get('description', message)}", file=sys.stderr)


def main():
    # Parse args: everything after "--" is the command.
    args = sys.argv[1:]
    if "--" in args:
        idx = args.index("--")
        args = args[idx + 1:]

    if not args:
        print("Usage: shield_inject.py [--] <command> [args...]", file=sys.stderr)
        sys.exit(1)

    # Read the hooks JS and substitute the socket path.
    with open(HOOKS_JS) as f:
        script_source = f.read()
    script_source = script_source.replace("SHIELD_SOCKET_PLACEHOLDER", SOCKET_PATH)

    # Check daemon is running.
    if not os.path.exists(SOCKET_PATH):
        print(f"[shield] Daemon not running (no socket at {SOCKET_PATH})", file=sys.stderr)
        print(f"[shield] Start it with: ~/.defenseclaw-shield/defenseclaw-shield start", file=sys.stderr)
        sys.exit(1)

    print(f"[shield] Target: {' '.join(args)}", file=sys.stderr)
    print(f"[shield] Socket: {SOCKET_PATH}", file=sys.stderr)
    print(f"[shield] Mode:   Frida SSL hook (no TLS termination)", file=sys.stderr)
    print(file=sys.stderr)

    import shutil

    # Resolve full path for the executable.
    exe = shutil.which(args[0]) or args[0]
    spawn_args = [exe] + args[1:]

    # Spawn the process suspended, inject hooks, then resume.
    device = frida.get_local_device()
    pid = device.spawn(spawn_args)
    session = device.attach(pid)
    script = session.create_script(script_source)
    script.on("message", on_message)
    script.load()
    device.resume(pid)

    print(f"[shield] Injected into PID {pid}, monitoring SSL traffic...", file=sys.stderr)
    print(file=sys.stderr)

    # Wait for the process to exit.
    try:
        while True:
            time.sleep(0.5)
            # Check if process is still alive.
            try:
                os.kill(pid, 0)
            except OSError:
                break
    except KeyboardInterrupt:
        pass

    try:
        device.kill(pid)
    except frida.ProcessNotFoundError:
        pass


if __name__ == "__main__":
    main()
