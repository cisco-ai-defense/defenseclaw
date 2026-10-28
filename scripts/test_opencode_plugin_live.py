#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Opt-in OpenCode CLI smoke test with a fake model and gateway.

Usage: python3 scripts/test_opencode_plugin_live.py --binary /path/to/opencode --major 2
Requires an already downloaded vendor binary. Installs nothing, uses no model
credentials, and isolates all vendor configuration/data under a temporary home.
The gateway verdict is synthetic: this tests the vendor's enforcement boundary,
not a live guardrail provider. Supported on POSIX hosts.
The fake HTTP transport substitutes for native connected-peer verification;
the connector transport suites check that boundary separately.
"""

import argparse
import json
import os
import re
import shlex
import signal
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def check(binary: str, blocked: bool, registration: str, tool: str) -> None:
    with tempfile.TemporaryDirectory(prefix="defenseclaw-opencode-live-") as temporary:
        root = Path(temporary).resolve()
        project = root / "project"
        project.mkdir()
        marker = project / "sentinel"
        if tool in ("read", "edit"):
            marker.write_text("before\n")
        tool_args = {
            "shell": {
                "command": "/usr/bin/touch " + shlex.quote(str(marker)),
                "workdir": str(project),
                "timeout": 10000,
                "background": False,
            },
            "write": {"path": str(marker), "content": "after\n"},
            "read": {"path": str(marker), "offset": 1, "limit": 1},
            "edit": {"path": str(marker), "oldString": "before", "newString": "after", "replaceAll": False},
            "patch": {"patchText": f"*** Begin Patch\n*** Add File: {marker}\n+after\n*** End Patch"},
        }[tool]
        payloads = []
        model_calls = 0

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                nonlocal model_calls
                length = int(self.headers.get("Content-Length", "0"))
                if length > 2 * 1024 * 1024:
                    self.send_error(413)
                    return
                data = json.loads(self.rfile.read(length))
                if self.path == "/api/v1/opencode/hook":
                    payloads.append(data)
                    deny = blocked and data.get("hook_event_name") == "tool.execute.before"
                    verdict = {
                        "action": "block" if deny else "allow",
                        "mode": "action",
                        "hook_output": {
                            "decision": "deny" if deny else "allow",
                            "reason": "DefenseClaw smoke-test denial",
                        },
                    }
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(verdict).encode())
                    return
                model_calls += 1
                done = any(m.get("role") == "tool" for m in data.get("messages", [])) or model_calls > 2
                names = [item.get("function", {}).get("name") for item in data.get("tools", [])]
                if not done and tool not in names:
                    self.send_error(422, f"Expected native {tool} tool is unavailable: {names}")
                    return
                delta = (
                    {"content": "Fixture complete."}
                    if done
                    else {
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call_fixture",
                                "type": "function",
                                "function": {
                                    "name": tool,
                                    "arguments": json.dumps(tool_args),
                                },
                            }
                        ]
                    }
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                for value, finish in [(delta, None), ({}, "stop" if done else "tool_calls")]:
                    chunk = {
                        "id": "chatcmpl-fixture",
                        "object": "chat.completion.chunk",
                        "created": int(time.time()),
                        "model": "fixture",
                        "choices": [{"index": 0, "delta": value, "finish_reason": finish}],
                    }
                    self.wfile.write(("data: " + json.dumps(chunk) + "\n\n").encode())
                self.wfile.write(b"data: [DONE]\n\n")

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.server_address[1]
            config_dir = root / "config/opencode"
            config_dir.mkdir(parents=True)
            autoload = registration == "auto"
            plugin = config_dir / "plugins" if autoload else root / "plugin"
            plugin.mkdir()
            token = root / "token"
            token.write_text("a" * 64 + "\n")
            token.chmod(0o600)
            template = (
                Path(__file__).resolve().parents[1]
                / "internal/gateway/connector/testdata/bridge_host/opencode-plugin.js"
            )
            values = {
                "APIAddr": f"127.0.0.1:{port}",
                "TokenFileJS": str(token),
                "FailMode": "closed",
                "ServiceUID": "0",
            }
            rendered = re.sub(
                r"\{\{\.(\w+)\}\}", lambda m: json.dumps(values.get(m[1], ""))[1:-1], template.read_text()
            )
            # This tests the vendor callback boundary against a synthetic
            # HTTP gateway. Native connected-peer verification is exercised
            # by the connector transport tests, as in writeRenderedPlugin.
            rendered = rendered.replace('const DC_PER_USER_NATIVE_POST = "1"', 'const DC_PER_USER_NATIVE_POST = ""')
            rendered = rendered.replace(
                'throw defenseclawPeerError("the DefenseClaw gateway listener has no account proof");',
                'return fetch("http://" + DC_API_ADDR + path, init);',
            )
            (plugin / ("defenseclaw.js" if autoload else "index.js")).write_text(rendered)
            settings = {"baseURL": f"http://127.0.0.1:{port}/v1", "apiKey": "fixture"}
            # The pinned vendor exposes patch for GPT-family models and
            # edit/write for other models. Both use this same local fake API.
            model_id = "gpt-5" if tool == "patch" else "fixture"
            models = {model_id: {"name": "Fixture", "limit": {"context": 32768, "output": 1024}}}
            config = {
                "share": "disabled",
                "plugins": [] if autoload else [str(plugin)],
                "update": "disable",
                "snapshots": False,
                "permissions": [{"action": "*", "resource": "*", "effect": "allow"}],
                "providers": {
                    "fixture": {"package": "@ai-sdk/openai-compatible", "settings": settings, "models": models}
                },
            }
            (config_dir / "opencode.json").write_text(json.dumps(config))
            env = {
                key: value for key, value in os.environ.items() if key in ("PATH", "TMPDIR", "LANG", "USER", "SHELL")
            }
            env.update(
                {
                    "HOME": str(root / "home"),
                    "XDG_DATA_HOME": str(root / "data"),
                    "XDG_STATE_HOME": str(root / "state"),
                    "XDG_CACHE_HOME": str(root / "cache"),
                    "XDG_CONFIG_HOME": str(root / "config"),
                    "OPENCODE_CONFIG_DIR": str(config_dir),
                    "OPENCODE_TEST_MANAGED_CONFIG_DIR": str(root / "managed"),
                    "OPENCODE_DISABLE_AUTOUPDATE": "1",
                }
            )
            command = [
                binary,
                "run",
                "--standalone",
                "--format",
                "json",
                "--model",
                f"fixture/{model_id}",
                "--title",
                "DefenseClaw fixture",
                "Run the fixture tool once.",
            ]
            process = subprocess.Popen(
                command,
                cwd=project,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=90)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                if process.poll() is None:
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=10)
            assert process.returncode == 0, (stdout[-4000:], stderr[-4000:])
            before = [p for p in payloads if p.get("hook_event_name") == "tool.execute.before"]
            assert len(before) == 1, f"expected one before hook, got {len(before)}"
            assert before[0]["arguments_authoritative"] is True
            assert before[0]["tool_name"] == tool
            assert before[0]["tool_input"] == tool_args
            if tool == "read":
                assert marker.read_text() == "before\n"
            elif tool == "edit":
                assert marker.read_text() == ("before\n" if blocked else "after\n")
            else:
                assert marker.exists() is not blocked, f"blocked={blocked}, tool executed={marker.exists()}"
                if not blocked and tool != "shell":
                    assert marker.read_text() == "after\n"
            if blocked:
                assert "DefenseClaw smoke-test denial" in stdout + stderr
            else:
                after = [p for p in payloads if p.get("hook_event_name") == "tool.execute.after"]
                assert len(after) == 1
                assert after[0]["tool_call_id"] == before[0]["tool_call_id"]
                result = after[0]["tool_response"]
                assert result["opencode_v2_status"] == "completed"
                if tool == "shell":
                    assert result["output"]["exit"] == 0
                elif tool == "read":
                    assert "before" in json.dumps(result)
            print(
                f"OpenCode V2 {tool} {registration} {'block' if blocked else 'allow'}: "
                "PASS (native before hook, execution, result)"
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=lambda value: str(Path(value).resolve(strict=True)))
    parser.add_argument("--major", default=2, type=int, choices=(2,))
    parser.add_argument("--registration", choices=("auto", "configured", "both"), default="both")
    parser.add_argument("--tool", choices=("shell", "read", "write", "edit", "patch", "all"), default="all")
    args = parser.parse_args()
    if os.name != "posix":
        parser.error("this smoke test requires a POSIX host")
    for registration in ("auto", "configured") if args.registration == "both" else (args.registration,):
        for tool in ("shell", "read", "write", "edit", "patch") if args.tool == "all" else (args.tool,):
            check(args.binary, blocked=True, registration=registration, tool=tool)
            check(args.binary, blocked=False, registration=registration, tool=tool)
