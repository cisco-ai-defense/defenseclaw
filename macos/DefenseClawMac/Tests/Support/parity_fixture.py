#!/usr/bin/env python3
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

"""Disposable UI fixture. Never starts a DefenseClaw gateway or scans the host.
Run with --serve; stdout reports a temporary root, CLI and loopback port.
The mock CLI only reads/writes files under that root. Policy/config catalogs
use the separately selected real runtime interpreter in read-only mode.
"""
import datetime
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def cli():
    root = Path(__file__).resolve().parent.parent
    args = sys.argv[1:]
    with (root / "commands.jsonl").open("a") as handle:
        handle.write(json.dumps(args) + "\n")
    if Path(sys.argv[0]).name == "openshell":
        if (root / "inspection-fail").exists():
            print("Fixture gateway unavailable")
            sys.exit(1)
        sandbox = "fixture-codex"
        rule = {"binaries": [{"path": "/usr/bin/curl"}], "endpoints": [{"host": "api.example.invalid", "port": 443, "access": "read-only"}]}
        policy = {"version": 1, "filesystem_policy": {"read_only": ["/usr"], "read_write": ["/work", "/tmp"]},
                  "landlock": {"compatibility": "hard_requirement"}, "network_policies": {"api": rule},
                  "process": {"run_as_user": "501", "run_as_group": "20"}}
        if "logs" in args:
            source = args[args.index("--source") + 1]
            now = time.time()
            print(f"[{now}] [{source}] [OCSF] NET:OPEN DENIED /usr/bin/curl -> blocked.example.invalid:443 [policy:api] [reason:no matching policy]")
            print(f"[{now - 1}] [{source}] [OCSF] NET:OPEN ALLOWED /usr/bin/curl -> api.example.invalid:443 [policy:api]")
            print(f"[{now - 2}] [{source}] [ERROR] Provider authentication failed; reconnect inside the sandbox")
        elif "list" in args:
            print(json.dumps({"revisions": [{"sandbox": sandbox, "scope": "sandbox", "version": n, "status": "loaded",
                 "created_at_ms": int(time.time() * 1000), "loaded_at_ms": int(time.time() * 1000), "hash": "fixture digest"} for n in [2, 1]], "next_page_token": ""}))
        else:
            version = int(args[args.index("--rev") + 1]) if "--rev" in args else 2
            if version == 1: policy["filesystem_policy"]["read_write"] = ["/tmp"]
            if "--full" in args: policy["network_policies"]["provider"] = {"endpoints": [{"host": "provider.example.invalid", "port": 443}]}
            print(json.dumps({"sandbox": sandbox, "scope": "global" if "--global" in args else "sandbox", "version": version,
                              "active_version": 2, "status": "effective", "policy_source": "sandbox", "hash": "fixture digest", "policy": policy}))
    elif args[:3] == ["sandbox", "policy", "explain"]:
        print(json.dumps({"pack": "balanced", "profile": "balanced", "network_mode": "proxy", "admin": {"configured": True, "authority": "organization"},
                          "settings": [{"key": "egress.allow", "value": "api.example.invalid", "source": "pack", "origin": "balanced"},
                                       {"key": "allow_yolo", "value": "false", "source": "organization", "origin": "managed policy"}]}))
    elif args[:2] == ["sandbox", "destinations"]:
        print(json.dumps({"name": "fixture-codex", "destinations": [{"host": "api.example.invalid", "contacted": True, "blocked": 0}, {"host": "blocked.example.invalid", "contacted": False, "blocked": 2}]}))
    elif args in (["--version"], ["version"]):
        version_file = root / "runtime-version"
        print("defenseclaw, version " + (version_file.read_text().strip() if version_file.exists() else "1.0.0"))
    elif args[:1] == ["upgrade"]:
        assert args == ["upgrade", "--yes", "--version", "1.0.1"], "unexpected upgrade arguments"
        assert os.environ.get("DEFENSECLAW_APP_PATH") == "none", "Mac app must be preserved"
        for key, target in [("DEFENSECLAW_HOME", root), ("DEFENSECLAW_CONFIG", root / "config.yaml"), ("DEFENSECLAW_VENV", root / ".venv")]:
            assert Path(os.environ[key]).resolve() == target.resolve(), "selected installation must be preserved"
        print("Fixture runtime upgrade in progress", flush=True)
        time.sleep(2)
        if (root / "fail-upgrade").exists():
            print("Error: fixture upgrade failed before activation", flush=True)
            sys.exit(1)
        if not (root / "unchanged-upgrade").exists():
            (root / "runtime-version").write_text("1.0.1")
        if (root / "source-switch-fixture").exists() and not (root / "unchanged-upgrade").exists():
            release_cli = root / ".venv/bin/defenseclaw"
            release_cli.parent.mkdir(parents=True, exist_ok=True)
            source = (root / "bin/defenseclaw").read_text().replace(
                "root = Path(__file__).resolve().parent.parent", "root = Path(" + repr(str(root)) + ")", 1)
            release_cli.write_text(source)
            release_cli.chmod(0o700)
            if not (root / "unchanged-launcher").exists():
                launcher = root / ".local/bin/defenseclaw"
                launcher.unlink(missing_ok=True)
                launcher.symlink_to(release_cli)
        print("Fixture runtime upgrade completed", flush=True)
    elif "--help" in args:
        print("Usage: defenseclaw [OPTIONS] COMMAND\nCommands:\n  redaction  Redaction policy\n  codex  Codex\n  amp  Amp\n  scan  Scan\n  enable  Enable\n  disable  Disable\n  selftest  Self-test\n  findings  Findings")
    elif args[:2] in (["sandbox", "setup"], ["sandbox", "doctor"]) or args[:3] == ["sandbox", "image", "build"]:
        stage = args[1]
        print("Fixture sandbox " + stage + " progress", flush=True)
        time.sleep(2)
        if (root / ("fail-sandbox-" + stage)).exists():
            print("Fixture sandbox " + stage + " failed", flush=True)
            sys.exit(1)
        print("Fixture sandbox " + stage + " completed", flush=True)
    elif args[:4] == ["sandbox", "pack", "list", "-o"]:
        print(json.dumps({"packs": [{"name": "open", "builtin": True, "profile": "open", "description": "Synthetic fixture sandbox pack"}]}))
    elif args[:2] == ["guardrail", "validate-pack"]:
        print('{"valid": true, "summary": {"rule_count": 10}}')
    elif len(args) >= 2 and args[0] in ("skill", "mcp", "plugin", "tool") and args[1] == "list":
        resource = args[0]
        key = {"skill": "skills", "mcp": "mcp_servers", "plugin": "plugins", "tool": "tools"}[resource]
        row = dict(name="Fixture " + resource, id="fixture-" + resource, connector="codex", description="Synthetic catalog row",
                   version="1.0", status="active", source="fixture", eligible=True, enabled=True,
                   transport="stdio", command="fixture-tool", actions={"install": "allow", "runtime": "enable"})
        print(json.dumps([{"connector": "codex", key: [row]}]))
    elif args[:2] == ["aibom", "scan"]:
        print(json.dumps([{"connector": "codex", "skills": [{"name": "Fixture skill", "path": str(root / "skill"), "eligible": True}],
                           "mcp_servers": [{"name": "Fixture MCP", "transport": "stdio"}], "plugins": [], "tools": [],
                           "agents": [], "models": [], "model_providers": [], "memory": [], "ide_plugins": [{"plugin_id": "fixture.assistant", "ide_product": "Fixture IDE", "user": "fixture", "version": "1.0", "enabled": "enabled", "is_ai": True}]}]))
    elif args[:1] == ["alerts"]:
        print(json.dumps([{"id": "fixture-alert", "timestamp": "2026-10-12T12:00:00Z", "severity": "HIGH", "action": "block", "target": "fixture tool", "connector": "codex", "details": "Synthetic policy block", "agent_identity_id": "fixture-agent", "decision": "blocked"}]))
    elif args[:2] == ["agent", "identities"]:
        print(json.dumps({"identities": [{"agent_id": "fixture-agent", "connector": "codex", "user": "fixture", "sessions_seen": 3}], "total": 1}))
    elif args[:3] == ["setup", "redaction", "status"]:
        print("Synthetic fixture: default sensitive; no external destinations. No real policy was read.")
    else:
        print("Fixture command completed; no production installation was changed.")


def serve():
    root = Path(tempfile.mkdtemp(prefix="defenseclawmac-parity-", dir="/private/tmp"))
    (root / "bin").mkdir()
    (root / "bin/defenseclaw").write_text(Path(__file__).read_text())
    (root / "bin/defenseclaw").chmod(0o755)
    (root / "bin/openshell").write_text(Path(__file__).read_text())
    (root / "bin/openshell").chmod(0o755)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    db = sqlite3.connect(root / "audit.db")
    db.execute("CREATE TABLE audit_events (id TEXT, timestamp TEXT, bucket TEXT, event_name TEXT, source TEXT, signal TEXT, severity TEXT, action TEXT, actor TEXT, details TEXT, connector TEXT, payload_json TEXT, projected_record_json TEXT, target TEXT)")
    for i, bucket in enumerate(("security.finding", "compliance.activity", "network.egress", "guardrail.evaluation")):
        record = {"message": "Synthetic fixture event", "severity": "HIGH", "action": "block", "connector": "codex"}
        db.execute("INSERT INTO audit_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (str(i), now, bucket, "fixture.event", "fixture", "logs", "HIGH", "block", "fixture", "Synthetic fixture detail", "codex", json.dumps(record), json.dumps(record), "codex:fixture"))
    db.commit()
    db.close()
    (root / "gateway.log").write_text("INFO Synthetic gateway ready\nWARN Synthetic fixture warning\n")
    (root / "watchdog.log").write_text("INFO Synthetic watchdog ready\n")
    signals = [{"product": "Codex", "vendor": "OpenAI", "category": "ai_cli", "detector": "binary", "state": "active", "confidence": 0.95},
               {"product": "Fixture Models", "vendor": "Fixture", "category": "local_model", "detector": "model_api", "state": "active", "confidence": 0.95,
                "model": {"id": "fixture/model", "status": "loaded", "format": "gguf", "modality": "text", "relevance": "primary", "owner_application": "Fixture Models", "discovery_confidence": 0.96}}]
    sandbox = {"name": "fixture-codex", "harness": "codex", "phase": "ready", "pack": "open", "profile": "open", "workdir_mode": "copy", "project": str(root), "egress": {"blocked": 1, "destinations": 2}, "hooks": {"tool_calls": 3}}
    replies = {
        "/status": {"policy": {"effective_digest": "fixture-policy-digest", "generation": 9}},
        "/api/v1/guardrail/profiles/resolve": {"profile": "fixture-profile", "effective": {"mode": "observe", "rule_pack": "default", "block_at": "HIGH", "alert_at": "LOW"}},
        "/health": {"state": "running", "version": "1.0.0", "uptime_ms": 100000, "guardrail": {"state": "running"}, "watcher": {"state": "running"}, "connectors": [{"name": "codex", "state": "running", "requests": 5}]},
        "/api/v1/ai-usage": {"enabled": True, "signals": signals, "summary": {"active_signals": 2, "files_scanned": 10, "scanned_at": now}},
        "/api/v1/ai-usage/runtime": {"enabled": True, "planes": [{"name": "agent actions", "running": True, "available": True}], "findings": [], "last_poll": now},
        "/api/v1/sandbox/status": {"enabled": True, "available": True, "running": 1, "sandboxes": 1, "gateway": {"name": "fixture", "workspace": "default", "version": "0.1.3", "driver": "vm"}},
        "/api/v1/sandbox/sandboxes": {"sandboxes": [sandbox]},
        "/api/v1/sandbox/approvals": {"approvals": [{"id": "fixture-ask", "sandbox": "fixture-codex", "host": "example.invalid", "port": 443, "kind": "egress", "status": "pending"}]},
        "/api/v1/sandbox/activity": {"events": [{"seq": 1, "kind": "egress.blocked", "sandbox": "fixture-codex", "host": "example.invalid", "unblockable": True, "message": "Synthetic block"}]},
    }
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            path = self.path.split("?")[0]
            if (root / "offline").exists():
                self.send_response(503); self.end_headers(); return
            payload = replies.get(path, {})
            body = json.dumps(payload).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        def do_POST(self):
            self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 4096))
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(b'{"ok":true}')
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    (root / "config.yaml").write_text(f"config_version: 9\ndata_dir: {root}\naudit_db: {root}/audit.db\npolicy_dir: {root}/policies\nclaw:\n  mode: codex\nguardrail:\n  enabled: true\n  mode: observe\n  connectors:\n    codex:\n      enabled: true\n      mode: observe\ngateway:\n  host: 127.0.0.1\n  port: {port}\n  api_port: {port}\nopenshell:\n  enabled: true\nai_discovery:\n  enabled: true\nobservability:\n  defaults:\n    redaction_profile: sensitive\n")
    print(json.dumps({"root": str(root), "port": port, "cli": str(root / "bin/defenseclaw")}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    if sys.argv[1:] == ["--serve"]:
        serve()
    else:
        cli()
