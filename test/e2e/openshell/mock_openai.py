#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Dependency-free mock of the OpenAI Responses API for Codex E2E tests.

  POST /v1/responses | /responses       streaming SSE (and non-streaming JSON)
  GET  /v1/models | /models             static list ({"data": [...], "models": [...]})
  anything else                          logged, 404 JSON error

Every request is appended to --log as one JSON line; --dump-dir stores full
bodies. Script file (JSON), selected by substring match against the last user
message text in the request "input":

  {
    "scenarios": [
      {"name": "default", "match": "",
       "turns": [
         {"shell": "echo hello-from-tool > /tmp/tool.txt"},
         {"text": "Done."}
       ]}
    ]
  }

A {"shell": "<cmd>"} turn is rendered against whatever shell tool the request
advertises: shell_command {"command": str}, exec_command {"cmd": str},
shell {"command": ["bash","-lc",str]}, or the built-in local_shell tool.
{"function_call": {"name": ..., "arguments": {...}}} emits a raw call.
Turn index = number of model-emitted items (function/custom/local-shell calls
and assistant messages) after the last user message.
"""

import argparse
import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

ARGS = None
LOCK = threading.Lock()
SEQ = [0]

DEFAULT_SCRIPT = {
    "scenarios": [
        {"name": "default", "match": "",
         "turns": [{"shell": "echo hello-from-tool > /tmp/tool.txt && cat /tmp/tool.txt"},
                   {"text": "Done: the marker file was written."}]}
    ]
}

MODEL_ITEMS = {"function_call", "custom_tool_call", "local_shell_call", "web_search_call"}


def load_script():
    if ARGS.script and os.path.exists(ARGS.script):
        with open(ARGS.script, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return DEFAULT_SCRIPT


def log_line(obj):
    line = json.dumps(obj)
    with LOCK:
        if ARGS.log:
            with open(ARGS.log, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        if not ARGS.quiet:
            sys.stderr.write(line[:2000] + "\n")
            sys.stderr.flush()


def item_text(item):
    content = item.get("content")
    if isinstance(content, str):
        return content
    out = []
    for part in content or []:
        if isinstance(part, dict) and part.get("type") in ("input_text", "output_text", "text"):
            out.append(part.get("text", ""))
    return "\n".join(out)


def position(items):
    last_user = -1
    for i, it in enumerate(items):
        if it.get("type", "message") == "message" and it.get("role") == "user":
            txt = item_text(it)
            if "<environment_context>" in txt and len(items) > i + 1:
                continue
            last_user = i
    if last_user < 0:
        return "", 0
    prompt = item_text(items[last_user])
    n = 0
    for it in items[last_user + 1:]:
        t = it.get("type", "message")
        if t in MODEL_ITEMS or (t == "message" and it.get("role") == "assistant"):
            n += 1
    return prompt, n


def tool_names(body):
    names = {}
    for t in body.get("tools") or []:
        if not isinstance(t, dict):
            continue
        kind = t.get("type")
        name = t.get("name") or (t.get("function") or {}).get("name") or kind
        names[name] = kind
    return names


def render_shell(cmd, tools, seq):
    call_id = "call_mock_%d_%s" % (seq, uuid.uuid4().hex[:6])
    if "shell_command" in tools:
        return {"type": "function_call", "name": "shell_command", "call_id": call_id,
                "arguments": json.dumps({"command": cmd, "timeout_ms": 30000})}
    if "exec_command" in tools:
        return {"type": "function_call", "name": "exec_command", "call_id": call_id,
                "arguments": json.dumps({"cmd": cmd, "yield_time_ms": 10000})}
    if "shell" in tools and tools["shell"] == "function":
        return {"type": "function_call", "name": "shell", "call_id": call_id,
                "arguments": json.dumps({"command": ["bash", "-lc", cmd], "timeout_ms": 30000})}
    if "local_shell" in tools or tools.get("local_shell") == "local_shell":
        return {"type": "local_shell_call", "call_id": call_id, "status": "completed",
                "action": {"type": "exec", "command": ["bash", "-lc", cmd], "timeout_ms": 30000}}
    return None


def plan(body, seq):
    script = load_script()
    items = body.get("input") or []
    if isinstance(items, str):
        items = [{"type": "message", "role": "user", "content": items}]
    tools = tool_names(body)
    prompt, idx = position(items)
    sc = None
    for cand in script.get("scenarios", []):
        if cand.get("match", "") in prompt:
            sc = cand
            break
    info = {"scenario": sc and sc.get("name"), "turn": idx, "tools": sorted(tools)[:60]}
    if not sc or not sc.get("turns"):
        return [msg_item(script.get("aux_text", "ok"))], info
    turns = sc["turns"]
    turn = turns[idx] if idx < len(turns) else {"text": turns[-1].get("text") or "Done."}
    if "shell" in turn:
        item = render_shell(turn["shell"], tools, seq)
        if item is None:
            info["error"] = "no shell tool advertised"
            return [msg_item("mock: no shell tool among %s" % sorted(tools))], info
        out = []
        if turn.get("text"):
            out.append(msg_item(turn["text"]))
        out.append(item)
        return out, info
    if "function_call" in turn:
        fc = turn["function_call"]
        args = fc.get("arguments", {})
        return [{"type": "function_call", "name": fc["name"],
                 "call_id": "call_mock_%d_%s" % (seq, uuid.uuid4().hex[:6]),
                 "arguments": args if isinstance(args, str) else json.dumps(args)}], info
    return [msg_item(turn.get("text", "Done."))], info


def msg_item(text):
    return {"type": "message", "role": "assistant", "id": "msg_mock_%s" % uuid.uuid4().hex[:8],
            "status": "completed", "content": [{"type": "output_text", "text": text, "annotations": []}]}


def usage():
    return {"input_tokens": 12, "input_tokens_details": {"cached_tokens": 0}, "output_tokens": 5,
            "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 17}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mock-openai/1"

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        out = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def _record(self, raw):
        with LOCK:
            SEQ[0] += 1
            seq = SEQ[0]
        rec = {"seq": seq, "ts": time.time(), "method": self.command, "path": self.path,
               "headers": {k: v for k, v in self.headers.items()}, "body_len": len(raw)}
        body = None
        if raw:
            try:
                body = json.loads(raw)
            except Exception:
                rec["body_excerpt"] = raw[:400].decode(errors="replace")
        if isinstance(body, dict):
            items = body.get("input") or []
            rec["summary"] = {"model": body.get("model"), "stream": body.get("stream"),
                              "n_input": len(items) if isinstance(items, list) else 1,
                              "input_types": [(i.get("type", "message") + ":" + str(i.get("role", "")))
                                              for i in items if isinstance(i, dict)][-12:],
                              "previous_response_id": body.get("previous_response_id")}
        if ARGS.dump_dir and raw:
            os.makedirs(ARGS.dump_dir, exist_ok=True)
            with open(os.path.join(ARGS.dump_dir, "%05d.json" % seq), "wb") as fh:
                fh.write(raw)
        return seq, body, rec

    def do_GET(self):
        seq, _, rec = self._record(b"")
        path = urlparse(self.path).path
        if path.rstrip("/") in ("/v1/models", "/models"):
            rec["reply"] = "models"
            log_line(rec)
            data = [{"id": m, "object": "model", "created": 1767225600, "owned_by": "mock"}
                    for m in ("mock-model", "gpt-5.1-codex", "gpt-5.1")]
            return self._json(200, {"object": "list", "data": data, "models": []})
        if self.headers.get("Upgrade", "").lower() == "websocket":
            rec["reply"] = "websocket-refused"
            log_line(rec)
            return self._json(426, {"error": {"message": "mock: websocket unsupported"}})
        rec["reply"] = 404
        log_line(rec)
        return self._json(404, {"error": {"message": "mock: " + path, "type": "not_found"}})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        seq, body, rec = self._record(raw)
        path = urlparse(self.path).path
        if path.rstrip("/") not in ("/v1/responses", "/responses") or not isinstance(body, dict):
            rec["reply"] = 404
            log_line(rec)
            return self._json(404, {"error": {"message": "mock: " + path, "type": "not_found"}})
        out_items, info = plan(body, seq)
        rec["plan"] = dict(info, items=[i.get("type") + ":" + str(i.get("name", i.get("role", "")))
                                       for i in out_items])
        log_line(rec)
        resp_id = "resp_mock_%d" % seq
        model = body.get("model") or "mock-model"
        base = {"id": resp_id, "object": "response", "created_at": int(time.time()), "model": model}
        if not body.get("stream"):
            return self._json(200, dict(base, status="completed", output=out_items, usage=usage()))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        sn = [0]

        def ev(obj):
            obj["sequence_number"] = sn[0]
            sn[0] += 1
            self.wfile.write(("event: %s\ndata: %s\n\n" % (obj["type"], json.dumps(obj))).encode())
            self.wfile.flush()

        try:
            ev({"type": "response.created", "response": dict(base, status="in_progress", output=[])})
            for idx, item in enumerate(out_items):
                added = dict(item)
                if added.get("type") == "message":
                    added["content"] = []
                    added["status"] = "in_progress"
                ev({"type": "response.output_item.added", "output_index": idx, "item": added})
                if item.get("type") == "message":
                    text = item["content"][0]["text"]
                    for j in range(0, len(text), 24):
                        ev({"type": "response.output_text.delta", "item_id": item["id"], "output_index": idx,
                            "content_index": 0, "delta": text[j:j + 24]})
                ev({"type": "response.output_item.done", "output_index": idx, "item": item})
            ev({"type": "response.completed",
                "response": dict(base, status="completed", output=out_items, usage=usage())})
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    global ARGS
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18922)
    ap.add_argument("--script")
    ap.add_argument("--log")
    ap.add_argument("--dump-dir")
    ap.add_argument("--quiet", action="store_true")
    ARGS = ap.parse_args()
    srv = ThreadingHTTPServer((ARGS.host, ARGS.port), Handler)
    srv.daemon_threads = True
    sys.stderr.write("mock-openai listening on %s:%d\n" % (ARGS.host, ARGS.port))
    srv.serve_forever()


if __name__ == "__main__":
    main()
