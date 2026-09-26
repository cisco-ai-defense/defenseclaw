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

"""Dependency-free mock of the Anthropic Messages API for harness E2E tests.

Serves a scripted conversation to Claude Code (or any Messages API client):

  POST /v1/messages[?beta=true]          streaming (SSE) and non-streaming
  POST /v1/messages/count_tokens         {"input_tokens": N}
  GET  /v1/models[/<id>]                 small static model list
  anything else                          logged, 404 JSON error

Every request is appended to --log as one JSON line (path, query, headers,
summary of the body). --dump-dir additionally stores each full request body.

Script file (JSON), selected per request by substring match against the most
recent *real* user prompt (a user message that is not only tool_result blocks):

  {
    "scenarios": [
      {"name": "blockme", "match": "BLOCKME",
       "turns": [
         {"tool_use": {"name": "Bash",
                       "input": {"command": "echo BLOCKME", "description": "x"}}},
         {"text": "The command was blocked."}
       ]},
      {"name": "default", "match": "",
       "turns": [ {"text": "hello"} ]}
    ],
    "aux_text": "Mock title"
  }

Turn index = number of assistant messages after that real user prompt, so a
tool_use turn is answered with the next turn once the tool_result comes back.
A turn may also be {"content": [<raw content blocks>], "stop_reason": "..."}.
Requests that do not advertise the tool a scenario turn wants to call (title
generation, quota probes, prefix classifiers, ...) get "aux_text" instead.
The script file is re-read on every request, so tests can swap it live.
"""

import argparse
import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ARGS = None
LOCK = threading.Lock()
SEQ = [0]

DEFAULT_SCRIPT = {
    "scenarios": [
        {
            "name": "default",
            "match": "",
            "turns": [
                {
                    "tool_use": {
                        "name": "Bash",
                        "input": {
                            "command": "echo hello-from-tool > /tmp/tool.txt && cat /tmp/tool.txt",
                            "description": "Write a marker file",
                        },
                    }
                },
                {"text": "Done: the marker file was written."},
            ],
        }
    ],
    "aux_text": "Mock session",
}


def load_script():
    if ARGS.script and os.path.exists(ARGS.script):
        with open(ARGS.script, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return DEFAULT_SCRIPT


def log_line(obj):
    line = json.dumps(obj, sort_keys=False)
    with LOCK:
        if ARGS.log:
            with open(ARGS.log, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        if not ARGS.quiet:
            sys.stderr.write(line[:2000] + "\n")
            sys.stderr.flush()


def block_text(content):
    if isinstance(content, str):
        return content
    out = []
    for block in content or []:
        if isinstance(block, dict) and block.get("type") == "text":
            out.append(block.get("text", ""))
    return "\n".join(out)


def is_tool_result_only(msg):
    content = msg.get("content")
    if not isinstance(content, list) or not content:
        return False
    return all(isinstance(b, dict) and b.get("type") == "tool_result" for b in content)


def conversation_position(messages):
    """Return (prompt_text, assistant_turns_since_prompt)."""
    last_prompt = -1
    for i, msg in enumerate(messages):
        if msg.get("role") == "user" and not is_tool_result_only(msg):
            last_prompt = i
    if last_prompt < 0:
        return "", 0
    prompt = block_text(messages[last_prompt].get("content"))
    turns = sum(1 for m in messages[last_prompt + 1:] if m.get("role") == "assistant")
    return prompt, turns


def pick_scenario(script, prompt):
    for sc in script.get("scenarios", []):
        if sc.get("match", "") in prompt:
            return sc
    return None


def turn_blocks(turn, seq):
    """Normalize a scripted turn into (content_blocks, stop_reason)."""
    if "content" in turn:
        blocks = []
        for b in turn["content"]:
            b = dict(b)
            if b.get("type") == "tool_use" and "id" not in b:
                b["id"] = "toolu_mock_%d_%s" % (seq, uuid.uuid4().hex[:8])
            blocks.append(b)
        stop = turn.get("stop_reason") or (
            "tool_use" if any(b.get("type") == "tool_use" for b in blocks) else "end_turn")
        return blocks, stop
    blocks = []
    if turn.get("text"):
        blocks.append({"type": "text", "text": turn["text"]})
    if turn.get("tool_use"):
        tu = turn["tool_use"]
        blocks.append({
            "type": "tool_use",
            "id": "toolu_mock_%d_%s" % (seq, uuid.uuid4().hex[:8]),
            "name": tu["name"],
            "input": tu.get("input", {}),
        })
        return blocks, "tool_use"
    return blocks, "end_turn"


def wanted_tools(turn):
    names = set()
    if turn.get("tool_use"):
        names.add(turn["tool_use"]["name"])
    for b in turn.get("content", []) or []:
        if isinstance(b, dict) and b.get("type") == "tool_use":
            names.add(b.get("name"))
    return names


def plan_response(body, seq):
    script = load_script()
    messages = body.get("messages") or []
    tools = {t.get("name") for t in (body.get("tools") or []) if isinstance(t, dict)}
    prompt, idx = conversation_position(messages)
    sc = pick_scenario(script, prompt)
    info = {"scenario": None, "turn": idx, "kind": "aux"}
    aux = script.get("aux_text", "Mock session")
    if sc is None:
        return [{"type": "text", "text": aux}], "end_turn", info
    turns = sc.get("turns", [])
    info["scenario"] = sc.get("name")
    if not turns:
        return [{"type": "text", "text": aux}], "end_turn", info
    turn = turns[min(idx, len(turns) - 1)] if idx < len(turns) else {"text": turns[-1].get("text") or "Done."}
    need = wanted_tools(turn)
    # A request that cannot call the scripted tool is an auxiliary call
    # (title/quota/classifier); never burn a scripted turn on it.
    if need and not need.issubset(tools):
        return [{"type": "text", "text": aux}], "end_turn", info
    if not tools and not need and idx == 0 and body.get("max_tokens", 0) <= 1:
        return [{"type": "text", "text": aux}], "end_turn", info
    info["kind"] = "main"
    blocks, stop = turn_blocks(turn, seq)
    return blocks, stop, info


def usage(out_tokens=5):
    return {
        "input_tokens": 12,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        "output_tokens": out_tokens,
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mock-anthropic/1"

    def log_message(self, *a):
        pass

    def _read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        return raw

    def _json(self, code, obj):
        out = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.send_header("request-id", "req_mock_%s" % uuid.uuid4().hex[:12])
        self.end_headers()
        self.wfile.write(out)

    def _record(self, raw, extra=None):
        with LOCK:
            SEQ[0] += 1
            seq = SEQ[0]
        body = None
        try:
            body = json.loads(raw) if raw else None
        except Exception:
            body = None
        rec = {
            "seq": seq,
            "ts": time.time(),
            "method": self.command,
            "path": urlparse(self.path).path,
            "query": parse_qs(urlparse(self.path).query),
            "headers": {k: v for k, v in self.headers.items()},
            "body_len": len(raw),
        }
        if isinstance(body, dict):
            msgs = body.get("messages") or []
            rec["summary"] = {
                "model": body.get("model"),
                "stream": body.get("stream"),
                "max_tokens": body.get("max_tokens"),
                "n_messages": len(msgs),
                "tools": [t.get("name") for t in (body.get("tools") or []) if isinstance(t, dict)][:80],
                "roles": [m.get("role") for m in msgs],
                "last_user_text": block_text(msgs[-1].get("content"))[-400:] if msgs else None,
            }
        elif raw:
            rec["body_excerpt"] = raw[:400].decode(errors="replace")
        if extra:
            rec.update(extra)
        if ARGS.dump_dir and raw:
            os.makedirs(ARGS.dump_dir, exist_ok=True)
            with open(os.path.join(ARGS.dump_dir, "%05d.json" % seq), "wb") as fh:
                fh.write(raw)
        return seq, body, rec

    def do_GET(self):
        raw = b""
        seq, _, rec = self._record(raw)
        path = urlparse(self.path).path
        if path.startswith("/v1/models"):
            rec["reply"] = "models"
            log_line(rec)
            models = [{"type": "model", "id": m, "display_name": m, "created_at": "2026-01-01T00:00:00Z"}
                      for m in ("claude-sonnet-4-5", "claude-opus-4-1", "claude-haiku-4-5")]
            if path.rstrip("/") != "/v1/models":
                mid = path.rsplit("/", 1)[-1]
                return self._json(200, {"type": "model", "id": mid, "display_name": mid,
                                        "created_at": "2026-01-01T00:00:00Z"})
            return self._json(200, {"data": models, "has_more": False,
                                    "first_id": models[0]["id"], "last_id": models[-1]["id"]})
        rec["reply"] = 404
        log_line(rec)
        return self._json(404, {"type": "error", "error": {"type": "not_found_error", "message": "mock: " + path}})

    def do_HEAD(self):
        # Claude Code HEADs the base URL at startup (connection warm-up).
        _, _, rec = self._record(b"")
        rec["reply"] = "head"
        log_line(rec)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        raw = self._read_body()
        seq, body, rec = self._record(raw)
        path = urlparse(self.path).path
        if path == "/v1/messages/count_tokens":
            rec["reply"] = "count_tokens"
            log_line(rec)
            return self._json(200, {"input_tokens": max(1, len(raw) // 4)})
        if path != "/v1/messages" or not isinstance(body, dict):
            rec["reply"] = 404
            log_line(rec)
            return self._json(404, {"type": "error", "error": {"type": "not_found_error", "message": "mock: " + path}})
        blocks, stop, info = plan_response(body, seq)
        rec["plan"] = dict(info, stop_reason=stop, blocks=[b.get("type") + (":" + b.get("name") if b.get("name") else "") for b in blocks])
        log_line(rec)
        model = body.get("model") or "claude-sonnet-4-5"
        msg_id = "msg_mock_%d_%s" % (seq, uuid.uuid4().hex[:8])
        if not body.get("stream"):
            return self._json(200, {
                "id": msg_id, "type": "message", "role": "assistant", "model": model,
                "content": blocks, "stop_reason": stop, "stop_sequence": None, "usage": usage(),
            })
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("request-id", "req_mock_%s" % uuid.uuid4().hex[:12])
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        def ev(name, data):
            self.wfile.write(("event: %s\ndata: %s\n\n" % (name, json.dumps(data))).encode())
            self.wfile.flush()

        try:
            ev("message_start", {"type": "message_start", "message": {
                "id": msg_id, "type": "message", "role": "assistant", "model": model, "content": [],
                "stop_reason": None, "stop_sequence": None, "usage": usage(1)}})
            ev("ping", {"type": "ping"})
            for i, b in enumerate(blocks):
                if b["type"] == "text":
                    ev("content_block_start", {"type": "content_block_start", "index": i,
                                               "content_block": {"type": "text", "text": ""}})
                    text = b["text"]
                    for j in range(0, len(text), 24):
                        ev("content_block_delta", {"type": "content_block_delta", "index": i,
                                                   "delta": {"type": "text_delta", "text": text[j:j + 24]}})
                elif b["type"] == "tool_use":
                    ev("content_block_start", {"type": "content_block_start", "index": i,
                                               "content_block": {"type": "tool_use", "id": b["id"],
                                                                 "name": b["name"], "input": {}}})
                    js = json.dumps(b.get("input", {}))
                    for j in range(0, len(js), 32):
                        ev("content_block_delta", {"type": "content_block_delta", "index": i,
                                                   "delta": {"type": "input_json_delta", "partial_json": js[j:j + 32]}})
                else:
                    ev("content_block_start", {"type": "content_block_start", "index": i, "content_block": b})
                ev("content_block_stop", {"type": "content_block_stop", "index": i})
            ev("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                                 "usage": {"output_tokens": 5}})
            ev("message_stop", {"type": "message_stop"})
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    global ARGS
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18921)
    ap.add_argument("--script", help="scenario JSON file (re-read per request)")
    ap.add_argument("--log", help="append one JSON line per request here")
    ap.add_argument("--dump-dir", help="store full request bodies here")
    ap.add_argument("--quiet", action="store_true")
    ARGS = ap.parse_args()
    srv = ThreadingHTTPServer((ARGS.host, ARGS.port), Handler)
    srv.daemon_threads = True
    sys.stderr.write("mock-anthropic listening on %s:%d\n" % (ARGS.host, ARGS.port))
    srv.serve_forever()


if __name__ == "__main__":
    main()
