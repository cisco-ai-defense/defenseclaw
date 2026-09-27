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

"""Dependency-free mock of the OpenAI Chat Completions and Gemini
generateContent APIs for the Hermes, OpenHands and Antigravity sandbox E2E.

  POST /v1/chat/completions | /chat/completions              JSON or SSE
  POST /v1/responses | /responses                            JSON or SSE (function tools)
  POST /v1beta/models/<m>:generateContent                     JSON
  POST /v1beta/models/<m>:streamGenerateContent[?alt=sse]     SSE
  GET  /v1/models | /models                                   static list
  anything else                                               logged, 404 JSON error

Every request is appended to --log as one JSON line with credential header
values redacted (the log records only whether a value is still an OpenShell
placeholder, i.e. the supervisor did not substitute it) and the tool results
the harness reported back to the model. Script file (JSON, the mock_openai.py
format), selected by substring match against the latest user prompt:

  {"scenarios": [{"name": "default", "match": "",
                  "turns": [{"shell": "echo hi > /tmp/x"}, {"text": "Done."}]}]}

A {"shell": "<cmd>"} turn is rendered against whichever advertised tool is a
known shell tool (terminal, execute_bash, run_command, bash, shell, ...), with
the command under its command key and a placeholder for every other required
property. Turn index = number of model turns after the latest user prompt.
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

SHELL_TOOLS = ["terminal", "execute_bash", "run_command", "run_shell_command", "sys_os_shell", "bash", "Bash", "shell",
               "exec_command", "shell_command"]
COMMAND_KEYS = ["command", "cmd", "CommandLine", "commandLine", "script"]
CREDENTIAL_HEADER_WORDS = ("auth", "token", "key", "secret", "cookie", "session", "password", "credential",
                           "signature")
PLACEHOLDER_PREFIX = "openshell:resolve:"


def load_script():
    if ARGS.script and os.path.exists(ARGS.script):
        with open(ARGS.script, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {"scenarios": [{"name": "default", "match": "", "turns": [{"text": "ok"}]}]}


def redact_headers(headers):
    out = {}
    for name, value in headers.items():
        if not any(word in name.lower() for word in CREDENTIAL_HEADER_WORDS):
            out[name] = value
            continue
        scheme, sep, rest = value.strip().partition(" ")
        prefix, secret = (scheme + " ", rest.strip()) if sep and scheme.isalpha() else ("", value.strip())
        out[name] = prefix + ("[redacted placeholder]" if secret.startswith(PLACEHOLDER_PREFIX) else "[redacted]")
    return out


def log_line(obj):
    line = json.dumps(obj)
    with LOCK:
        if ARGS.log:
            with open(ARGS.log, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        if not ARGS.quiet:
            sys.stderr.write(line[:2000] + "\n")


def fill_args(schema, command):
    schema = schema or {}
    props = schema.get("properties") or {}
    args = {}
    key = next((k for k in COMMAND_KEYS if k in props), "command")
    args[key] = command
    for name in schema.get("required") or []:
        if name in args:
            continue
        prop = props.get(name) or {}
        kind = prop.get("type")
        if prop.get("enum"):
            args[name] = prop["enum"][0]
        elif kind == "boolean":
            args[name] = False
        elif kind in ("integer", "number"):
            args[name] = 30
        elif kind == "array":
            args[name] = []
        elif kind == "object":
            args[name] = {}
        elif "cwd" in name.lower() or "dir" in name.lower():
            args[name] = "/tmp"
        else:
            args[name] = "dce2e"
    return args


def schema_keys(schema):
    """The shell tool's parameter names, for the log: which fields a real
    model's call could carry next to the command."""
    schema = schema or {}
    return {"properties": sorted(schema.get("properties") or {}), "required": list(schema.get("required") or [])}


def pick(prompt):
    for sc in load_script().get("scenarios", []):
        if sc.get("match", "") in prompt:
            return sc
    return None


def turn_for(sc, idx):
    if not sc or not sc.get("turns"):
        return {"text": "ok"}
    turns = sc["turns"]
    return turns[idx] if idx < len(turns) else {"text": turns[-1].get("text") or "Done."}


def text_of(content):
    if isinstance(content, str):
        return content
    return "\n".join(p.get("text", "") for p in content or [] if isinstance(p, dict) and isinstance(p.get("text"), str))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mock-chat/1"

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        out = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def _sse(self, chunks, crlf=False):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        sep = "\r\n\r\n" if crlf else "\n\n"
        try:
            for c in chunks:
                self.wfile.write(("data: " + (c if isinstance(c, str) else json.dumps(c)) + sep).encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _record(self, raw):
        with LOCK:
            SEQ[0] += 1
            seq = SEQ[0]
        rec = {"seq": seq, "ts": time.time(), "method": self.command, "path": self.path,
               "headers": redact_headers(self.headers), "body_len": len(raw)}
        body = None
        if raw:
            try:
                body = json.loads(raw)
            except Exception:
                rec["body_excerpt"] = raw[:400].decode(errors="replace")
        if ARGS.dump_dir and raw:
            os.makedirs(ARGS.dump_dir, exist_ok=True)
            with open(os.path.join(ARGS.dump_dir, "%05d.json" % seq), "wb") as fh:
                fh.write(raw)
        return seq, body, rec

    def do_GET(self):
        _, _, rec = self._record(b"")
        path = urlparse(self.path).path.rstrip("/")
        if path in ("/v1/models", "/models"):
            rec["reply"] = "models"
            log_line(rec)
            return self._json(200, {"object": "list", "data": [{"id": "mock-model", "object": "model", "created": 0,
                                                                "owned_by": "mock"}]})
        rec["reply"] = 404
        log_line(rec)
        return self._json(404, {"error": {"message": "mock: " + path, "type": "not_found"}})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        seq, body, rec = self._record(raw)
        path = urlparse(self.path).path.rstrip("/")
        if not isinstance(body, dict):
            rec["reply"] = 400
            log_line(rec)
            return self._json(400, {"error": {"message": "mock: body is not a JSON object"}})
        if path in ("/v1/chat/completions", "/chat/completions"):
            return self.chat(seq, body, rec)
        if path in ("/v1/responses", "/responses"):
            return self.responses_api(seq, body, rec)
        if path.startswith("/v1beta/models/") and (path.endswith(":generateContent") or path.endswith(":streamGenerateContent")):
            return self.gemini(body, rec, stream=path.endswith(":streamGenerateContent"))
        rec["reply"] = 404
        log_line(rec)
        return self._json(404, {"error": {"message": "mock: " + path, "type": "not_found"}})

    def chat(self, seq, body, rec):
        msgs = [m for m in body.get("messages") or [] if isinstance(m, dict)]
        last = max((i for i, m in enumerate(msgs) if m.get("role") == "user"), default=-1)
        prompt = text_of(msgs[last].get("content")) if last >= 0 else ""
        after = msgs[last + 1:] if last >= 0 else []
        idx = sum(1 for m in after if m.get("role") == "assistant")
        rec["tool_results"] = [text_of(m.get("content"))[:2000] for m in after if m.get("role") == "tool"]
        schemas = {}
        for t in body.get("tools") or []:
            fn = (t or {}).get("function") or {}
            if fn.get("name"):
                schemas[fn["name"]] = fn.get("parameters")
        sc = pick(prompt)
        turn = turn_for(sc, idx) if sc else {"text": load_script().get("aux_text", "ok")}
        message, finish = {"role": "assistant", "content": turn.get("text", "Done.")}, "stop"
        if "shell" in turn:
            tool = next((name for name in SHELL_TOOLS if name in schemas), None)
            if tool is None:
                message["content"] = "mock: no shell tool among %s" % sorted(schemas)
            else:
                message = {"role": "assistant", "content": None, "tool_calls": [{
                    "id": "call_mock_%d_%s" % (seq, uuid.uuid4().hex[:6]), "type": "function",
                    "function": {"name": tool, "arguments": json.dumps(fill_args(schemas[tool], turn["shell"]))}}]}
                finish = "tool_calls"
        rec["plan"] = {"scenario": sc and sc.get("name"), "turn": idx, "tools": sorted(schemas)[:60],
                       "reply": "tool_call" if finish == "tool_calls" else "text"}
        if message.get("tool_calls"):
            fn = message["tool_calls"][0]["function"]
            rec["plan"]["call"] = {"name": fn["name"], "args": fn["arguments"], "schema": schema_keys(schemas[fn["name"]])}
        log_line(rec)
        base = {"id": "chatcmpl-mock-%d" % seq, "created": int(time.time()), "model": body.get("model") or "mock-model"}
        use = {"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17}
        if not body.get("stream"):
            return self._json(200, dict(base, object="chat.completion", usage=use,
                                        choices=[{"index": 0, "message": message, "finish_reason": finish}]))
        delta = {"role": "assistant"}
        if message.get("tool_calls"):
            call = message["tool_calls"][0]
            delta["tool_calls"] = [{"index": 0, "id": call["id"], "type": "function", "function": call["function"]}]
        else:
            delta["content"] = message["content"]
        self._sse([dict(base, object="chat.completion.chunk", choices=[{"index": 0, "delta": delta, "finish_reason": None}]),
                   dict(base, object="chat.completion.chunk", usage=use,
                        choices=[{"index": 0, "delta": {}, "finish_reason": finish}]),
                   "[DONE]"])

    def responses_api(self, seq, body, rec):
        # OpenAI Responses, for OmniGent's openai-agents harness. Function
        # tools only: the harness's shell tool (sys_os_shell) is a function.
        items = body.get("input") or []
        if isinstance(items, str):
            items = [{"type": "message", "role": "user", "content": items}]
        items = [i for i in items if isinstance(i, dict)]
        last = max((i for i, it in enumerate(items)
                    if it.get("type", "message") == "message" and it.get("role") == "user"), default=-1)
        prompt = text_of(items[last].get("content")) if last >= 0 else ""
        after = items[last + 1:] if last >= 0 else []
        idx = sum(1 for it in after if it.get("type") == "function_call"
                  or (it.get("type", "message") == "message" and it.get("role") == "assistant"))
        rec["tool_results"] = [str(it.get("output"))[:2000] for it in after if it.get("type") == "function_call_output"]
        schemas = {}
        for t in body.get("tools") or []:
            if isinstance(t, dict) and t.get("type") == "function":
                name = t.get("name") or (t.get("function") or {}).get("name")
                schemas[name] = t.get("parameters") or (t.get("function") or {}).get("parameters")
        sc = pick(prompt)
        turn = turn_for(sc, idx) if sc else {"text": load_script().get("aux_text", "ok")}
        out = [{"type": "message", "role": "assistant", "id": "msg_mock_%d" % seq, "status": "completed",
                "content": [{"type": "output_text", "text": turn.get("text", "Done."), "annotations": []}]}]
        if "shell" in turn:
            tool = next((name for name in SHELL_TOOLS if name in schemas), None)
            if tool is None:
                out[0]["content"][0]["text"] = "mock: no shell tool among %s" % sorted(k for k in schemas if k)
            else:
                out = [{"type": "function_call", "id": "fc_mock_%d" % seq, "call_id": "call_mock_%d" % seq,
                        "name": tool, "status": "completed",
                        "arguments": json.dumps(fill_args(schemas[tool], turn["shell"]))}]
        rec["plan"] = {"scenario": sc and sc.get("name"), "turn": idx, "tools": sorted(k for k in schemas if k)[:60],
                       "reply": "tool_call" if out[0]["type"] == "function_call" else "text"}
        if out[0]["type"] == "function_call":
            rec["plan"]["call"] = {"name": out[0]["name"], "args": out[0]["arguments"],
                                   "schema": schema_keys(schemas[out[0]["name"]])}
        log_line(rec)
        use = {"input_tokens": 12, "input_tokens_details": {"cached_tokens": 0}, "output_tokens": 5,
               "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 17}
        resp = {"id": "resp_mock_%d" % seq, "object": "response", "created_at": int(time.time()),
                "model": body.get("model") or "mock-model", "status": "completed", "output": out, "usage": use}
        if not body.get("stream"):
            return self._json(200, resp)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        n = [0]

        def ev(obj):
            obj["sequence_number"] = n[0]
            n[0] += 1
            self.wfile.write(("event: %s\ndata: %s\n\n" % (obj["type"], json.dumps(obj))).encode())
            self.wfile.flush()

        try:
            ev({"type": "response.created", "response": dict(resp, status="in_progress", output=[])})
            for i, item in enumerate(out):
                ev({"type": "response.output_item.added", "output_index": i, "item": item})
                ev({"type": "response.output_item.done", "output_index": i, "item": item})
            ev({"type": "response.completed", "response": resp})
        except (BrokenPipeError, ConnectionResetError):
            pass

    def gemini(self, body, rec, stream):
        contents = [c for c in body.get("contents") or [] if isinstance(c, dict)]
        last = -1
        for i, c in enumerate(contents):
            if c.get("role") == "user" and any(isinstance(p, dict) and "text" in p for p in c.get("parts") or []):
                last = i
        prompt = "\n".join(p.get("text", "") for p in (contents[last].get("parts") if last >= 0 else []) or []
                           if isinstance(p, dict) and "text" in p)
        after = contents[last + 1:] if last >= 0 else []
        idx = sum(1 for c in after if c.get("role") == "model")
        rec["tool_results"] = [json.dumps(p.get("functionResponse"))[:2000] for c in after for p in c.get("parts") or []
                               if isinstance(p, dict) and "functionResponse" in p]
        schemas = {}
        for t in body.get("tools") or []:
            for fd in (t or {}).get("functionDeclarations") or []:
                schemas[fd.get("name")] = fd.get("parameters") or fd.get("parametersJsonSchema")
        sc = pick(prompt)
        turn = turn_for(sc, idx) if sc else {"text": load_script().get("aux_text", "ok")}
        parts = [{"text": turn.get("text", "Done.")}]
        if "shell" in turn:
            tool = next((name for name in SHELL_TOOLS if name in schemas), None)
            if tool is None:
                parts = [{"text": "mock: no shell tool among %s" % sorted(k for k in schemas if k)}]
            else:
                parts = [{"functionCall": {"name": tool, "args": fill_args(schemas[tool], turn["shell"])}}]
        rec["plan"] = {"scenario": sc and sc.get("name"), "turn": idx, "tools": sorted(k for k in schemas if k)[:60],
                       "reply": "tool_call" if "functionCall" in parts[0] else "text"}
        if "functionCall" in parts[0]:
            fc = parts[0]["functionCall"]
            rec["plan"]["call"] = {"name": fc["name"], "args": json.dumps(fc["args"]), "schema": schema_keys(schemas[fc["name"]])}
        log_line(rec)
        resp = {"candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": "STOP", "index": 0}],
                "usageMetadata": {"promptTokenCount": 12, "candidatesTokenCount": 5, "totalTokenCount": 17},
                "modelVersion": "mock-model"}
        if not stream:
            return self._json(200, resp)
        self._sse([resp], crlf=True)


def main():
    global ARGS
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18923)
    ap.add_argument("--script")
    ap.add_argument("--log")
    ap.add_argument("--dump-dir")
    ap.add_argument("--quiet", action="store_true")
    ARGS = ap.parse_args()
    srv = ThreadingHTTPServer((ARGS.host, ARGS.port), Handler)
    srv.daemon_threads = True
    sys.stderr.write("mock-chat listening on %s:%d\n" % (ARGS.host, ARGS.port))
    srv.serve_forever()


if __name__ == "__main__":
    main()
