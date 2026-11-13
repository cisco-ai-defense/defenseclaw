#!/usr/bin/env python3
"""OpenAI-compatible /v1/chat/completions on 127.0.0.1 in front of Amazon Bedrock Converse, for competitor LLM checks that
expect an OpenAI-style endpoint (LlamaFirewall AlignmentCheck uses the OpenAI SDK against Together by default; NeMo self-check).

  python3 llmshim.py --port 18431 --log ~/s7c/compare/llm/llama4.jsonl --cap-usd 60

Model names: llama4-maverick (LlamaFirewall's default AlignmentCheck model, Llama-4-Maverick-17B-128E-Instruct), llama4-scout,
llama3.3-70b. response_format json_schema (what the OpenAI SDK's parse() sends) is honoured by adding the schema to the system
prompt and returning the first JSON object of the answer: Bedrock Converse has no constrained decoding for Llama, so a
non-JSON answer is returned as is and the caller's own parser decides (LlamaFirewall then uses its error default). Every
call is logged with tokens, latency and list-price cost; a hard cap refuses calls once reached. Credentials come from the
host's AWS chain; nothing secret is printed.
"""
import argparse, json, os, re, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import boto3
from botocore.config import Config

MODELS = {"llama4-maverick": "us.meta.llama4-maverick-17b-instruct-v1:0", "llama4-scout": "us.meta.llama4-scout-17b-instruct-v1:0",
          "llama3.3-70b": "us.meta.llama3-3-70b-instruct-v1:0"}
# USD per 1M tokens (input, output), Amazon Bedrock on-demand list price, us-east-1 (see README "Prices")
PRICES = {"llama4-maverick": (0.24, 0.97), "llama4-scout": (0.085, 0.33), "llama3.3-70b": (0.72, 0.72)}   # AWS Price List API 2026-11-13

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=18431)
ap.add_argument("--log", required=True)
ap.add_argument("--cap-usd", type=float, default=50.0)
ap.add_argument("--region", default="us-east-1")
ap.add_argument("--max-inflight", type=int, default=48)
args = ap.parse_args()
rt = boto3.client("bedrock-runtime", region_name=args.region, config=Config(retries={"max_attempts": 8, "mode": "adaptive"}, read_timeout=120, max_pool_connections=128))
lock = threading.Lock(); sem = threading.Semaphore(args.max_inflight)
os.makedirs(os.path.dirname(os.path.abspath(args.log)), exist_ok=True)
logf = open(args.log, "a")
spent = {"usd": 0.0}
for l in open(args.log):
    try:
        spent["usd"] += json.loads(l).get("usd", 0)
    except ValueError:
        pass


def json_objects(text):
    """Every balanced top-level {...} in the text that parses as JSON, in order."""
    out, depth, start, instr, esc = [], 0, None, False, False
    for i, ch in enumerate(text):
        if instr:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                instr = False
            continue
        if ch == '"':
            instr = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0:
                try:
                    out.append((text[start:i + 1], json.loads(text[start:i + 1])))
                except ValueError:
                    pass
    return out


def first_json(text, schema=None):
    """The answer object: the last JSON object holding every required key of the schema (a model sometimes quotes the trace's
    own action JSON before its answer), else the first JSON object."""
    objs = json_objects(text)
    req = set((schema or {}).get("required") or [])
    for raw, o in reversed(objs):
        if isinstance(o, dict) and req and req <= set(o):
            return raw
    return objs[0][0] if objs else None


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        model = body.get("model", ""); mid = MODELS.get(model)
        if not mid:
            return self._send(400, {"error": {"message": f"unknown model {model}"}})
        if spent["usd"] >= args.cap_usd:
            return self._send(429, {"error": {"message": "spend cap reached"}})
        system, msgs = [], []
        for m in body["messages"]:
            c = m.get("content") or ""
            if isinstance(c, list):
                c = "".join(x.get("text", "") for x in c if isinstance(x, dict))
            if m["role"] == "system":
                system.append({"text": c})
            else:
                role = "assistant" if m["role"] == "assistant" else "user"
                if msgs and msgs[-1]["role"] == role:
                    msgs[-1]["content"][0]["text"] += "\n" + c
                else:
                    msgs.append({"role": role, "content": [{"text": c}]})
        rf = body.get("response_format") or {}
        schema = (rf.get("json_schema") or {}).get("schema") if rf.get("type") == "json_schema" else None
        if schema:
            system.append({"text": "Respond with only a JSON object that conforms to this JSON schema, and nothing else:\n" + json.dumps(schema)})
        elif rf.get("type") == "json_object":
            system.append({"text": "Respond with only a JSON object."})
        inf = {"maxTokens": int(body.get("max_tokens") or body.get("max_completion_tokens") or 1024)}
        if body.get("temperature") is not None:
            inf["temperature"] = float(body["temperature"])
        t = time.time()
        with sem:
            try:
                r = rt.converse(modelId=mid, messages=msgs, system=system, inferenceConfig=inf)
            except Exception as e:
                rec = {"ts": t, "model": model, "err": f"{type(e).__name__}: {str(e)[:200]}", "ms": (time.time() - t) * 1000}
                with lock:
                    logf.write(json.dumps(rec) + "\n"); logf.flush()
                return self._send(502, {"error": {"message": rec["err"]}})
        ms = (time.time() - t) * 1000
        text = "".join(x.get("text", "") for x in r["output"]["message"]["content"])
        parsed_ok = None
        if schema or rf.get("type") == "json_object":
            j = first_json(text, schema); parsed_ok = j is not None and (not schema or set(schema.get("required") or []) <= set(json.loads(j)))
            if j:
                text = j
        u = r.get("usage", {}); tin, tout = u.get("inputTokens", 0), u.get("outputTokens", 0)
        p = PRICES[model]; usd = (tin * p[0] + tout * p[1]) / 1e6
        with lock:
            spent["usd"] += usd
            logf.write(json.dumps({"ts": t, "model": model, "in": tin, "out": tout, "usd": usd, "ms": ms, "json_ok": parsed_ok, "stop": r.get("stopReason")}) + "\n"); logf.flush()
        self._send(200, {"id": "shim", "object": "chat.completion", "created": int(t), "model": model,
                         "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop" if r.get("stopReason") == "end_turn" else (r.get("stopReason") or "stop")}],
                         "usage": {"prompt_tokens": tin, "completion_tokens": tout, "total_tokens": tin + tout}})


ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()
