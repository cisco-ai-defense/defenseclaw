#!/usr/bin/env python3
"""s7 model proxy (benchmark only, binds 127.0.0.1).

/v1/chat/completions  OpenAI-compatible, forwards to Amazon Bedrock (Mantle for open
                      models, Converse for Claude). The product's LLM judge points here.
(The earlier /v1/systemone route, an LLM's verbalized probabilities standing in for a
System One model, is removed: it is not a decision model and must not be benchmarked as one.)
response_format is forwarded to Mantle, and the real usage and finish_reason are returned.
--replay-latency makes a cache hit wait as long as the original call took, so a rerun of
the same samples under another strategy meets the hook's answer window as the live call did.
Every call is logged (tokens, latency, cost, cache hit) to --log. A response cache keyed
by the exact request makes repeated identical requests free; a model name suffix
"#tag" gives a separate cache namespace (used for repeatability reruns). A hard spend
cap (--cap-usd, persisted in --ledger) refuses calls once reached.
Credentials come from the host's AWS chain; no secret is printed or logged.
"""
import argparse, base64, hashlib, json, os, sys, threading, time, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import boto3
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.session import Session

PRICES = {  # USD per 1M tokens: input, output, cache read
    "gemma-4-31b": (0.14, 0.40, 0.14), "gemma-4-26b-a4b": (0.13, 0.40, 0.13),
    "gemma-3-27b": (0.23, 0.38, 0.23), "gpt-oss-safeguard-20b": (0.07, 0.20, 0.07),
    "gpt-oss-safeguard-120b": (0.15, 0.60, 0.15),
    "haiku-4-5": (1.00, 5.00, 0.10), "haiku-5-5": (0.10, 0.50, 0.01), "sonnet-5-5": (2.00, 10.00, 0.10),
}
MANTLE = {"gemma-4-31b": "google.gemma-4-31b", "gemma-4-26b-a4b": "google.gemma-4-26b-a4b",
          "gemma-3-27b": "google.gemma-3-27b-it", "gpt-oss-safeguard-20b": "openai.gpt-oss-safeguard-20b",
          "gpt-oss-safeguard-120b": "openai.gpt-oss-safeguard-120b"}
CONVERSE = {"haiku-4-5": "us.anthropic.claude-haiku-4-5-20251001-v1:0", "haiku-5-5": "us.anthropic.claude-haiku-5-5",
            "sonnet-5-5": "us.anthropic.claude-sonnet-5-5"}
NO_SAMPLING = {"haiku-5-5", "sonnet-5-5"}

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=18991)
ap.add_argument("--log", required=True)
ap.add_argument("--ledger", required=True)
ap.add_argument("--cache", required=True)
ap.add_argument("--cap-usd", type=float, default=70.0)
ap.add_argument("--region", default="us-east-1")
ap.add_argument("--conc", type=int, default=16)
ap.add_argument("--replay-latency", action="store_true")
ap.add_argument("--cache-only", action="store_true", help="answer only from the cache; a miss is refused (503) and logged, never sent to a model")
args = ap.parse_args()

lock = threading.Lock()
reserved = 0.0
sem = threading.BoundedSemaphore(args.conc)
spent = 0.0
if os.path.exists(args.ledger):
    try:
        spent = float(json.load(open(args.ledger)).get("spent_usd", 0))
    except Exception:
        spent = 0.0
cache = {}
if os.path.exists(args.cache):
    for line in open(args.cache):
        try:
            k, v = line.rstrip("\n").split("\t", 1)
            cache[k] = json.loads(v)
        except Exception:
            pass
cachef = open(args.cache, "a")
logf = open(args.log, "a")
brt = boto3.client("bedrock-runtime", region_name=args.region, config=Config(retries={"max_attempts": 6, "mode": "adaptive"}, read_timeout=120))
_tok = {"v": None, "t": 0}

def mantle_token():
    if _tok["v"] and time.time() - _tok["t"] < 1800:
        return _tok["v"]
    creds = Session().get_credentials().get_frozen_credentials()
    req = AWSRequest(method="POST", url="https://bedrock.amazonaws.com/", headers={"host": "bedrock.amazonaws.com"}, params={"Action": "CallWithBearerToken"})
    SigV4QueryAuth(creds, "bedrock", args.region, expires=3600).add_auth(req)
    _tok["v"] = "bedrock-api-key-" + base64.b64encode((req.url.replace("https://", "") + "&Version=1").encode()).decode()
    _tok["t"] = time.time()
    return _tok["v"]

def cost(model, tin, tout, tcache):
    p = PRICES[model]
    return (tin * p[0] + tout * p[1] + tcache * p[2]) / 1e6

def call_model(model, messages, max_tokens, temperature, response_format=None):
    """Returns (text, in_tokens, out_tokens, cache_read_tokens, stop)."""
    if model in MANTLE:
        body = {"model": MANTLE[model], "messages": messages, "max_tokens": max_tokens}
        if temperature is not None:
            body["temperature"] = temperature
        if response_format is not None:
            body["response_format"] = response_format
        last = None
        for attempt in range(6):
            req = urllib.request.Request(f"https://bedrock-mantle.{args.region}.api.aws/v1/chat/completions",
                                         data=json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json", "Authorization": "Bearer " + mantle_token()})
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    d = json.loads(r.read())
                u = d.get("usage") or {}
                ch = d["choices"][0]
                msg = ch.get("message") or {}
                return (msg.get("content") or ""), u.get("prompt_tokens", 0), u.get("completion_tokens", 0), 0, ch.get("finish_reason")
            except urllib.error.HTTPError as e:
                last = f"http {e.code}"
                if e.code in (429, 500, 502, 503, 504):
                    time.sleep(min(30, 2 ** attempt))
                    continue
                raise RuntimeError(last + " " + e.read()[:200].decode("utf-8", "replace"))
            except Exception as e:
                last = type(e).__name__
                time.sleep(min(30, 2 ** attempt))
        raise RuntimeError("mantle retries exhausted: " + str(last))
    system = [{"text": m["content"]} for m in messages if m["role"] == "system"]
    if system:
        system.append({"cachePoint": {"type": "default"}})
    conv = [{"role": m["role"], "content": [{"text": m["content"] or " "}]} for m in messages if m["role"] != "system"]
    inf = {"maxTokens": max_tokens}
    if temperature is not None and model not in NO_SAMPLING:
        inf["temperature"] = temperature
    kw = dict(modelId=CONVERSE[model], messages=conv, inferenceConfig=inf)
    if system:
        kw["system"] = system
    r = brt.converse(**kw)
    u = r.get("usage", {})
    text = "".join(b.get("text", "") for b in r["output"]["message"]["content"] if "text" in b)
    return text, u.get("inputTokens", 0), u.get("outputTokens", 0), u.get("cacheReadInputTokens", 0), r.get("stopReason")

def run(kind, model_tag, messages, max_tokens, temperature, response_format=None):
    global spent
    model, _, tag = model_tag.partition("#")
    if model not in PRICES:
        raise ValueError("unknown model")
    key = hashlib.sha256(json.dumps([model_tag, messages, max_tokens, temperature, response_format], sort_keys=True).encode()).hexdigest()
    with lock:
        hit = cache.get(key)
    if hit is None and args.cache_only:
        with lock:
            logf.write(json.dumps({"ts": time.time(), "kind": kind, "model": model, "key": key[:16], "cache_miss_refused": True}) + "\n"); logf.flush()
        raise PermissionError("cache-only: miss refused")
    rec = {"ts": time.time(), "kind": kind, "model": model, "tag": tag, "key": key[:16]}
    if hit is not None:
        rec.update(cache_hit=True, in_tok=hit["in"], out_tok=hit["out"], latency_ms=hit["ms"], cost=0.0, stop=hit.get("stop"))
        with lock:
            logf.write(json.dumps(rec) + "\n"); logf.flush()
        if args.replay_latency:
            time.sleep(hit["ms"] / 1000.0)
        return hit["text"], hit["in"], hit["out"], hit.get("stop")
    # Reserve a worst-case cost (about 3 characters per input token, every
    # output token) inside the semaphore, so queued calls cannot overshoot the cap.
    est = cost(model, len(json.dumps(messages)) // 3 + 1, max_tokens, 0)
    global reserved
    with sem:
        with lock:
            if spent + reserved + est > args.cap_usd:
                raise PermissionError("spend cap reached")
            reserved += est
        try:
            t0 = time.time()
            text, tin, tout, tcache, stop = call_model(model, messages, max_tokens, temperature, response_format)
            ms = int((time.time() - t0) * 1000)
        finally:
            with lock:
                reserved -= est
    c = cost(model, tin, tout, tcache)
    with lock:
        spent += c
        json.dump({"spent_usd": spent, "updated": time.time()}, open(args.ledger, "w"))
        cache[key] = {"text": text, "in": tin, "out": tout, "ms": ms, "stop": stop}
        cachef.write(key + "\t" + json.dumps(cache[key]) + "\n"); cachef.flush()
        rec.update(cache_hit=False, in_tok=tin, out_tok=tout, cache_read=tcache, latency_ms=ms, cost=c, stop=stop, text=text[:2000])
        logf.write(json.dumps(rec) + "\n"); logf.flush()
    return text, tin, tout, stop

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        self._send(200, {"spent_usd": spent, "cache": len(cache)})
    def do_POST(self):
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            if self.path.endswith("/systemone"):
                return self._send(404, {"error": {"message": "no System One model behind this proxy"}})
            msgs = [{"role": m["role"], "content": m["content"] if isinstance(m["content"], str) else "".join(p.get("text", "") for p in m["content"])} for m in body["messages"]]
            text, tin, tout, stop = run("judge", body["model"].split("/", 1)[-1], msgs, int(body.get("max_tokens") or body.get("max_completion_tokens") or 512), body.get("temperature"), body.get("response_format"))
            self._send(200, {"id": "s7", "object": "chat.completion", "model": body["model"],
                             "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": stop or "stop"}],
                             "usage": {"prompt_tokens": tin, "completion_tokens": tout, "total_tokens": tin + tout}})
        except PermissionError as e:
            self._send(503, {"error": {"message": str(e)}})
        except Exception as e:
            with lock:
                logf.write(json.dumps({"ts": time.time(), "error": type(e).__name__ + ": " + str(e)[:300], "path": self.path}) + "\n"); logf.flush()
            self._send(502, {"error": {"message": type(e).__name__}})

print(f"s7proxy on 127.0.0.1:{args.port} spent so far ${spent:.4f}", file=sys.stderr, flush=True)
ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()
