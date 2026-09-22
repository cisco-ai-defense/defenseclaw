"""Fault-injection mock of the OpenJev ``/v1/systemone`` shim.

Speaks the same wire contract that ``benchmark_run_system_one.evaluate`` expects and that
``/opt/openjev-model/helper/shim.py`` implements, so the real runner can be pointed at it
unchanged:

request  POST <endpoint>  body = canonical_request(): {"model", "state", "questions"}
         headers: Content-Type: application/json, optional Authorization: Bearer <key>
response 200 {"id", "model", "answers": {<question_id>: <answer>}, "usage": {"input_tokens",
         "output_tokens"}} where each answer is one of
           choice {"type","choice","probabilities","confidence"}
           score  {"type","score","legend","probabilities","confidence"}
           noul   {"type","noul"}
         The real shim also emits 401 (bad bearer), 422 (bad request/question), 502
         (upstream failure), and drops the connection on an unhandled readout error.

Unlike the real shim this server answers from a deterministic hash of the request instead of
a model, and injects a selectable failure. It exists to test fail-closed behaviour of the
harness (dataset-card caveat C17), never to produce quality numbers.

Behaviours (``--behaviour``)
  ok                      valid, deterministic answer
  slow                    valid answer after ``--delay-seconds`` (use a delay above the
                          runner's --timeout for a hard read timeout)
  http429                 429 with no Retry-After
  http429_retry_after     429 with Retry-After: <seconds>
  http429_retry_after_date  429 with Retry-After as an HTTP-date (legal per RFC 9110)
  http500 / http502 / http503
  http422                 422, the real shim's "bad request" answer (not retry-classified)
  reset                   read the request, then RST the connection with no response
  reset_mid               status line + headers + half the body, then RST
  truncated_body          200 with the full Content-Length but only half the bytes written
  truncated_json          200 with a correct Content-Length over a syntactically cut JSON
                          document (the gpt-oss 9.12% parse-rate failure mode)
  invalid_json            200 with an HTML error page as the body
  missing_keys            200 with "answers": {}
  wrong_keys              200 with answers keyed by names the request did not ask for
  extra_answer_key        200 with every requested answer plus one extra
  extra_top_level_key     200 with valid answers plus an unexpected top-level field
  out_of_range_probs      200 with a probability above 1 that does not sum to 1
  duplicate_json_keys     200 whose raw body repeats "answers" twice
  object_choice           200 whose choice is an object instead of an enum string
  nonfinite_usage         200 with usage.input_tokens = 1e400 (parses as inf)
  type_mismatch_noul      200 that answers every question as a choice over yes/no even when
                          the request declared the question as noul or score
  silent_allow            200, perfectly well formed, always the most permissive answer
                          (models a degraded provider that defaults open)
  intermittent            ``--fail-fraction`` of requests get ``--intermittent-behaviour``,
                          the rest get ``ok``; selection is by request counter so it is
                          reproducible

"connection refused" is not a behaviour: the driver simply points the runner at a port where
nothing is listening.

Every request appends one JSON line to ``--ledger`` (request number, applied behaviour,
path, question ids) so a driver can count provider attempts server-side and prove whether
retries fired.

Run: python fault_inject_server.py --port 8851 --behaviour http503 --ledger /tmp/l.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

MODEL_STRING = "fault-inject-mock T=1.1 noul=3.0,-0.4 flags={} shim=fault_inject_server@0000"

STATUS_BEHAVIOURS = {
    "http422": 422,
    "http429": 429,
    "http429_retry_after": 429,
    "http429_retry_after_date": 429,
    "http500": 500,
    "http502": 502,
    "http503": 503,
}

BEHAVIOURS = (
    "ok",
    "slow",
    *sorted(STATUS_BEHAVIOURS),
    "reset",
    "reset_mid",
    "truncated_body",
    "truncated_json",
    "invalid_json",
    "missing_keys",
    "wrong_keys",
    "extra_answer_key",
    "extra_top_level_key",
    "out_of_range_probs",
    "duplicate_json_keys",
    "object_choice",
    "nonfinite_usage",
    "type_mismatch_noul",
    "silent_allow",
    "intermittent",
)


class Config:
    """Server-wide knobs, set once from argv and read by every handler thread."""

    behaviour = "ok"
    intermittent_behaviour = "http503"
    fail_fraction = 0.5
    delay_seconds = 5.0
    retry_after = 1
    token = ""
    ledger: Path | None = None
    lock = threading.Lock()
    count = 0
    applied: dict[str, int] = {}

    @classmethod
    def next_behaviour(cls) -> tuple[int, str]:
        """Pick the behaviour for the next request and record it, under one lock."""
        with cls.lock:
            cls.count += 1
            number = cls.count
            if cls.behaviour == "intermittent":
                # Deterministic interleave: fail every 1/fraction-th request.
                period = max(1, round(1 / cls.fail_fraction)) if cls.fail_fraction > 0 else 0
                applied = cls.intermittent_behaviour if period and number % period == 0 else "ok"
            else:
                applied = cls.behaviour
            cls.applied[applied] = cls.applied.get(applied, 0) + 1
            return number, applied


def deterministic_index(seed: str, modulus: int) -> int:
    return int(hashlib.sha256(seed.encode()).hexdigest(), 16) % max(1, modulus)


def answer_for(question_id: str, question: dict[str, Any], seed: str, permissive: bool) -> dict[str, Any]:
    """Build a well-formed answer of the type the request declared."""
    question_type = question.get("type")
    if question_type == "choice":
        options = list(question.get("criteria") or {}) or ["allow", "confirm", "block"]
        index = 0 if permissive else deterministic_index(seed + question_id, len(options))
        probabilities = {option: 0.05 for option in options}
        probabilities[options[index]] = round(1 - 0.05 * (len(options) - 1), 4)
        return {
            "type": "choice",
            "choice": options[index],
            "probabilities": probabilities,
            "confidence": 0.9 if permissive else 0.72,
        }
    if question_type == "score":
        levels = list(question.get("criteria") or [])
        count = max(2, len(levels))
        index = 0 if permissive else deterministic_index(seed + question_id, count)
        probabilities = {str(position): 0.02 for position in range(count)}
        probabilities[str(index)] = round(1 - 0.02 * (count - 1), 4)
        return {
            "type": "score",
            "score": float(index),
            "legend": {str(position): str(level) for position, level in enumerate(levels)},
            "probabilities": probabilities,
            "confidence": 0.8,
        }
    value = 0.02 if permissive else round(0.02 + 0.9 * deterministic_index(seed + question_id, 100) / 100, 4)
    return {"type": "noul", "noul": value}


def yes_no_choice() -> dict[str, Any]:
    """A choice over yes/no: the shape a provider emits when it ignores the declared type."""
    return {
        "type": "choice",
        "choice": "yes",
        "probabilities": {"yes": 0.95, "no": 0.05},
        "confidence": 0.95,
    }


def build_payload(body: dict[str, Any], applied: str) -> dict[str, Any]:
    questions = body.get("questions") if isinstance(body.get("questions"), dict) else {}
    seed = json.dumps(body.get("state"), sort_keys=True, ensure_ascii=False)[:4096]
    permissive = applied == "silent_allow"
    if applied == "type_mismatch_noul":
        answers = {question_id: yes_no_choice() for question_id in questions}
    else:
        answers = {
            question_id: answer_for(question_id, question if isinstance(question, dict) else {}, seed, permissive)
            for question_id, question in questions.items()
        }
    if applied == "missing_keys":
        answers = {}
    elif applied == "wrong_keys":
        answers = {f"not_{question_id}": answer for question_id, answer in answers.items()}
    elif applied == "extra_answer_key":
        answers["unexpected_question"] = answer_for("unexpected_question", {"type": "noul"}, seed, permissive)
    elif applied == "out_of_range_probs":
        for answer in answers.values():
            if "probabilities" in answer:
                first = next(iter(answer["probabilities"]))
                answer["probabilities"][first] = 1.4
    elif applied == "object_choice":
        for answer in answers.values():
            if answer.get("type") == "choice":
                answer["choice"] = {"disposition": "allow", "why": "degraded"}
    usage: dict[str, Any] = {"input_tokens": max(1, len(seed) // 4), "output_tokens": 0}
    if applied == "nonfinite_usage":
        usage["input_tokens"] = float("inf")
    payload: dict[str, Any] = {
        "id": f"mock-{int(time.time() * 1000)}",
        "model": MODEL_STRING,
        "answers": answers,
        "usage": usage,
    }
    if applied == "extra_top_level_key":
        payload["unexpected_field"] = {"note": "provider added a field"}
    return payload


def encode_payload(payload: dict[str, Any], applied: str) -> bytes:
    if applied == "nonfinite_usage":
        # json.dumps writes bare Infinity, which json.loads accepts back as inf.
        return json.dumps(payload).encode()
    if applied == "duplicate_json_keys":
        body = json.dumps(payload)
        return (body[:-1] + ', "answers": {"tampered": {"type": "noul", "noul": 0.0}}}').encode()
    return json.dumps(payload, ensure_ascii=False).encode()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def log_message(self, *args: Any) -> None:  # keep stdout for the ledger only
        return

    def abort(self) -> None:
        """Close with SO_LINGER 0 so the peer sees a TCP RST, not an orderly FIN."""
        try:
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            self.connection.close()
        except OSError:
            pass
        self.close_connection = True

    def send_bytes(self, code: int, data: bytes, headers: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def record(self, number: int, applied: str, questions: list[str]) -> None:
        if Config.ledger is None:
            return
        line = json.dumps(
            {
                "request": number,
                "behaviour": applied,
                "path": self.path,
                "questions": sorted(questions),
                "authorization": bool(self.headers.get("Authorization")),
                "at": round(time.time(), 3),
            },
            sort_keys=True,
        )
        with Config.lock:
            with Config.ledger.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def do_GET(self) -> None:
        if self.path.rstrip("/").endswith("/version"):
            return self.send_bytes(200, json.dumps({"model_dir": "fault-inject-mock"}).encode())
        self.send_bytes(404, json.dumps({"error": {"code": 404, "message": "GET /v1/version"}}).encode())

    def do_POST(self) -> None:
        if Config.token and self.headers.get("Authorization", "") != "Bearer " + Config.token:
            return self.send_bytes(401, json.dumps({"error": {"code": 401}}).encode())
        try:
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        except (OSError, ValueError):
            return self.abort()
        number, applied = Config.next_behaviour()
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        questions = list(body.get("questions") or {}) if isinstance(body.get("questions"), dict) else []
        self.record(number, applied, questions)

        if applied == "reset":
            return self.abort()
        if applied == "slow":
            time.sleep(Config.delay_seconds)
        if applied in STATUS_BEHAVIOURS:
            headers = {}
            if applied == "http429_retry_after":
                headers["Retry-After"] = str(Config.retry_after)
            if applied == "http429_retry_after_date":
                headers["Retry-After"] = time.strftime(
                    "%a, %d %b %Y %H:%M:%S GMT", time.gmtime(time.time() + Config.retry_after)
                )
            payload = {"error": {"code": STATUS_BEHAVIOURS[applied], "message": f"injected {applied}"}}
            return self.send_bytes(STATUS_BEHAVIOURS[applied], json.dumps(payload).encode(), headers)
        if applied == "invalid_json":
            data = b"<html><head><title>502 Bad Gateway</title></head><body>upstream</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        data = encode_payload(build_payload(body, applied), applied)

        if applied == "truncated_body":
            # Promise the full length, deliver half, then hang up: an IncompleteRead.
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data[: max(1, len(data) // 2)])
            self.wfile.flush()
            self.close_connection = True
            return
        if applied == "truncated_json":
            cut = data[: max(1, len(data) // 2)]
            return self.send_bytes(200, cut)
        if applied == "reset_mid":
            half = data[: max(1, len(data) // 2)]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            try:
                self.wfile.write(half)
                self.wfile.flush()
            except OSError:
                pass
            return self.abort()
        self.send_bytes(200, data)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--behaviour", choices=BEHAVIOURS, default="ok")
    parser.add_argument("--intermittent-behaviour", choices=BEHAVIOURS, default="http503")
    parser.add_argument("--fail-fraction", type=float, default=0.5)
    parser.add_argument("--delay-seconds", type=float, default=5.0)
    parser.add_argument("--retry-after", type=int, default=1)
    parser.add_argument("--token", default="")
    parser.add_argument("--ledger", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.port in {3000, 3100, 8000, 8011, 8765, 8766, 8767, 8768, 8769}:
        raise ValueError(f"port {args.port} belongs to a real tunnel, shim, or vLLM; pick a fresh high port")
    Config.behaviour = args.behaviour
    Config.intermittent_behaviour = args.intermittent_behaviour
    Config.fail_fraction = args.fail_fraction
    Config.delay_seconds = args.delay_seconds
    Config.retry_after = args.retry_after
    Config.token = args.token
    Config.ledger = args.ledger
    if Config.ledger is not None:
        Config.ledger.parent.mkdir(parents=True, exist_ok=True)
        Config.ledger.write_text("", encoding="utf-8")
    ThreadingHTTPServer.request_queue_size = 256
    ThreadingHTTPServer.daemon_threads = True
    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(json.dumps({"listening": f"{args.host}:{args.port}", "behaviour": args.behaviour}), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
