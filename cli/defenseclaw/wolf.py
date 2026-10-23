# SPDX-License-Identifier: Apache-2.0
"""Offline Wolf Defender CPU worker. Configuration is supplied by the gateway on stdin."""

from __future__ import annotations

import hashlib
import json
import math
import sys
import threading
import time
from pathlib import Path

MAX_BYTES = 256 * 1024


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


class RefusalError(Exception):
    pass


class OnnxBackend:
    """Binary logits only; strict labels, explicit CPU, bounded overlapping windows."""

    def __init__(self, config):
        import numpy as np
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.np, self.ort = np, ort
        self.config = config
        paths = {k: Path(config[k]).expanduser() for k in ("model", "tokenizer", "model_config")}
        self.hashes = {k: sha256(p) for k, p in paths.items()}
        for k, digest in config["sha256"].items():
            if k not in self.hashes or digest != self.hashes[k]:
                raise ValueError("asset digest mismatch: " + k)
        if set(config["sha256"]) != set(paths):
            raise ValueError("all three asset digests required")
        mc = json.loads(paths["model_config"].read_text())
        labels = {str(k): str(v).lower() for k, v in mc["id2label"].items()}
        if set(labels) != {"0", "1"} or set(labels.values()) != {"benign", "injection"}:
            raise ValueError("explicit binary benign/injection labels required")
        self.positive = next(int(k) for k, v in labels.items() if v == "injection")
        self.tokenizer = Tokenizer.from_file(str(paths["tokenizer"]))
        self.tokenizer.no_truncation()
        self.tokenizer.no_padding()
        self.special = self.tokenizer.encode("").ids
        if len(self.special) != 2:
            raise ValueError("expected two boundary tokens")
        if config["window_tokens"] + 2 > mc["max_position_embeddings"]:
            raise ValueError("window exceeds model context")
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = config["threads"]
        opts.inter_op_num_threads = 1
        opts.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
        opts.log_severity_level = 3
        self.session = ort.InferenceSession(str(paths["model"]), opts, providers=["CPUExecutionProvider"])
        self.names = {x.name for x in self.session.get_inputs()}
        if "input_ids" not in self.names or not self.names <= {"input_ids", "attention_mask", "token_type_ids"}:
            raise ValueError("unsupported model inputs")
        if any(x.type != "tensor(int64)" for x in self.session.get_inputs()):
            raise ValueError("expected int64 model inputs")
        self.output = self.session.get_outputs()[0].name

    def score(self, text, deadline):
        np = self.np
        ids = self.tokenizer.encode(text, add_special_tokens=False).ids
        if len(ids) > self.config["max_tokens"]:
            raise RefusalError("token_limit")
        if not ids:
            return 0.0, 0, 0
        width, overlap = self.config["window_tokens"], self.config["overlap_tokens"]
        starts = []
        for start in range(0, len(ids), width - overlap):
            starts.append(start)
            if start + width >= len(ids):
                break
        if len(starts) > self.config["max_windows"]:
            raise RefusalError("window_limit")
        scores = []
        for start in starts:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                raise RefusalError("timeout")
            row = [self.special[0]] + ids[start : start + width] + [self.special[1]]
            arr = np.array([row], dtype=np.int64)
            feeds = {"input_ids": arr}
            if "attention_mask" in self.names:
                feeds["attention_mask"] = np.ones_like(arr)
            if "token_type_ids" in self.names:
                feeds["token_type_ids"] = np.zeros_like(arr)
            run = self.ort.RunOptions()
            timer = threading.Timer(remaining, lambda: setattr(run, "terminate", True))
            timer.daemon = True
            timer.start()
            try:
                logits = self.session.run([self.output], feeds, run)[0]
            except Exception as e:
                if time.perf_counter() >= deadline:
                    raise RefusalError("timeout") from e
                raise
            finally:
                timer.cancel()
                timer.join()
            if time.perf_counter() >= deadline:
                raise RefusalError("timeout")
            if logits.shape != (1, 2) or not np.isfinite(logits).all():
                raise RefusalError("invalid_logits")
            values = logits[0].astype(np.float64)
            probs = np.exp(values - values.max())
            probs /= probs.sum()
            scores.append(float(probs[self.positive]))
        return max(scores), len(ids), len(scores)


class Adapter:
    def __init__(self, config, backend_factory=OnnxBackend):
        self.config = dict(config)
        if config["mode"] not in {"action", "observe"}:
            raise ValueError("mode must be action or observe")
        if not math.isfinite(config["threshold"]) or not 0 < config["threshold"] < 1:
            raise ValueError("invalid threshold")
        for key in ("threads", "window_tokens", "max_tokens", "max_windows", "budget_ms"):
            if type(config[key]) is not int or config[key] <= 0:
                raise ValueError("invalid " + key)
        if not 0 <= config["overlap_tokens"] < config["window_tokens"]:
            raise ValueError("invalid overlap")
        self.lock = threading.Lock()
        self.backend, self.load_error = None, False
        if config["enabled"]:
            try:
                self.backend = backend_factory(config)
            except Exception:
                self.load_error = True

    def verdict(self, code, *, score=None, tokens=0, windows=0, elapsed=0):
        error = code not in {"scored", "disabled"}
        raw = "block" if error or (score is not None and score >= self.config["threshold"]) else "allow"
        action = raw if error or self.config["mode"] == "action" else "allow"
        return {
            "action": action,
            "raw_action": raw,
            "mode": self.config["mode"],
            "would_block": raw == "block" and action == "allow",
            "severity": "HIGH" if raw == "block" else "NONE",
            "confidence": score if score is not None else 0.0,
            "reason": "wolf:"
            + (code if error or code == "disabled" else ("injection" if raw == "block" else "below_threshold")),
            "findings": ["wolf:prompt_injection"]
            if code == "scored" and raw == "block"
            else (["wolf:" + code] if error else []),
            "wolf": {
                "status": "error" if error else code,
                "score": score,
                "threshold": self.config["threshold"],
                "tokens": tokens,
                "windows": windows,
                "complete": code == "scored",
                "elapsed_ms": round(elapsed, 4),
                "model_sha256": getattr(self.backend, "hashes", {}).get("model"),
            },
        }

    def inspect(self, request):
        start = time.perf_counter()
        if not self.lock.acquire(blocking=False):
            return self.verdict("busy")
        try:
            if (
                not isinstance(request, dict)
                or not isinstance(request.get("tool"), str)
                or not request["tool"].strip()
                or "output" not in request
            ):
                raise RefusalError("invalid_request")
            # JSON strings are decoded once; structures include keys AND values.
            output = request["output"]
            text = (
                output
                if isinstance(output, str)
                else json.dumps(output, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
            )
            if len(text.encode("utf-8", errors="strict")) > MAX_BYTES:
                raise RefusalError("byte_limit")
            if not self.config["enabled"]:
                return self.verdict("disabled")
            if self.load_error:
                raise RefusalError("model_unavailable")
            score, tokens, windows = self.backend.score(text, start + self.config["budget_ms"] / 1000)
            if not math.isfinite(score) or not 0 <= score <= 1:
                raise RefusalError("invalid_score")
            if (time.perf_counter() - start) * 1000 >= self.config["budget_ms"]:
                raise RefusalError("timeout")
            return self.verdict(
                "scored", score=score, tokens=tokens, windows=windows, elapsed=(time.perf_counter() - start) * 1000
            )
        except RefusalError as e:
            return self.verdict(str(e), elapsed=(time.perf_counter() - start) * 1000)
        except Exception:
            # Do not leak tool content, exception strings, model paths or secrets.
            return self.verdict("scan_error", elapsed=(time.perf_counter() - start) * 1000)
        finally:
            self.lock.release()


# Official artifacts, pinned independently for Small and Full. No model is bundled.
MANIFEST = {
    "small": {
        "model_id": "patronus-studio/wolf-defender-prompt-injection-small",
        "revision": "bcab2eff97bcabd7227849639e2d0d7a61b46c92",
        "sha256": {
            "model": "a6c77496152e458c072e4787f872192af0449a427359d1afbfa1d4d6b116a305",
            "tokenizer": "7e426c3929b44e6ab4c931770b5f22b913280633f5a1c67c81e9ad64decef55c",
            "model_config": "b5bfba7b100b4b1aa361e8160e5593695164d81ca09b47f3b26561332b520218",
        },
    },
    "full": {
        "model_id": "patronus-studio/wolf-defender-prompt-injection",
        "revision": "a77e7b669f079c3ad7e72e4ad10f3bd173ac4f4d",
        "sha256": {
            "model": "c449bbbd925ffb299cd70b226955956aa0aca04b5f616c6d0d3442500bef8acf",
            "tokenizer": "7e426c3929b44e6ab4c931770b5f22b913280633f5a1c67c81e9ad64decef55c",
            "model_config": "3c584c1079d46a3eb5c0dd2aad02d34aaa258da8d70823d415b5b98a868d00a9",
        },
    },
}


def runtime_config(settings):
    variant = settings["variant"]
    pinned = MANIFEST[variant]
    directory = Path(settings["model_dir"])
    if not directory.is_absolute():
        raise ValueError("absolute model directory required")
    return {
        **settings,
        **pinned,
        "mode": "action",
        "budget_ms": settings["timeout_ms"],
        "model": str(directory / "onnx/int8_int4_embeddings/model.onnx"),
        "tokenizer": str(directory / "tokenizer.json"),
        "model_config": str(directory / "config.json"),
    }


def main():
    # First line is trusted canonical configuration from the parent, never a path
    # supplied in an untrusted tool response. Assets and code must be owner-trusted.
    try:
        raw = sys.stdin.buffer.readline(65537)
        if len(raw) > 65536:
            raise ValueError("configuration too large")
        adapter = Adapter(runtime_config(json.loads(raw)))
        if adapter.load_error or adapter.backend is None:
            raise ValueError("runtime unavailable")
    except Exception:
        print(json.dumps({"ready": False}), flush=True)
        return 1
    print(json.dumps({"ready": True}), flush=True)
    if "--check" in sys.argv:
        return 0
    while True:
        raw = sys.stdin.buffer.readline(MAX_BYTES * 6 + 1025)
        if not raw:
            return 0
        if len(raw) > MAX_BYTES * 6 + 1024 or not raw.endswith(b"\n"):
            return 1
        try:
            verdict = adapter.inspect(json.loads(raw))
        except Exception:
            verdict = adapter.verdict("invalid_request")
        print(json.dumps(verdict, allow_nan=False), flush=True)


if __name__ == "__main__":
    sys.exit(main())
