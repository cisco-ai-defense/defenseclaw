#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Drive a guarded ACP subprocess for cross-platform release validation."""

from __future__ import annotations

import argparse
import json
import queue
import subprocess
import sys
import threading
import time
from typing import Any


def _write(process: subprocess.Popen[str], value: dict[str, Any]) -> None:
    assert process.stdin is not None
    process.stdin.write(json.dumps(value, separators=(",", ":")) + "\n")
    process.stdin.flush()


def _reader(stream, messages: queue.Queue[object]) -> None:
    try:
        for line in stream:
            messages.put(line)
    finally:
        messages.put(None)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect", choices=("action", "observe"), required=True)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a guard command is required after --")

    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    messages: queue.Queue[object] = queue.Queue()
    threading.Thread(target=_reader, args=(process.stdout, messages), daemon=True).start()

    seen_agent_requests: list[str] = []
    prompt_result: dict[str, Any] | None = None
    deadline = time.monotonic() + args.timeout
    requests = (
        (1, "initialize", {"protocolVersion": 1, "clientInfo": {"name": "DefenseClaw E2E", "version": "1"}}),
        (2, "session/new", {"cwd": ".", "mcpServers": []}),
        (3, "session/prompt", {"sessionId": "fixture-session", "prompt": []}),
    )
    next_request = 0
    try:
        _write(
            process,
            {"jsonrpc": "2.0", "id": requests[0][0], "method": requests[0][1], "params": requests[0][2]},
        )
        next_request = 1
        while time.monotonic() < deadline and prompt_result is None:
            try:
                item = messages.get(timeout=max(0.05, deadline - time.monotonic()))
            except queue.Empty:
                break
            if item is None:
                break
            message = json.loads(str(item))
            method = message.get("method")
            message_id = message.get("id")
            if isinstance(method, str) and message_id is not None:
                seen_agent_requests.append(method)
                _write(process, {"jsonrpc": "2.0", "id": message_id, "result": {}})
                continue
            if message_id == requests[next_request - 1][0] and next_request < len(requests):
                request_id, request_method, params = requests[next_request]
                _write(
                    process,
                    {"jsonrpc": "2.0", "id": request_id, "method": request_method, "params": params},
                )
                next_request += 1
                continue
            if message_id == 3:
                prompt_result = message

        if prompt_result is None:
            raise RuntimeError("guarded ACP prompt did not reach a terminal response")
        blocked = isinstance(prompt_result.get("error"), dict)
        dangerous = {"fs/write_text_file", "terminal/create", "session/request_permission"}
        if args.expect == "action":
            if not blocked or dangerous.intersection(seen_agent_requests):
                raise RuntimeError(
                    f"action mode did not block before client execution: response={prompt_result}, "
                    f"requests={seen_agent_requests}"
                )
        elif blocked or not dangerous.issubset(seen_agent_requests):
            raise RuntimeError(
                f"observe mode did not preserve inspected traffic: response={prompt_result}, "
                f"requests={seen_agent_requests}"
            )
        print(
            json.dumps(
                {
                    "expect": args.expect,
                    "prompt_blocked": blocked,
                    "agent_requests_seen": seen_agent_requests,
                    "result": "ok",
                },
                sort_keys=True,
            )
        )
        return 0
    finally:
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        stderr = process.stderr.read().strip()
        if process.returncode not in (0, None) and stderr:
            print(stderr, file=sys.stderr)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ACP E2E driver failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
