#!/usr/bin/env python3
"""Evaluate a fixture through OmniGent's installed policy registry and adapter."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from omnigent.config import load_global_config
from omnigent.policies.function import resolve_function_policy
from omnigent.policies.registry import get_entry, load_registry
from omnigent.policies.types import EvaluationContext
from omnigent.spec import parse_default_policies
from omnigent.spec.types import FunctionPolicySpec, Phase

HANDLER = "defenseclaw_omnigent_policy.defenseclaw_policy"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("payload", nargs="?", type=Path)
    parser.add_argument(
        "--event-type",
        choices=[phase.value for phase in Phase],
    )
    parser.add_argument("--content", default="")
    return parser


def _event(args: argparse.Namespace) -> dict[str, Any]:
    if args.payload:
        return json.loads(args.payload.read_text(encoding="utf-8"))
    if not args.event_type:
        raise SystemExit("payload or --event-type is required")
    if args.event_type == Phase.REQUEST.value:
        data: Any = {"user_content": args.content, "attachments": []}
    elif args.event_type == Phase.TOOL_CALL.value:
        data = {
            "name": "sys_os_shell",
            "arguments": {"command": args.content},
        }
    else:
        data = args.content
    return {
        "type": args.event_type,
        "target": "sys_os_shell" if args.event_type in {"tool_call", "tool_result"} else None,
        "data": data,
        "context": {"model": "defenseclaw-contract"},
    }


async def _evaluate(event: dict[str, Any]) -> dict[str, str]:
    config = load_global_config()
    modules = config.get("policy_modules")
    if not isinstance(modules, list):
        raise RuntimeError("effective global config has no policy_modules list")
    load_registry([str(module) for module in modules])
    if get_entry(HANDLER) is None:
        raise RuntimeError("DefenseClaw handler is absent from OmniGent's policy registry")

    policies = parse_default_policies(config.get("policies"), expand_env=False)
    spec = next(
        (
            candidate
            for candidate in policies
            if isinstance(candidate, FunctionPolicySpec)
            and candidate.function is not None
            and candidate.function.path == HANDLER
        ),
        None,
    )
    if spec is None:
        raise RuntimeError("DefenseClaw handler is absent from OmniGent's parsed server policies")
    policy = resolve_function_policy(spec)

    event_type = str(event.get("type") or "")
    data = event.get("data")
    target = event.get("target")
    request_data = event.get("request_data")
    context = event.get("context")
    if not isinstance(context, dict):
        context = {}
    actor = context.get("actor")
    if not isinstance(actor, dict):
        actor = {}
    result = await policy.evaluate(
        EvaluationContext(
            phase=Phase(event_type),
            content=data,
            tool_name=str(target) if target else None,
            actor={str(key): str(value) for key, value in actor.items()},
            model=str(context.get("model") or "") or None,
            request_data=request_data,
        ),
        {},
    )
    return {
        "result": result.action.value.upper(),
        "reason": result.reason or "",
    }


def main() -> int:
    event = _event(_parser().parse_args())
    print(json.dumps(asyncio.run(_evaluate(event)), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
