# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Phase 9: live OPA evaluation lane for the Policy Creator.

Python port of ``docs-site/components/policy-creator/lib/opa-eval.ts``.

The web Creator lazy-loads compiled WASM modules (`/opa/<domain>.wasm`)
into the browser and pokes them via ``@open-policy-agent/opa-wasm``.
That doesn't translate to a TUI: we don't want to ship a WASM
runtime to operator terminals, and the gateway already depends on
the ``opa`` CLI being on PATH for ``defenseclaw policy verify``.

So the TUI shells out to ``opa eval`` instead. The signature mirrors
the web lane (``evaluate_domain(domain, input, data) -> OpaResult``)
so the Live Test pane in the Playground can swap between the two
without touching renderer code.

Behavior contract:

* If ``opa`` is not on PATH, ``OpaUnavailableError`` propagates so
  the UI can render a "install OPA" banner.
* All subprocess calls are bounded by ``timeout`` (default 5s) so a
  pathological policy can't lock up the TUI. Timeouts surface as
  ``OpaUnavailableError`` so the UI degrades gracefully.
* ``verdict_tone`` mirrors the JS module's enum mapping 1:1 so the
  Playground header can colour-code verdicts identically to the
  docs creator.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from defenseclaw.tui.creator.types import OpaResult

# Verdict tone bucket the UI maps to a colour. Keep in sync with
# ``verdictTone`` in ``opa-eval.ts`` so the docs site and the TUI
# colour the same verdicts the same way.
VerdictTone = Literal["positive", "caution", "negative", "neutral"]


class OpaUnavailableError(RuntimeError):
    """Raised when the ``opa`` CLI is missing, refused to run, or
    timed out.

    The Live Test pane catches this and renders a one-line banner
    pointing at ``opa`` install docs rather than a raw stack trace.
    """


# --- Domain entrypoint mapping ---------------------------------------------
#
# Each domain maps to the Rego entrypoint the gateway evaluates at
# runtime. The (verdict, reason) tuple matches the web Creator's
# ``pickVerdictEntrypoint`` / ``pickReasonEntrypoint`` switches so a
# rule rename only has to land in one place.

_DOMAIN_ENTRYPOINTS: dict[str, tuple[str, str | None]] = {
    "admission": (
        "defenseclaw.admission.verdict",
        "defenseclaw.admission.reason",
    ),
    "guardrail": (
        "defenseclaw.guardrail.severity",
        "defenseclaw.guardrail.reason",
    ),
    "firewall": (
        "defenseclaw.firewall.action",
        "defenseclaw.firewall.rule_name",
    ),
    "audit": (
        "defenseclaw.audit.retain",
        "defenseclaw.audit.retain_reason",
    ),
    "skill_actions": (
        "defenseclaw.skill_actions.runtime_action",
        None,
    ),
}


def domain_entrypoints(domain: str) -> tuple[str, str | None]:
    """Return ``(verdict_path, reason_path)`` for ``domain``.

    Falls back to the conventional ``defenseclaw.<domain>.verdict``
    rule for unknown domains so a custom Rego module exposing the
    standard verdict shape works without code changes.
    """
    if domain in _DOMAIN_ENTRYPOINTS:
        return _DOMAIN_ENTRYPOINTS[domain]
    return (f"defenseclaw.{domain}.verdict", None)


# --- Subprocess plumbing ---------------------------------------------------


def is_opa_available(*, opa_bin: str = "opa") -> bool:
    """True iff a runnable ``opa`` binary is on PATH.

    Used by the Playground to decide whether to render the Live Test
    pane vs a "install OPA" call-out.
    """
    return shutil.which(opa_bin) is not None


@dataclass(frozen=True)
class OpaConfig:
    """Inputs to ``evaluate_domain`` that don't change per call.

    Centralized here so the Playground state model can pass one
    object around rather than passing six positional args every
    time the operator types a character into the input pane.
    """

    rego_dir: Path
    opa_bin: str = "opa"
    timeout_seconds: float = 5.0
    extra_paths: tuple[Path, ...] = field(default_factory=tuple)


def _run_opa_eval(
    *,
    config: OpaConfig,
    entrypoint: str,
    input_payload: Any,
    data_payload: Mapping[str, Any],
    workspace: Path,
) -> Any:
    """Invoke ``opa eval`` once and return the parsed result.

    ``input_payload`` and ``data_payload`` are streamed via files in
    ``workspace`` so policy bundles with megabyte-scale rule packs
    don't bump up against argv limits. The caller owns ``workspace``
    (typically a ``tempfile.TemporaryDirectory``) so we can re-use
    it across the verdict + reason calls without paying two
    ``mkdtemp`` syscalls per evaluation.
    """
    input_path = workspace / "input.json"
    data_path = workspace / "data.json"
    input_path.write_text(json.dumps(input_payload), encoding="utf-8")
    data_path.write_text(json.dumps(data_payload), encoding="utf-8")

    cmd: list[str] = [
        config.opa_bin,
        "eval",
        "--format",
        "json",
        "--data",
        str(config.rego_dir),
        "--data",
        str(data_path),
        "--input",
        str(input_path),
    ]
    for extra in config.extra_paths:
        cmd.extend(["--data", str(extra)])
    cmd.append(f"data.{entrypoint}")

    try:
        completed = subprocess.run(  # noqa: S603 - opa_bin defaults to a hardcoded literal; OpaConfig is operator-trusted
            cmd,
            capture_output=True,
            timeout=config.timeout_seconds,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise OpaUnavailableError(
            f"opa binary not found at {config.opa_bin!r}. Install OPA "
            f"from https://www.openpolicyagent.org/docs/latest/#running-opa "
            f"or set OpaConfig.opa_bin to its absolute path."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise OpaUnavailableError(
            f"opa eval timed out after {config.timeout_seconds}s. The "
            f"policy under evaluation may have a runaway rule; tighten "
            f"the time budget once you've fixed it."
        ) from exc

    if completed.returncode != 0:
        # ``opa eval`` writes parse / type errors to stderr. Surface
        # them as ``OpaUnavailableError`` so the Live Test pane can
        # show the operator the exact diagnostic.
        stderr = completed.stderr.strip() or completed.stdout.strip()
        raise OpaUnavailableError(f"opa eval failed: {stderr or 'no diagnostic'}")

    if not completed.stdout.strip():
        return None

    try:
        parsed: Any = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise OpaUnavailableError(
            f"opa eval emitted unparseable JSON: {exc.msg}"
        ) from exc

    # ``opa eval`` returns
    #   {"result": [{"expressions": [{"value": <verdict>, ...}], ...}]}
    # for a defined entrypoint, and
    #   {"result": []}
    # when the rule is undefined under the policy. We collapse to a
    # single value so callers don't have to know the wrapper shape.
    result_blocks = parsed.get("result") if isinstance(parsed, dict) else None
    if not isinstance(result_blocks, list) or not result_blocks:
        return None
    first = result_blocks[0]
    expressions = first.get("expressions") if isinstance(first, dict) else None
    if not isinstance(expressions, list) or not expressions:
        return None
    expr = expressions[0]
    return expr.get("value") if isinstance(expr, dict) else None


# --- Public API ------------------------------------------------------------


def evaluate_entrypoint(
    config: OpaConfig,
    entrypoint: str,
    input_payload: Any,
    data_payload: Mapping[str, Any],
    *,
    workspace: Path | None = None,
) -> Any:
    """Evaluate one Rego entrypoint and return the parsed value.

    Returns ``None`` when the entrypoint is undefined - callers should
    fall back to the rule's default verdict (matches OPA convention
    and the web Creator's ``evalEntrypoint``).
    """
    if workspace is None:
        import tempfile

        with tempfile.TemporaryDirectory(prefix="defenseclaw-opa-") as tmp:
            return _run_opa_eval(
                config=config,
                entrypoint=entrypoint,
                input_payload=input_payload,
                data_payload=data_payload,
                workspace=Path(tmp),
            )
    return _run_opa_eval(
        config=config,
        entrypoint=entrypoint,
        input_payload=input_payload,
        data_payload=data_payload,
        workspace=workspace,
    )


def evaluate_domain(
    config: OpaConfig,
    domain: str,
    input_payload: Any,
    data_payload: Mapping[str, Any],
) -> OpaResult:
    """Evaluate the verdict + reason pair for ``domain``.

    Returns a structured ``OpaResult`` the Live Test pane renders
    directly. Mirrors ``evalDomain`` from the web Creator.
    """
    import tempfile

    verdict_path, reason_path = domain_entrypoints(domain)
    with tempfile.TemporaryDirectory(prefix="defenseclaw-opa-") as tmp:
        workspace = Path(tmp)
        verdict = _run_opa_eval(
            config=config,
            entrypoint=verdict_path,
            input_payload=input_payload,
            data_payload=data_payload,
            workspace=workspace,
        )
        reason: Any = None
        if reason_path:
            reason = _run_opa_eval(
                config=config,
                entrypoint=reason_path,
                input_payload=input_payload,
                data_payload=data_payload,
                workspace=workspace,
            )

    return OpaResult(
        verdict="(undefined)" if verdict is None else str(verdict),
        reason="" if reason is None else str(reason),
        raw={"verdict": verdict, "reason": reason},
    )


def verdict_tone(verdict: str) -> VerdictTone:
    """Map a verdict label to a semantic colour bucket.

    Pinned to the same set of strings as ``verdictTone`` in
    ``opa-eval.ts`` so the Playground header colour-codes verdicts
    identically across web and TUI.
    """
    if verdict in {"allowed", "allow", "clean", "true"}:
        return "positive"
    if verdict in {"warning", "alert", "scan"}:
        return "caution"
    if verdict in {"blocked", "rejected", "block", "deny", "false"}:
        return "negative"
    return "neutral"
