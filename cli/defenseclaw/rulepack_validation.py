# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Secret-safe bridge to the authoritative Go rule-pack validator.

Python owns command ergonomics and doctor rendering only. Rule-pack schemas,
fallback behavior, category handling, and Go/RE2 pattern validity remain owned
by ``defenseclaw-gateway rulepack validate``. In particular, this module never
falls back to a second Python validator when the helper is missing or
incompatible.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Final

from defenseclaw.gateway import resolve_gateway_binary

RULEPACK_WIRE_VERSION: Final = 1
RULEPACK_HELPER_TIMEOUT_SECONDS: Final = 15
_MAX_HELPER_OUTPUT_CHARS: Final = 1_048_576
_SUMMARY_COUNT_FIELDS: Final = (
    "judge_count",
    "judge_category_count",
    "rule_file_count",
    "rule_count",
    "enabled_rule_count",
    "local_pattern_count",
    "suppression_count",
    "sensitive_tool_count",
)
_SUMMARY_FIELDS: Final = frozenset((*_SUMMARY_COUNT_FIELDS, "digest"))
_ERROR_FIELDS: Final = frozenset({"path", "code", "reason"})
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SHA256_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


class RulePackValidationBridgeError(RuntimeError):
    """A bounded, display-safe helper availability or protocol failure."""

    def __init__(self, message: str, *, code: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class RulePackValidationIssue:
    path: str
    code: str
    reason: str


@dataclass(frozen=True)
class RulePackValidationResult:
    wire_version: int
    kind: str
    valid: bool
    summary: dict[str, int | str] | None = None
    error: RulePackValidationIssue | None = None

    def to_wire_dict(self) -> dict[str, Any]:
        """Return a deterministic, JSON-serializable copy of the wire result."""
        payload: dict[str, Any] = {
            "wire_version": self.wire_version,
            "kind": self.kind,
            "valid": self.valid,
        }
        if self.summary is not None:
            payload["summary"] = dict(self.summary)
        if self.error is not None:
            payload["error"] = {
                "path": self.error.path,
                "code": self.error.code,
                "reason": self.error.reason,
            }
        return payload


def validate_rule_pack(
    path: str,
    *,
    gateway_binary: str | None = None,
) -> RulePackValidationResult:
    """Validate *path* with the canonical offline Go validator.

    A syntactically valid invalid-pack response is returned to the caller even
    though the helper exits non-zero. Missing helpers, execution failures, and
    protocol drift raise :class:`RulePackValidationBridgeError`; callers must
    not reinterpret those states as successful validation.
    """
    binary = gateway_binary if gateway_binary is not None else resolve_gateway_binary()
    if not binary:
        raise RulePackValidationBridgeError(
            "defenseclaw-gateway is required for authoritative rule-pack validation; "
            "run defenseclaw upgrade",
            code="gateway_unavailable",
        )

    try:
        completed = subprocess.run(
            [binary, "rulepack", "validate", "--dir", path, "--json"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=RULEPACK_HELPER_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RulePackValidationBridgeError(
            "rule-pack validation helper timed out",
            code="gateway_timeout",
        ) from exc
    except UnicodeError as exc:
        raise RulePackValidationBridgeError(
            "rule-pack validation helper returned malformed text; run defenseclaw upgrade",
            code="protocol_error",
        ) from exc
    except OSError as exc:
        raise RulePackValidationBridgeError(
            "rule-pack validation helper could not be started; run defenseclaw upgrade",
            code="gateway_unavailable",
        ) from exc

    stdout = completed.stdout
    if not isinstance(stdout, str) or len(stdout) > _MAX_HELPER_OUTPUT_CHARS:
        raise RulePackValidationBridgeError(
            "rule-pack validation helper returned an invalid response; run defenseclaw upgrade",
            code="protocol_error",
        )
    try:
        payload = json.loads(stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RulePackValidationBridgeError(
            "rule-pack validation helper returned malformed JSON; run defenseclaw upgrade",
            code="protocol_error",
        ) from exc
    if not isinstance(payload, dict):
        raise RulePackValidationBridgeError(
            "rule-pack validation helper returned an invalid response; run defenseclaw upgrade",
            code="protocol_error",
        )

    result = _decode_wire(payload)
    if completed.returncode == 0 and not result.valid:
        raise RulePackValidationBridgeError(
            "rule-pack validation helper returned an incompatible success response; "
            "run defenseclaw upgrade",
            code="protocol_error",
        )
    if completed.returncode != 0 and result.valid:
        raise RulePackValidationBridgeError(
            "rule-pack validation helper returned an incompatible failure response; "
            "run defenseclaw upgrade",
            code="protocol_error",
        )
    return result


def safe_display_path(path: str) -> str:
    """Quote an operator/config path without emitting terminal control bytes."""
    return json.dumps(str(path), ensure_ascii=True)


def bridge_error_wire(error: RulePackValidationBridgeError) -> dict[str, Any]:
    """Represent a local bridge failure using the same safe error envelope."""
    return {
        "wire_version": RULEPACK_WIRE_VERSION,
        "kind": "validation_error",
        "valid": False,
        "error": {
            "path": "$",
            "code": error.code,
            "reason": str(error),
        },
    }


def _decode_wire(payload: dict[str, Any]) -> RulePackValidationResult:
    if payload.get("wire_version") != RULEPACK_WIRE_VERSION:
        raise _protocol_error()
    kind = payload.get("kind")
    valid = payload.get("valid")
    if type(valid) is not bool:
        raise _protocol_error()

    if kind == "validation" and valid:
        if set(payload) != {"wire_version", "kind", "valid", "summary"}:
            raise _protocol_error()
        summary = _decode_summary(payload.get("summary"))
        return RulePackValidationResult(
            wire_version=RULEPACK_WIRE_VERSION,
            kind="validation",
            valid=True,
            summary=summary,
        )

    if kind == "validation_error" and not valid:
        if set(payload) != {"wire_version", "kind", "valid", "error"}:
            raise _protocol_error()
        issue = _decode_issue(payload.get("error"))
        return RulePackValidationResult(
            wire_version=RULEPACK_WIRE_VERSION,
            kind="validation_error",
            valid=False,
            error=issue,
        )

    raise _protocol_error()


def _decode_summary(value: Any) -> dict[str, int | str]:
    if not isinstance(value, dict) or set(value) != _SUMMARY_FIELDS:
        raise _protocol_error()
    summary: dict[str, int | str] = {}
    for field in _SUMMARY_COUNT_FIELDS:
        count = value.get(field)
        if type(count) is not int or count < 0:
            raise _protocol_error()
        summary[field] = count
    digest = value.get("digest")
    if not isinstance(digest, str) or _SHA256_DIGEST.fullmatch(digest) is None:
        raise _protocol_error()
    summary["digest"] = digest
    return summary


def _decode_issue(value: Any) -> RulePackValidationIssue:
    if not isinstance(value, dict) or set(value) != _ERROR_FIELDS:
        raise _protocol_error()
    path = value.get("path")
    code = value.get("code")
    reason = value.get("reason")
    if (
        not _safe_text(path, maximum=512, allow_empty=False)
        or not isinstance(code, str)
        or _SAFE_CODE.fullmatch(code) is None
        or not _safe_text(reason, maximum=1_000, allow_empty=False)
    ):
        raise _protocol_error()
    return RulePackValidationIssue(path=path, code=code, reason=reason)


def _safe_text(value: Any, *, maximum: int, allow_empty: bool) -> bool:
    return (
        isinstance(value, str)
        and (allow_empty or bool(value))
        and len(value) <= maximum
        and _CONTROL_CHARACTERS.search(value) is None
    )


def _protocol_error() -> RulePackValidationBridgeError:
    return RulePackValidationBridgeError(
        "rule-pack validation helper protocol is incompatible; run defenseclaw upgrade",
        code="protocol_error",
    )
