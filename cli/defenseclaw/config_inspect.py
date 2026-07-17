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

"""Secret-safe bridge to the canonical Go configuration-v8 compiler.

The Python CLI owns command ergonomics and rendering only. Effective policy,
defaults, destination capabilities, profile expansion, and validation remain
owned by ``defenseclaw-gateway config-v8``. This module never places source or
secret values on argv and never falls back to an independent Python compiler.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from defenseclaw.gateway import resolve_gateway_binary

CONFIG_V8_WIRE_VERSION: Final = 2
CONFIG_V8_HELPER_TIMEOUT_SECONDS: Final = 15
_OPERATIONS: Final = frozenset({"validate", "effective"})
_REFERENCE_FORMATS: Final = frozenset({"yaml", "markdown"})
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_EXEC_CONTROL_ENVIRONMENT_NAMES = frozenset(
    {
        "PATH",
        "NODE_PATH",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
    }
)
_EXEC_CONTROL_ENVIRONMENT_PREFIXES = ("LD_", "DYLD_")


class ConfigInspectError(RuntimeError):
    """A bounded, display-safe helper invocation or protocol failure."""


@dataclass(frozen=True)
class ConfigV8WireResult:
    wire_version: int
    kind: str
    config_version: int
    source: str
    data_dir: str
    plan_digest: str
    network_validation: str
    gateway_api_port: int = 18970
    valid: bool | None = None
    effective: dict[str, Any] | None = None


def inspect_v8_config(
    operation: str,
    *,
    config_path: str,
    data_dir: str | None = None,
    environment_overrides: Mapping[str, str] | None = None,
    gateway_binary: str | None = None,
) -> ConfigV8WireResult:
    """Run one versioned Go helper operation and validate its JSON wire."""

    if operation not in _OPERATIONS:
        raise ValueError(f"unsupported config-v8 operation {operation!r}")
    argv = _helper_argv(
        operation,
        config_path=config_path,
        data_dir=data_dir,
        gateway_binary=gateway_binary,
    )
    completed = _run(argv, environment_overrides=environment_overrides)
    if completed.returncode != 0:
        raise ConfigInspectError(_helper_failure(completed.stderr, operation))
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ConfigInspectError("configuration helper returned malformed JSON; run defenseclaw upgrade") from exc
    if not isinstance(payload, dict):
        raise ConfigInspectError("configuration helper returned an invalid response; run defenseclaw upgrade")
    return _decode_wire(payload, operation)


def config_v8_schema() -> str:
    """Return the exact embedded canonical JSON Schema from the Go binary."""

    completed = _run(_helper_argv("schema"))
    if completed.returncode != 0:
        raise ConfigInspectError(_helper_failure(completed.stderr, "schema"))
    try:
        schema = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ConfigInspectError(
            "configuration helper returned malformed JSON Schema; run defenseclaw upgrade"
        ) from exc
    if not isinstance(schema, dict) or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise ConfigInspectError("configuration helper returned an incompatible JSON Schema; run defenseclaw upgrade")
    return json.dumps(schema, indent=2, ensure_ascii=False) + "\n"


def config_v8_reference(fmt: str, *, section: str = "observability") -> str:
    """Return a generated reference artifact embedded in the Go binary."""

    normalized = fmt.strip().lower()
    if normalized not in _REFERENCE_FORMATS:
        raise ValueError(f"unsupported reference format {fmt!r}")
    argv = _helper_argv("reference", extra=("--section", section, "--format", normalized))
    completed = _run(argv)
    if completed.returncode != 0:
        raise ConfigInspectError(_helper_failure(completed.stderr, "reference"))
    if not completed.stdout.strip():
        raise ConfigInspectError("configuration helper returned an empty reference; run defenseclaw upgrade")
    return completed.stdout


def _helper_argv(
    operation: str,
    *,
    config_path: str | None = None,
    data_dir: str | None = None,
    gateway_binary: str | None = None,
    extra: tuple[str, ...] = (),
) -> list[str]:
    binary = gateway_binary if gateway_binary is not None else resolve_gateway_binary()
    if not binary:
        raise ConfigInspectError(
            "defenseclaw-gateway is required for canonical v8 configuration inspection; run defenseclaw upgrade"
        )
    argv = [binary, "config-v8", operation]
    if config_path:
        argv.extend(("--config", config_path))
    if data_dir:
        argv.extend(("--data-dir", data_dir))
    argv.extend(extra)
    return argv


def _run(
    argv: list[str],
    *,
    environment_overrides: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = None
    if environment_overrides is not None:
        environment = _validation_environment(environment_overrides)
    try:
        if environment is None:
            return subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=CONFIG_V8_HELPER_TIMEOUT_SECONDS,
                check=False,
            )
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=CONFIG_V8_HELPER_TIMEOUT_SECONDS,
            check=False,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        raise ConfigInspectError("configuration helper timed out without producing a result") from exc
    except OSError as exc:
        raise ConfigInspectError("configuration helper could not be started; run defenseclaw upgrade") from exc


def _validation_environment(overrides: Mapping[str, str]) -> dict[str, str]:
    """Merge protected validator values without placing them on argv.

    The observability-v8 activation transaction supplies only secret values
    promoted from legacy inline/header configuration. Names are validated and
    values containing NUL are rejected before ``subprocess`` sees them. Error
    text never contains a name or value.
    """

    if len(overrides) > 4_096:
        raise ConfigInspectError("configuration helper environment overrides are invalid")
    result = {
        name: value
        for name, value in os.environ.items()
        if not _is_exec_control_environment_name(name)
    }
    for name in overrides:
        value = overrides[name]
        if (
            not isinstance(name, str)
            or _ENVIRONMENT_NAME.fullmatch(name) is None
            or not isinstance(value, str)
            or "\x00" in value
        ):
            raise ConfigInspectError("configuration helper environment overrides are invalid")
        if _is_exec_control_environment_name(name):
            continue
        result[name] = value
    return result


def _is_exec_control_environment_name(name: str) -> bool:
    upper = name.upper()
    return upper in _EXEC_CONTROL_ENVIRONMENT_NAMES or upper.startswith(
        _EXEC_CONTROL_ENVIRONMENT_PREFIXES
    )


def _decode_wire(payload: dict[str, Any], operation: str) -> ConfigV8WireResult:
    expected_kind = "validation" if operation == "validate" else "effective"
    if payload.get("wire_version") != CONFIG_V8_WIRE_VERSION:
        raise ConfigInspectError("configuration helper protocol is incompatible; run defenseclaw upgrade")
    if payload.get("kind") != expected_kind or payload.get("config_version") != 8:
        raise ConfigInspectError("configuration helper returned an incompatible response; run defenseclaw upgrade")
    effective = payload.get("effective")
    if operation == "effective" and not isinstance(effective, dict):
        raise ConfigInspectError("configuration helper omitted the effective plan; run defenseclaw upgrade")
    valid = payload.get("valid")
    if operation == "validate" and valid is not True:
        raise ConfigInspectError(
            "configuration helper returned an invalid validation response; run defenseclaw upgrade"
        )
    for field in ("source", "data_dir", "plan_digest", "network_validation"):
        if not isinstance(payload.get(field), str):
            raise ConfigInspectError("configuration helper returned an incomplete response; run defenseclaw upgrade")
    gateway_api_port = payload.get("gateway_api_port")
    if (
        isinstance(gateway_api_port, bool)
        or not isinstance(gateway_api_port, int)
        or not 1 <= gateway_api_port <= 65535
    ):
        raise ConfigInspectError("configuration helper returned an incomplete response; run defenseclaw upgrade")
    return ConfigV8WireResult(
        wire_version=CONFIG_V8_WIRE_VERSION,
        kind=expected_kind,
        config_version=8,
        source=payload["source"],
        data_dir=payload["data_dir"],
        plan_digest=payload["plan_digest"],
        network_validation=payload["network_validation"],
        gateway_api_port=gateway_api_port,
        valid=valid if isinstance(valid, bool) else None,
        effective=effective,
    )


def _helper_failure(stderr: str | None, operation: str) -> str:
    detail = _safe_detail(stderr)
    if detail:
        return detail
    return f"canonical configuration {operation} failed; correct config.yaml and retry"


def _safe_detail(value: str | None) -> str:
    """Bound helper diagnostics and strip terminal-control payloads."""

    if not value:
        return ""
    cleaned = _CONTROL_CHARACTERS.sub("", value).strip()
    if len(cleaned) > 2_000:
        cleaned = cleaned[:2_000] + "…"
    return cleaned
