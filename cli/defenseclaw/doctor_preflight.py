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

"""Read-only startup diagnostics for ``defenseclaw doctor``.

The root CLI normally constructs the runtime configuration before dispatching a
subcommand. Doctor is also a recovery surface, so a loader failure must not
prevent it from reporting the canonical raw-source validation result. This
module deliberately owns no repair or persistence behavior.
"""

from __future__ import annotations

from dataclasses import dataclass

_MAX_DIAGNOSTICS = 32
_MAX_DETAIL_CHARS = 2_000


@dataclass(frozen=True)
class DoctorStartupCheck:
    """One bounded check that Doctor can render without a runtime config."""

    status: str
    label: str
    detail: str


@dataclass(frozen=True)
class DoctorStartupDiagnostics:
    """Structured fallback produced when the runtime config cannot load."""

    checks: tuple[DoctorStartupCheck, ...]
    remediation: str


def _bounded_detail(value: object) -> str:
    """Return one control-safe, bounded diagnostic line."""

    rendered = " ".join(str(value).replace("\x00", "").split())
    if len(rendered) <= _MAX_DETAIL_CHARS:
        return rendered
    return rendered[: _MAX_DETAIL_CHARS - 3] + "..."


def inspect_doctor_config_load_failure(load_error: BaseException) -> DoctorStartupDiagnostics:
    """Inspect the raw config after runtime loading failed.

    ``validate_config`` uses the canonical v8 validator and does not construct a
    runtime ``Config`` or initialize the audit database. If that validator is
    unavailable, Doctor still reports the bounded loader failure and the
    validator's exception type instead of aborting before its own output starts.
    """

    from defenseclaw.commands.cmd_config import validate_config

    remediation = (
        "Run `defenseclaw config validate` for the complete raw-source report, "
        "repair or upgrade the configuration, then rerun `defenseclaw doctor`."
    )
    loader_type = type(load_error).__name__
    loader_detail = _bounded_detail(load_error)
    checks: list[DoctorStartupCheck] = []

    try:
        validation = validate_config()
    except Exception as validation_error:  # noqa: BLE001 - recovery must remain available.
        checks.append(
            DoctorStartupCheck(
                "fail",
                "Config load",
                f"runtime loader failed ({loader_type}: {loader_detail}); {remediation}",
            )
        )
        checks.append(
            DoctorStartupCheck(
                "warn",
                "Raw config validation",
                "canonical validation was unavailable "
                f"({type(validation_error).__name__}); no startup mutation was attempted",
            )
        )
        return DoctorStartupDiagnostics(tuple(checks), remediation)

    path = _bounded_detail(getattr(validation, "path", "") or "(configuration path unavailable)")
    if bool(getattr(validation, "exists", False)):
        checks.append(DoctorStartupCheck("pass", "Config file", path))
    else:
        checks.append(
            DoctorStartupCheck(
                "fail",
                "Config file",
                f"not found at {path}; run `defenseclaw init` or `defenseclaw quickstart`",
            )
        )

    parse_error = _bounded_detail(getattr(validation, "parse_error", "") or "")
    if parse_error:
        checks.append(DoctorStartupCheck("fail", "Config parse", parse_error))

    for error in list(getattr(validation, "errors", ()) or ())[:_MAX_DIAGNOSTICS]:
        checks.append(DoctorStartupCheck("fail", "Config validation", _bounded_detail(error)))
    for warning in list(getattr(validation, "warnings", ()) or ())[:_MAX_DIAGNOSTICS]:
        checks.append(DoctorStartupCheck("warn", "Config validation", _bounded_detail(warning)))

    if bool(getattr(validation, "ok", False)):
        detail = (
            f"canonical raw-source validation passed, but the runtime loader failed "
            f"({loader_type}: {loader_detail}); {remediation}"
        )
    else:
        detail = (
            f"runtime loader rejected the configuration ({loader_type}); "
            f"no startup mutation or automatic repair was attempted. {remediation}"
        )
    checks.append(DoctorStartupCheck("fail", "Config load", detail))
    return DoctorStartupDiagnostics(tuple(checks), remediation)
