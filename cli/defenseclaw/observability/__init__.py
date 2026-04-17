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

"""Observability setup helpers.

Provides a small preset registry for telemetry destinations (gateway
OTel exporter + ``audit_sinks``) plus the writer used by
``defenseclaw setup observability`` and the ``setup splunk`` back-compat
aliases.
"""

from defenseclaw.observability.presets import (
    PRESETS,
    Preset,
    preset_choices,
    resolve_preset,
)
from defenseclaw.observability.writer import (
    Destination,
    WriteResult,
    apply_preset,
    list_destinations,
    remove_destination,
    set_destination_enabled,
)

__all__ = [
    "PRESETS",
    "Destination",
    "Preset",
    "WriteResult",
    "apply_preset",
    "list_destinations",
    "preset_choices",
    "remove_destination",
    "resolve_preset",
    "set_destination_enabled",
]
