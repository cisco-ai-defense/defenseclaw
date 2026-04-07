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

"""Centralised constants for the DefenseClaw Python CLI.

All magic numbers, default strings, header names, and legacy identifiers
that were previously scattered across source files live here so they can
be reviewed and changed in one place.
"""

from __future__ import annotations

# --- Network defaults ---
DEFAULT_SIDECAR_HOST = "127.0.0.1"
DEFAULT_SIDECAR_PORT = 18970
DEFAULT_OPENCLAW_PORT = 18789
DEFAULT_GUARDRAIL_PORT = 4000
DEFAULT_TIMEOUT = 5
SKILL_SCAN_TIMEOUT = 120

# --- Header names ---
HEADER_CLIENT = "X-DefenseClaw-Client"
CLIENT_NAME = "python-cli"

# --- Default paths ---
DEFAULT_DATA_DIR = "~/.defenseclaw"
DEFAULT_OPENCLAW_HOME = "~/.openclaw"
DEFAULT_OPENCLAW_CONFIG = "~/.openclaw/openclaw.json"

# --- Legacy provider prefixes (used in migrations) ---
LEGACY_PROVIDER_PREFIXES = ("defenseclaw/", "litellm/")
LEGACY_PROVIDER_KEYS = ("defenseclaw", "litellm")
