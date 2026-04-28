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

"""Guardrail module — back-compat shim re-exporting connector-aware helpers.

This file used to mix three concerns: API-key/model detection,
master-key derivation, and OpenClaw config patching. S4.4 of the
claw-agnostic plan split it into two focused modules:

* :mod:`defenseclaw.llm_keys` — connector-agnostic API-key + model
  helpers (``detect_api_key_env``, ``model_to_proxy_name``,
  ``derive_master_key``).
* :mod:`defenseclaw.openclaw_guardrail` — OpenClaw-specific config
  patching (``patch_openclaw_config``, ``restore_openclaw_config``,
  ``uninstall_openclaw_plugin``, ``record_pristine_backup``,
  ``pristine_backup_path``, ``detect_current_model``, plus the
  internal ``_backup`` / ``_register_plugin_in_config`` /
  ``_preserve_ownership`` helpers).

Existing call sites — ``cmd_setup``, ``cmd_doctor``,
``cmd_uninstall``, and ``tests/test_guardrail.py`` — continue to
``from defenseclaw.guardrail import …`` exactly as before. New code
that only needs the connector-agnostic surface should import from
:mod:`defenseclaw.llm_keys` directly so it doesn't re-acquire a
transitive OpenClaw dependency.
"""

from __future__ import annotations

# Public connector-agnostic surface.
from defenseclaw.llm_keys import (
    derive_master_key as _derive_master_key,
)
from defenseclaw.llm_keys import (
    detect_api_key_env,
    model_to_proxy_name,
)

# Public OpenClaw-specific surface.
# Underscore-prefixed helpers — kept exported for the legacy test
# surface (tests/test_guardrail.py imports several of these directly).
# NEW code should not import these from here; reach into
# :mod:`defenseclaw.openclaw_guardrail` instead.
from defenseclaw.openclaw_guardrail import (  # noqa: F401
    BACKUP_INDEX_FILENAME,
    BACKUP_SUBDIR,
    _backup,
    _backup_index_path,
    _expand,
    _install_codeguard_skill_deferred,
    _preserve_ownership,
    _read_backup_index,
    _register_plugin_in_config,
    _remove_from_plugins_allow,
    _unregister_plugin_from_config,
    _write_backup_index,
    detect_current_model,
    patch_openclaw_config,
    pristine_backup_path,
    record_pristine_backup,
    restore_openclaw_config,
    uninstall_openclaw_plugin,
)

__all__ = [
    # Connector-agnostic
    "_derive_master_key",
    "detect_api_key_env",
    "model_to_proxy_name",
    # OpenClaw-specific
    "BACKUP_INDEX_FILENAME",
    "BACKUP_SUBDIR",
    "detect_current_model",
    "patch_openclaw_config",
    "pristine_backup_path",
    "record_pristine_backup",
    "restore_openclaw_config",
    "uninstall_openclaw_plugin",
    # Internal helpers (back-compat for tests)
    "_backup",
    "_backup_index_path",
    "_expand",
    "_install_codeguard_skill_deferred",
    "_preserve_ownership",
    "_read_backup_index",
    "_register_plugin_in_config",
    "_remove_from_plugins_allow",
    "_unregister_plugin_from_config",
    "_write_backup_index",
]
