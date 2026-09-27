# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Native Windows install state written by pre-release builds.

Pre-release native Windows builds made after 0.8.10 could select a connector
this release no longer ships and record that connector's home bindings in
``installer/install-state.json``. The uninstaller's closed-schema check
accepts those fields and selections so such an install can still be removed;
nothing reads their values. The Go Setup mirrors this list in
``cmd/defenseclaw-setup/retired_install_state.go``. These two files are the
only code that names these connectors
(``cli/tests/test_retired_connector_names.py`` allowlists both).
"""

from __future__ import annotations

# Home-binding fields older states carry.
RETIRED_INSTALL_STATE_FIELDS: frozenset[str] = frozenset(
    {
        "windsurf_user_home",
        "windsurf_hooks_path",
        "gemini_cli_home",
        "gemini_config_dir",
    }
)

# Connector selections older states may record.
RETIRED_INSTALL_STATE_CONNECTORS: frozenset[str] = frozenset({"windsurf", "geminicli"})
