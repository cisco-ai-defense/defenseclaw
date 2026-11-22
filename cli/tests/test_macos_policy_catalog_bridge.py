# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Run the macOS app's policy catalog bridge tests against this CLI.

The app ships ``policy_catalog_bridge.py`` and runs it with the installed
runtime's Python, so its tests need the DefenseClaw package: they run here
rather than in ``make macos-app-test-scripts`` (macOS UPDATING.md).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_TESTS = Path(__file__).resolve().parents[2] / "macos/DefenseClawMac/Tests/PolicyCatalogBridgeTests.py"
_spec = importlib.util.spec_from_file_location("macos_policy_catalog_bridge_tests", _TESTS)
assert _spec is not None and _spec.loader is not None
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)

PolicyCatalogBridgeTests = _module.PolicyCatalogBridgeTests
