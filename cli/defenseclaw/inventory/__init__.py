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

"""Inventory helpers — agent discovery and OpenClaw AIBOM indexing."""

from defenseclaw.inventory.agent_discovery import (
    AgentDiscovery,
    AgentSignal,
    discover_agents,
    first_installed,
    render_discovery_table,
)
from defenseclaw.inventory.claw_inventory import (
    build_claw_aibom,
    claw_aibom_to_scan_result,
    format_claw_aibom_human,
)

__all__ = [
    "AgentDiscovery",
    "AgentSignal",
    "build_claw_aibom",
    "claw_aibom_to_scan_result",
    "discover_agents",
    "format_claw_aibom_human",
    "first_installed",
    "render_discovery_table",
]
