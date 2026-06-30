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

"""Shared filtering for filesystem-backed plugin inventories."""

from __future__ import annotations

import os


def plugin_directory_entries(root: str) -> list[tuple[str, str]]:
    """Return eligible immediate plugin directories under *root*.

    Connector plugin roots also contain transient download caches and hidden
    activation/staging directories. Those entries are implementation details,
    not enabled plugins, so every inventory surface must exclude them.
    """
    if not os.path.isdir(root):
        return []
    try:
        entries = sorted(os.listdir(root))
    except OSError:
        return []

    eligible: list[tuple[str, str]] = []
    for entry in entries:
        if entry == "cache" or entry.startswith("."):
            continue
        path = os.path.join(root, entry)
        if os.path.isdir(path):
            eligible.append((entry, path))
    return eligible
