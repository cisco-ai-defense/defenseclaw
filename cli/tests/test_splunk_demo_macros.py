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

"""The local Splunk app's demo macros read the fields the v8 HEC adapter emits."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MACROS = REPO_ROOT / "bundles/splunk_local_bridge/splunk/apps/defenseclaw_local_mode/default/macros.conf"
HEC = REPO_ROOT / "internal/observability/destinations/push/splunk_hec.go"


def test_body_fields_are_read_under_the_hec_record() -> None:
    """GAP-0093: the v8 HEC event nests the canonical record under "record"
    (with a few top-level compatibility aliases), so a body attribute arrives as
    the flattened field record.body.<key>. Every macro that reads 'body.<key>'
    reads 'record.body.<key>' first; the AI Runtime Planes panels and the kernel
    macros showed (unknown) and 0 on live HEC data without it."""
    assert '`"event":{"record":`' in HEC.read_text(encoding="utf-8"), "the HEC envelope changed: recheck the macros"
    text = MACROS.read_text(encoding="utf-8")
    reads = re.findall(r"coalesce\('body\.([A-Za-z0-9_.]+)'", text) + re.findall(r", 'body\.([A-Za-z0-9_.]+)'", text)
    assert reads, "no macro reads a body field"
    missing = sorted({key for key in reads if f"coalesce('record.body.{key}', 'body.{key}'" not in text})
    assert not missing, f"macros read body fields without the record.body field the HEC event carries: {missing}"
    # Nothing reads a body field outside a coalesce that offers the HEC name.
    bare = [m.group(0) for m in re.finditer(r"(?<![.\w])'body\.[A-Za-z0-9_.]+'", text)]
    assert len(bare) == len(reads), f"a body field read outside coalesce('record.body...', ...): {bare}"
