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

# The live connector E2E scripts run on macOS bash 3.2 under set -u.
#
# Bash before 4.4 reports "unbound variable" for "${array[@]}" when the array
# is empty, so a hook invocation that appends optional arguments through an
# array exits 1 on macOS while passing on Linux (GAP-0769, Contract amp cell).
# An array that can be empty must expand as ${array[@]+"${array[@]}"}.

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts" / "live-connector-e2e"

_EMPTY_DECLARATION = re.compile(r"(?:local\s+)?(\w+)=\(\s*\)")
_BARE_EXPANSION = re.compile(r"(?<!\+)\"\$\{(\w+)\[@\]\}\"")


def _bare_expansions_of_possibly_empty_arrays(text: str) -> list[str]:
    declared_empty = set(_EMPTY_DECLARATION.findall(text))
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for match in _BARE_EXPANSION.finditer(line):
            if match.group(1) in declared_empty:
                found.append(f"{number}: {line.strip()}")
    return found


def test_possibly_empty_arrays_expand_safely_under_bash_32():
    offenders = {}
    for path in sorted(SCRIPTS.rglob("*.sh")):
        found = _bare_expansions_of_possibly_empty_arrays(path.read_text(encoding="utf-8"))
        if found:
            offenders[str(path.relative_to(ROOT))] = found
    assert offenders == {}


def test_checker_flags_the_unsafe_form_and_accepts_the_safe_one():
    unsafe = "local a=()\nrun \"${a[@]}\" x\n"
    safe = "local a=()\nrun ${a[@]+\"${a[@]}\"} x\n"
    literal = "b=(one two)\nrun \"${b[@]}\"\n"
    assert _bare_expansions_of_possibly_empty_arrays(unsafe)
    assert _bare_expansions_of_possibly_empty_arrays(safe) == []
    assert _bare_expansions_of_possibly_empty_arrays(literal) == []
