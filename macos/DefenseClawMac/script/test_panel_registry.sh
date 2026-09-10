#!/bin/bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
#
# Every PanelID must appear in MainWindow's sidebar groups.
#
# A panel can be fully implemented -- enum case, title, icon, view, decoder,
# passing model tests -- and still be unreachable, because the sidebar is
# driven by a separate hand-maintained list. That is exactly what happened to
# the Runtime panel: it shipped complete and no user could open it. Nothing
# else catches this; compiling both files together would drag in all of
# SwiftUI, so check the two sources against each other instead.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_STATE="$ROOT/DefenseClawMac/App/AppState.swift"
MAIN_WINDOW="$ROOT/DefenseClawMac/Features/MainWindow.swift"

for required in "$APP_STATE" "$MAIN_WINDOW"; do
  if [ ! -f "$required" ]; then
    echo "test_panel_registry: missing $required" >&2
    exit 1
  fi
done

python3 - "$APP_STATE" "$MAIN_WINDOW" <<'PY'
import re
import sys

app_state = open(sys.argv[1], encoding="utf-8").read()
main_window = open(sys.argv[2], encoding="utf-8").read()

enum = re.search(
    r"enum PanelID:[^{]*\{(.*?)\n\s*var id\b", app_state, re.S
)
if not enum:
    raise SystemExit("test_panel_registry: could not find the PanelID enum")

cases: list[str] = []
for line in enum.group(1).splitlines():
    stripped = line.strip()
    if not stripped.startswith("case "):
        continue
    body = stripped[len("case "):]
    if "(" in body:  # a case with associated values is not a sidebar panel
        continue
    for name in body.split(","):
        name = name.split("=")[0].strip()
        if name:
            cases.append(name)

if not cases:
    raise SystemExit("test_panel_registry: parsed no PanelID cases; the check is broken")

groups = re.search(r"private let groups:[^=]*=\s*\[(.*?)\n\s*\]", main_window, re.S)
if not groups:
    raise SystemExit("test_panel_registry: could not find MainWindow.groups")
listed = set(re.findall(r"\.([A-Za-z][A-Za-z0-9]*)", groups.group(1)))

missing = [case for case in cases if case not in listed]
if missing:
    raise SystemExit(
        "test_panel_registry: these panels exist but no sidebar group lists them, "
        "so no user can open them: " + ", ".join(missing)
    )

print(f"test_panel_registry: all {len(cases)} panels are reachable from the sidebar")
PY
