# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Policy Creator TUI subsystem.

Ports the docs-site web Policy Creator (`docs-site/components/policy-creator/`)
into a Textual modal screen subsystem. Layered as:

* ``types.py``         - Python dataclasses mirroring ``types.ts``.
* ``presets.py``       - Loader for bundled preset YAML/JSON.
* ``draft.py``         - ``PolicyDraftModel`` - in-flight edit state with
                          file-based persistence + diff vs preset.
* ``validators.py``    - Phase 8: regex/RE2/secret/risky-config lints.
* ``emit.py``          - Phase 7: ``Policy`` -> wheel-ready YAML/JSON.
* ``opa_eval.py``      - Phase 9: subprocess wrapper around ``opa eval``.
* ``answers.py``       - Quick-Start option catalogues (postures, blocks).
* ``screens/``         - Phase 10/11: ``QuickStartScreen``,
                          ``PlaygroundScreen``.
"""

from __future__ import annotations

from defenseclaw.tui.creator import (
    answers,
    apply,
    command_palette,
    data_projection,
    diff,
    draft,
    emit,
    emit_script,
    opa_eval,
    presets,
    rego_lint,
    scenarios,
    share,
    types,
    validators,
    wizard,
)

__all__ = [
    "answers",
    "apply",
    "command_palette",
    "data_projection",
    "diff",
    "draft",
    "emit",
    "emit_script",
    "opa_eval",
    "presets",
    "rego_lint",
    "scenarios",
    "share",
    "types",
    "validators",
    "wizard",
]
