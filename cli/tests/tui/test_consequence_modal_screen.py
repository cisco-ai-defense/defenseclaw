# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Generic consequence modal screen tests."""

from __future__ import annotations

from defenseclaw.tui.screens.consequence import (
    CommandSpec,
    ConsequenceAction,
    ConsequenceModalModel,
)


def _model() -> ConsequenceModalModel:
    return ConsequenceModalModel(
        title="Dangerous action",
        summary="Review the destination state before continuing.",
        details=("First consequence.", "Second consequence."),
        consequence="This is the confirmation step.",
        actions=(
            ConsequenceAction(
                action_id="preview",
                hotkey="p",
                label="Preview",
                description="Dry run only.",
                command=CommandSpec("defenseclaw", ("uninstall", "--dry-run"), "uninstall dry-run"),
            ),
            ConsequenceAction(
                action_id="run",
                hotkey="u",
                label="Run",
                description="Mutates local state.",
                command=CommandSpec("defenseclaw", ("uninstall", "--yes"), "uninstall --yes"),
                danger=True,
            ),
        ),
        default_action_id="preview",
    )


def test_consequence_model_resolves_default_and_hotkey() -> None:
    model = _model()

    assert model.default_action().action_id == "preview"
    assert model.action_for_hotkey("U").action_id == "run"
    assert model.action_for_hotkey("x") is None


def test_consequence_action_display_label_escapes_hotkey_brackets() -> None:
    """Hotkey labels must escape the opening bracket so Rich renders
    ``[p] Preview`` as literal text instead of treating ``p`` as a
    style name (which raises ``MissingStyle`` and crashes the modal).
    """

    action = ConsequenceAction(action_id="preview", hotkey="p", label="Preview", description="Dry run only.")
    assert action.display_label.startswith("\\[p]")
    assert "Preview" in action.display_label

    bare = ConsequenceAction(action_id="cancel", label="Cancel", description="")
    assert bare.display_label == "Cancel"
