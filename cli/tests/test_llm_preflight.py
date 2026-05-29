# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for :func:`_llm_picker.preflight_inherit`.

Covers:

* No-candidates short-circuit returns ``None``.
* Per-candidate ping result is captured and returned to the caller.
* Picking ``[R]`` (reconfigure) returns the right action.
* Picking ``[B]`` (back) returns the right action and surfaces through
  ``_maybe_inherit_existing_llm`` as :class:`click.Abort`.
* Choosing a numbered candidate populates ``source_path``.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

import click
from defenseclaw import config as _cfgmod
from defenseclaw.commands import _llm_picker


def _make_cfg_with_judge(d: str):
    cfg_path = os.path.join(d, "config.yaml")
    with open(cfg_path, "w", encoding="utf-8") as f:
        f.write(
            "llm:\n"
            "  provider: anthropic\n"
            "  model: claude-sonnet-4-5\n"
            "guardrail:\n"
            "  enabled: true\n"
            "  judge:\n"
            "    enabled: true\n"
            "    llm:\n"
            "      provider: openai\n"
            "      model: gpt-4o-mini\n"
        )
    prev = os.environ.get("DEFENSECLAW_HOME")
    os.environ["DEFENSECLAW_HOME"] = d
    try:
        return _cfgmod.load()
    finally:
        if prev is None:
            os.environ.pop("DEFENSECLAW_HOME", None)
        else:
            os.environ["DEFENSECLAW_HOME"] = prev


class TestPreflightInherit(unittest.TestCase):
    def test_no_candidates_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "config.yaml"), "w", encoding="utf-8") as f:
                f.write("llm: {}\n")
            prev = os.environ.get("DEFENSECLAW_HOME")
            os.environ["DEFENSECLAW_HOME"] = d
            try:
                cfg = _cfgmod.load()
            finally:
                if prev is None:
                    os.environ.pop("DEFENSECLAW_HOME", None)
                else:
                    os.environ["DEFENSECLAW_HOME"] = prev
            result = _llm_picker.preflight_inherit(cfg, target_path="")
            self.assertIsNone(result)

    def test_inherit_action_captures_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            cfg = _make_cfg_with_judge(d)
            with mock.patch.object(
                _llm_picker, "ping_llm", return_value=(True, "ok"),
            ), mock.patch(
                "click.prompt", side_effect=["1", "i"],
            ):
                result = _llm_picker.preflight_inherit(
                    cfg, target_path="scanners.skill", ping_timeout=0,
                )
            assert result is not None
            self.assertEqual(result["action"], "inherit")
            self.assertIn(result["source_path"], ("llm", "guardrail.judge"))

    def test_ping_failure_does_not_abort(self) -> None:
        """A flaky network must not block the wizard. ``ping_llm``
        returning ``(False, msg)`` should still surface the candidate
        and let the operator pick it.
        """
        with tempfile.TemporaryDirectory() as d:
            cfg = _make_cfg_with_judge(d)
            with mock.patch.object(
                _llm_picker, "ping_llm", return_value=(False, "timeout"),
            ), mock.patch(
                "click.prompt", side_effect=["1", "i"],
            ):
                result = _llm_picker.preflight_inherit(
                    cfg, target_path="scanners.skill", ping_timeout=0,
                )
            assert result is not None
            self.assertEqual(result["action"], "inherit")
            ok, msg = result["ping"]
            self.assertFalse(ok)
            self.assertIn("timeout", msg)

    def test_reconfigure_action_is_recognised(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            cfg = _make_cfg_with_judge(d)
            with mock.patch.object(
                _llm_picker, "ping_llm", return_value=(True, "ok"),
            ), mock.patch("click.prompt", side_effect=["r"]):
                result = _llm_picker.preflight_inherit(
                    cfg, target_path="scanners.skill", ping_timeout=0,
                )
            assert result is not None
            self.assertEqual(result["action"], "reconfigure")

    def test_back_action_propagates(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            cfg = _make_cfg_with_judge(d)
            with mock.patch.object(
                _llm_picker, "ping_llm", return_value=(True, "ok"),
            ), mock.patch("click.prompt", side_effect=["b"]):
                result = _llm_picker.preflight_inherit(
                    cfg, target_path="scanners.skill", ping_timeout=0,
                )
            assert result is not None
            self.assertEqual(result["action"], "back")

    def test_unrecognised_input_reprompts_instead_of_inheriting(self) -> None:
        """Regression: typing garbage at the action prompt must NOT
        silently map to "inherit" (which would overwrite the role's
        config without consent). The wizard re-prompts until the
        operator picks a recognised letter.
        """
        with tempfile.TemporaryDirectory() as d:
            cfg = _make_cfg_with_judge(d)
            # First prompt picks candidate #1; second prompt is the
            # action prompt — feed it a garbage value, then a valid
            # "r" (reconfigure). If the bug were live, the garbage
            # input would have been accepted as "inherit" and the
            # third side_effect would never be consumed.
            prompt_inputs = iter(["1", "garbage-not-a-letter", "r"])
            with mock.patch.object(
                _llm_picker, "ping_llm", return_value=(True, "ok"),
            ), mock.patch(
                "click.prompt", side_effect=lambda *a, **kw: next(prompt_inputs),
            ):
                result = _llm_picker.preflight_inherit(
                    cfg, target_path="scanners.skill", ping_timeout=0,
                )
            assert result is not None
            self.assertEqual(
                result["action"], "reconfigure",
                "garbage input must re-prompt, not silently inherit",
            )


class TestMaybeInheritExistingLLM(unittest.TestCase):
    """The interactive wrapper translates ``back`` → :class:`click.Abort`."""

    def test_back_raises_abort(self) -> None:
        from defenseclaw.commands.cmd_setup import _maybe_inherit_existing_llm

        with tempfile.TemporaryDirectory() as d:
            cfg = _make_cfg_with_judge(d)
            with mock.patch.object(
                _llm_picker, "ping_llm", return_value=(True, "ok"),
            ), mock.patch("click.prompt", side_effect=["b"]):
                with self.assertRaises(click.Abort):
                    _maybe_inherit_existing_llm(
                        cfg,
                        target_path="scanners.skill",
                        inherit_from=None,
                    )

    def test_explicit_inherit_from_skips_preflight(self) -> None:
        from defenseclaw.commands.cmd_setup import _maybe_inherit_existing_llm

        with tempfile.TemporaryDirectory() as d:
            cfg = _make_cfg_with_judge(d)
            with mock.patch.object(_llm_picker, "preflight_inherit") as patched:
                # ``--inherit-from`` short-circuits the preflight UI.
                _maybe_inherit_existing_llm(
                    cfg, target_path="scanners.skill", inherit_from="guardrail",
                )
                patched.assert_not_called()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
