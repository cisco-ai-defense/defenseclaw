# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""LiteLLM bridge telemetry and error classification (``defenseclaw.llm``)."""

from __future__ import annotations

import importlib
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, __import__("os").path.abspath(__import__("os").path.join(__import__("os").path.dirname(__file__), "..")))

from defenseclaw.gateway_error_codes import ERR_LLM_BRIDGE_ERROR  # noqa: E402


def _fake_litellm_module(resp: MagicMock | None, exc: BaseException | None) -> types.ModuleType:
    m = types.ModuleType("litellm")

    def completion(**_kwargs: object) -> MagicMock:
        if exc is not None:
            raise exc
        assert resp is not None
        return resp

    m.completion = completion
    return m


class LLMBridgeTests(unittest.TestCase):
    def test_success_returns_no_error_code(self) -> None:
        resp = MagicMock()
        resp.choices = [MagicMock(message=MagicMock(content="ok"))]
        resp.usage = MagicMock(prompt_tokens=1, completion_tokens=2, total_tokens=3)
        resp.model = "openai/gpt-4o"
        fake = _fake_litellm_module(resp, None)
        with patch.dict(sys.modules, {"litellm": fake}):
            import defenseclaw.llm as llm_mod

            importlib.reload(llm_mod)
            out = llm_mod.call_llm(
                {"messages": [{"role": "user", "content": "hi"}], "model": "openai/gpt-4o"},
            )
        self.assertIsNone(out.get("error"))
        self.assertIsNone(out.get("error_code"))

    def test_timeout_emits_error_code(self) -> None:
        fake = _fake_litellm_module(None, TimeoutError("boom"))
        with patch.dict(sys.modules, {"litellm": fake}):
            import defenseclaw.llm as llm_mod

            importlib.reload(llm_mod)
            out = llm_mod.call_llm(
                {"messages": [{"role": "user", "content": "hi"}], "model": "openai/gpt-4o"},
            )
        self.assertIsNotNone(out.get("error"))
        self.assertEqual(out.get("error_code"), ERR_LLM_BRIDGE_ERROR)


if __name__ == "__main__":
    unittest.main()
