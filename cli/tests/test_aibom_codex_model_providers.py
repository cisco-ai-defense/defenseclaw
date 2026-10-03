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

"""GAP-2101: AIBOM reads Codex model providers from config.toml, and an
unsupported empty category reads "not collected" instead of 0 / none."""

from __future__ import annotations

import io
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from defenseclaw.inventory import claw_inventory
from defenseclaw.inventory.claw_inventory import _model_providers_for_connector
from rich.console import Console

from tests.environment import isolated_home_env

_CONFIG = """\
model = "us.openai.gpt-5.6-luna"
model_provider = "bedrock-runtime"

[model_providers.bedrock-runtime]
name = "Amazon Bedrock"
base_url = "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1"
env_key = "DCTEST_BEDROCK_KEY"
wire_api = "responses"
http_headers = { "X-Test-Header" = "header-value-not-for-bom" }

[model_providers.other]
name = "Other"
base_url = "https://user:pw-not-for-bom@other.example.com/v1"
"""


class CodexModelProvidersTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="dc-gap2101-")
        self.codex_home = os.path.join(self.tmp, ".codex")
        os.makedirs(self.codex_home)
        env = {**isolated_home_env(self.tmp), "CODEX_HOME": self.codex_home, "DCTEST_BEDROCK_KEY": "k"}
        self.env = patch.dict(os.environ, env)
        self.env.start()
        for var in ("OPENAI_BASE_URL", "OPENAI_API_KEY"):
            os.environ.pop(var, None)

    def tearDown(self) -> None:
        self.env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, text: str) -> None:
        with open(os.path.join(self.codex_home, "config.toml"), "w") as fh:
            fh.write(text)

    def test_providers_come_from_config_toml_without_secrets(self) -> None:
        self._write(_CONFIG)
        rows = _model_providers_for_connector("codex", None)
        by_id = {r["id"]: r for r in rows}
        self.assertEqual(set(by_id), {"bedrock-runtime", "other"})
        active = by_id["bedrock-runtime"]
        self.assertTrue(active["active"])
        self.assertEqual(active["model"], "us.openai.gpt-5.6-luna")
        self.assertEqual(active["env_key"], "DCTEST_BEDROCK_KEY")
        self.assertTrue(active["api_key_present"])
        self.assertFalse(by_id["other"]["active"])
        self.assertEqual(by_id["other"]["base_url"], "https://other.example.com/v1")
        self.assertNotIn("not-for-bom", repr(rows))

    def test_model_without_provider_is_builtin_openai_with_env(self) -> None:
        self._write('model = "gpt-5"\n')
        os.environ["OPENAI_BASE_URL"] = "https://proxy.example.com/v1"
        rows = _model_providers_for_connector("codex", None)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "openai")
        self.assertEqual(rows[0]["model"], "gpt-5")
        self.assertEqual(rows[0]["base_url"], "https://proxy.example.com/v1")

    def test_human_output_lists_codex_provider(self) -> None:
        self._write(_CONFIG)
        inv = {
            "connector": "codex",
            "model_providers": _model_providers_for_connector("codex", None),
            "limitations": [],
        }
        out = _render(inv)
        self.assertIn("bedrock-runtime (active)", out)
        self.assertIn("us.openai.gpt-5.6-luna", out)
        self.assertNotIn("Model providers: none", out)


    def test_unparsable_config_is_an_error_not_zero_providers(self) -> None:
        # GAP-2148: an invalid config.toml read as "Model providers: none".
        self._write("model = gpt-edge-test\n")
        from defenseclaw.config import default_config

        inv = claw_inventory.build_claw_aibom(default_config(), categories={"models"}, connector="codex")
        self.assertEqual(inv["model_providers"], [])
        self.assertEqual([e["command"] for e in inv["errors"]], ["codex:models"])
        self.assertIn("config.toml", inv["errors"][0]["error"])
        out = _render(inv)
        self.assertIn("Model providers: not collected", out)
        self.assertNotIn("Model providers: none", out)
        self.assertIn("codex:models", out)


class NotCollectedRenderingTests(unittest.TestCase):
    def test_unsupported_empty_category_reads_not_collected(self) -> None:
        inv = {
            "connector": "hermes",
            "model_providers": [],
            "limitations": [
                {"connector": "hermes", "category": "models", "status": "unsupported", "reason": "r"},
            ],
        }
        out = _render(inv)
        self.assertIn("Model providers: not collected", out)
        self.assertNotIn("Model providers: none", out)
        row = next(line for line in out.splitlines() if line.lstrip().startswith("Model providers") and "│" in line)
        self.assertIn("not collected", row)
        self.assertNotIn(" 0 ", row)


def _render(inv: dict) -> str:
    buf = io.StringIO()
    console = Console(file=buf, width=120, color_system=None)
    with patch("rich.console.Console", return_value=console):
        claw_inventory.format_claw_aibom_human(inv)
    return buf.getvalue()


if __name__ == "__main__":
    unittest.main()
