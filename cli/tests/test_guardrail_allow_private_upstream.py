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

"""GAP-1406: ``guardrail allow-private-upstream`` allows a private LLM endpoint
(an AWS VPC endpoint for Bedrock) without hand-editing config.yaml."""

from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from defenseclaw.commands.cmd_guardrail import guardrail
from tests.helpers import cleanup_app, make_app_context

HOST = "bedrock-runtime.us-east-1.amazonaws.com"


def _resolves_to(*ips: str):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443)) for ip in ips]


class AllowPrivateUpstreamTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()
        self.runner = CliRunner()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _run(self, *args: str):
        return self.runner.invoke(guardrail, ["allow-private-upstream", *args], obj=self.app,
                                  catch_exceptions=False)

    def test_a_hostname_adds_its_private_addresses_and_remove_drops_them(self):
        with patch("socket.getaddrinfo", return_value=_resolves_to("10.0.2.169", "10.0.3.65")):
            added = self._run(HOST)
        self.assertEqual(added.exit_code, 0, added.output)
        self.assertEqual(self.app.cfg.guardrail.allow_private_upstreams, ["10.0.2.169", "10.0.3.65"])
        self.assertIn("defenseclaw-gateway restart", added.output)
        listed = self._run()
        self.assertIn("10.0.2.169, 10.0.3.65", listed.output)
        removed = self._run("--remove", "10.0.2.169")
        self.assertEqual(removed.exit_code, 0, removed.output)
        self.assertEqual(self.app.cfg.guardrail.allow_private_upstreams, ["10.0.3.65"])

    def test_metadata_loopback_and_cidr_are_refused(self):
        for target in ("169.254.169.254", "127.0.0.1", "10.0.0.0/8"):
            result = self.runner.invoke(guardrail, ["allow-private-upstream", target], obj=self.app)
            self.assertNotEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.app.cfg.guardrail.allow_private_upstreams, [])

    def test_a_public_address_is_not_stored(self):
        with patch("socket.getaddrinfo", return_value=_resolves_to("52.94.1.10")):
            result = self._run(HOST)
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("public address", result.output)
        self.assertEqual(self.app.cfg.guardrail.allow_private_upstreams, [])


if __name__ == "__main__":
    unittest.main()
