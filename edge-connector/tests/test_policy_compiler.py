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

"""Policy input errors must be distinguishable from compiler environment errors."""

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
COMPILER = ROOT / 'tools' / 'policy_compiler.py'
VALID = ROOT / 'policies' / 'strict.yaml'


class PolicyCompilerExitTest(unittest.TestCase):
    def compile(self, work: Path, policy: Path, *extra: str):
        env = os.environ.copy()
        env.pop('DCLAW_PRODUCTION', None)
        env.pop('DCLAW_DEV_MODE', None)
        return subprocess.run([sys.executable, str(COMPILER), '--input', str(policy),
                               '--output-header', 'policy_tables.h',
                               '--output-binary', 'policy.bin', *extra],
                              cwd=work, env=env, text=True, capture_output=True)

    def test_input_errors_return_dataerr_without_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            for name, source, extra in (
                ('syntax', 'name: [broken\n', ()),
                ('shape', '[]\n', ()),
                ('hostname', 'iot_extensions:\n  destination_allowlist:\n    - api.openai.com\n', ()),
                ('private_ip', 'iot_extensions:\n  destination_allowlist:\n    - 127.0.0.1\n', ()),
                ('unsupported', 'iot_extensions:\n  trust_boundaries:\n    infer_from_context: true\n', ()),
                ('unsupported_content', 'iot_extensions:\n  content_inspection:\n    enabled: true\n', ()),
                ('unsupported_ssrf', 'iot_extensions:\n  ssrf_protection:\n    enabled: true\n', ()),
                ('unsupported_cloud', 'iot_extensions:\n  cloud_escalation:\n    include_content: true\n', ()),
                ('unsupported_broker', 'iot_extensions:\n  broker_fallback: []\n', ()),
                ('unsupported_canary', 'iot_extensions:\n  canary:\n    enabled: true\n', ()),
                ('unsupported_rate', 'iot_extensions:\n  rate_limits:\n    tool_calls_per_minute: 1\n', ()),
                ('unsupported_escalation', 'iot_extensions:\n  escalation_mode:\n    net_fetch: sync_block\n', ()),
                ('policy_name', 'name: 1\n', ()),
                ('sequence_action', 'iot_extensions:\n  capability_sequences:\n    - sequence: [read_fs, send_msg]\n      action: typo\n', ()),
                ('sequence_type', 'iot_extensions:\n  capability_sequences:\n    - sequence: read_fs\n', ()),
                ('unknown_capability', 'iot_extensions:\n  capability_sequences:\n    - sequence: [read_fs, typo]\n', ()),
                ('long_sequence', 'iot_extensions:\n  capability_sequences:\n    - sequence: [read_fs, read_fs, read_fs, read_fs, send_msg]\n', ()),
                ('runtime_action', 'skill_actions:\n  critical:\n    runtime: typo\n', ()),
                ('unknown_severity', 'skill_actions:\n  typo:\n    runtime: disable\n', ()),
                ('canary_type', 'iot_extensions:\n  canary:\n    baseline_blocks_per_min: true\n', ()),
                ('reserved_version', VALID.read_text(), ('--version', '65535')),
                ('oversize', VALID.read_text(), ('--target-partition-size', '1')),
            ):
                with self.subTest(name=name):
                    work = Path(temp) / name
                    work.mkdir()
                    policy = work / f'{name}.yaml'
                    policy.write_text(source)
                    result = self.compile(work, policy, *extra)
                    self.assertEqual(result.returncode, 65, result.stderr)
                    self.assertIn('Invalid policy:', result.stderr)
                    self.assertFalse((work / 'policy.bin').exists())
                    self.assertFalse((work / 'policy_tables.h').exists())

    def test_environment_fault_remains_distinct(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            result = self.compile(work, work / 'missing.yaml')
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('Cannot read policy input:', result.stderr)
            self.assertNotIn('Traceback', result.stderr)
            self.assertFalse((work / 'policy.bin').exists())
            self.assertFalse((work / 'policy_tables.h').exists())

    def test_valid_policy_compiles(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            result = self.compile(work, VALID)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertGreater((work / 'policy.bin').stat().st_size, 64)

    def test_ipv6_allowlist_entries_are_written_without_brackets(self):
        # rel-1-0-4 GAP-0592: dclaw_policy_check_destination compares the
        # destination host with its brackets removed, so only the bare
        # literal can match; a bracketed entry is refused with the form to use.
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            for dest in ('2606:4700:4700::1111', '2001:4860:4860::8888'):
                with self.subTest(dest=dest):
                    policy = work / 'ipv6.yaml'
                    policy.write_text(f'iot_extensions:\n  destination_allowlist:\n    - "[{dest}]"\n')
                    result = self.compile(work, policy)
                    self.assertEqual(result.returncode, 65, result.stderr)
                    self.assertIn(f"without brackets ('{dest}')", result.stderr)
                    self.assertFalse((work / 'policy.bin').exists())
                    policy.write_text(f'iot_extensions:\n  destination_allowlist:\n    - "{dest}"\n')
                    result = self.compile(work, policy)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f'"{dest}"', (work / 'policy_tables.h').read_text())
                    (work / 'policy.bin').unlink()

    def test_the_policies_page_examples_compile(self):
        # Every policy on docs-site .../edge-connector/policies.mdx compiles
        # with the command the page shows, and the bracketed form of each
        # IPv6 entry it lists is refused, as the page says (GAP-0592).
        docs_dir = ROOT.parent / 'docs-site' / 'content' / 'docs'
        page = (docs_dir / 'edge-connector' / 'policies.mdx').read_text()
        blocks = re.findall(r'```yaml[^\n]*\n(.*?)```', page, re.S)
        self.assertGreaterEqual(len(blocks), 4)
        ipv6 = [dest for block in blocks for dest in re.findall(r'- "([0-9a-f:]*:[0-9a-f:]*)"', block)]
        self.assertTrue(ipv6, 'the page shows no IPv6 allowlist entry')
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            for index, block in enumerate(blocks):
                with self.subTest(block=index):
                    policy = work / f'page-{index}.yaml'
                    policy.write_text(block)
                    result = self.compile(work, policy, '--profile', 'standard', '--version', '1')
                    self.assertEqual(result.returncode, 0, f'{block}\n{result.stderr}')
            for dest in ipv6:
                policy = work / 'bracketed.yaml'
                policy.write_text(f'iot_extensions:\n  destination_allowlist:\n    - "[{dest}]"\n')
                self.assertEqual(self.compile(work, policy).returncode, 65)
                self.assertIn(f'`[{dest}]`', page)


if __name__ == '__main__':
    unittest.main()
