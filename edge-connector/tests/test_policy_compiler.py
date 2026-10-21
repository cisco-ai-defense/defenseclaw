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
                ('unknown_sequence_cap',
                 'iot_extensions:\n  destination_allowlist: []\n  capability_sequences:\n'
                 '    - sequence: [net_fetch, exec_shel]\n      action: block\n', ()),
                ('long_sequence',
                 'iot_extensions:\n  destination_allowlist: []\n  capability_sequences:\n'
                 '    - sequence: [read_fs, net_fetch, read_fs, net_fetch, exec_shell]\n'
                 '      action: block\n', ()),
                ('unknown_sequence_action',
                 'iot_extensions:\n  destination_allowlist: []\n  capability_sequences:\n'
                 '    - sequence: [net_fetch, exec_shell]\n      action: deny\n', ()),
                ('too_many_sequences',
                 'iot_extensions:\n  destination_allowlist: []\n  capability_sequences:\n'
                 + '    - sequence: [net_fetch, exec_shell]\n      action: block\n' * 17, ()),
                ('too_many_destinations',
                 'iot_extensions:\n  destination_allowlist:\n'
                 + ''.join(f'    - 8.8.{i}.1\n' for i in range(33)), ()),
                ('runtime_block',
                 'skill_actions:\n  high:\n    runtime: block\n'
                 'iot_extensions:\n  destination_allowlist: []\n', ()),
                ('allowlist_string',
                 "iot_extensions:\n  destination_allowlist: '8.8.8.8'\n", ()),
                ('allowlist_empty_string',
                 "iot_extensions:\n  destination_allowlist: ''\n", ()),
                ('allowlist_mapping',
                 'iot_extensions:\n  destination_allowlist:\n    8.8.8.8: true\n', ()),
                ('allowlist_scalar', 'iot_extensions:\n  destination_allowlist: 5\n', ()),
                ('missing_allowlist', 'iot_extensions:\n  canary:\n    baseline_blocks_per_min: 2\n', ()),
                ('reserved_version', VALID.read_text(), ('--version', '65535')),
                ('oversize', VALID.read_text(), ('--target-partition-size', '1')),
            ):
                with self.subTest(name=name):
                    policy = work / f'{name}.yaml'
                    policy.write_text(source)
                    result = self.compile(work, policy, *extra)
                    self.assertEqual(result.returncode, 65, result.stderr)
                    self.assertIn('Invalid policy:', result.stderr)
                    self.assertFalse((work / 'policy.bin').exists())
                    self.assertFalse((work / 'policy_tables.h').exists())

    def test_four_step_sequence_and_known_runtime_values_compile(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            policy = work / 'ok.yaml'
            policy.write_text(
                'skill_actions:\n  critical:\n    runtime: disable\n'
                '  high:\n    runtime: warn\n  low:\n    runtime: enable\n'
                'iot_extensions:\n  destination_allowlist: []\n  capability_sequences:\n'
                '    - sequence: [sensor_read, net_fetch, read_fs, exec_shell]\n'
                '      action: block\n')
            result = self.compile(work, policy)
            self.assertEqual(result.returncode, 0, result.stderr)
            header = (work / 'policy_tables.h').read_text()
            self.assertIn('sequence_rules_count = 1;', header)

    def test_checked_in_tables_match_compiler(self):
        """generated/policy_tables.h is built from policies/strict.yaml."""
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            result = self.compile(work, VALID)
            self.assertEqual(result.returncode, 0, result.stderr)
            generated = (work / 'policy_tables.h').read_text()
        checked_in = (ROOT / 'generated' / 'policy_tables.h').read_text()
        self.assertEqual(generated, checked_in,
                         'regenerate generated/policy_tables.h from policies/strict.yaml')
        self.assertIn('"ignore all previous instructions"', checked_in)

    def test_environment_fault_remains_distinct(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            result = self.compile(work, work / 'missing.yaml')
            self.assertEqual(result.returncode, 1, result.stderr)

    def test_bracketed_ipv6_allowlist_entry_is_normalized(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            policy = work / 'v6.yaml'
            policy.write_text("iot_extensions:\n  destination_allowlist:\n    - '[2606:4700:4700::1111]'\n")
            result = self.compile(work, policy)
            self.assertEqual(result.returncode, 0, result.stderr)
            header = (work / 'policy_tables.h').read_text()
            self.assertIn('"2606:4700:4700::1111"', header)
            self.assertNotIn('[2606:', header)

    def test_production_flag_matches_go_parser(self):
        """Without a signing key, any Go-production value refuses to compile."""
        for raw, refuses in (('on', True), (' TRUE ', True), ('yes', True),
                             ('0', False), ('off', False), ('', False)):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as temp:
                work = Path(temp)
                env = os.environ.copy()
                env.pop('DCLAW_DEV_MODE', None)
                env['DCLAW_PRODUCTION'] = raw
                result = subprocess.run(
                    [sys.executable, str(COMPILER), '--input', str(VALID),
                     '--output-header', 'policy_tables.h', '--output-binary', 'policy.bin'],
                    cwd=work, env=env, text=True, capture_output=True)
                if refuses:
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertIn('production mode', result.stderr)
                    self.assertFalse((work / 'policy.bin').exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_valid_policy_compiles(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            result = self.compile(work, VALID)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertGreater((work / 'policy.bin').stat().st_size, 64)


if __name__ == '__main__':
    unittest.main()
