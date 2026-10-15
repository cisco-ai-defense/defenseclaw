"""Shipped adapter classifications must match the C trust-boundary table."""

import ast
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
ADAPTERS = (
    ROOT / 'integrations/homeassistant/defenseclaw_ha.py',
    ROOT / 'integrations/bubbaloop/defenseclaw_bubbaloop.py',
    ROOT / 'integrations/espclaw/defenseclaw_espclaw.py',
)
C_TABLE = ROOT / 'src/decision/policy_table.c'


class AdapterCapabilityParityTest(unittest.TestCase):
    def test_all_shipped_adapter_names_have_matching_trusted_c_capability(self):
        expected = {}
        for path in ADAPTERS:
            tree = ast.parse(path.read_text())
            maps = [node.value for node in tree.body
                    if isinstance(node, ast.AnnAssign)
                    and isinstance(node.target, ast.Name)
                    and node.target.id.endswith('TOOL_CAP_MAP')]
            self.assertEqual(len(maps), 1, str(path))
            for key, value in zip(maps[0].keys, maps[0].values):
                self.assertIsInstance(key, ast.Constant)
                self.assertIsInstance(value, ast.Name)
                name = key.value
                capability = value.id.removeprefix('CAP_') if hasattr(str, 'removeprefix') else value.id[4:]
                if name in expected:
                    self.assertEqual(expected[name], capability, name)
                expected[name] = capability

        actual = {}
        for name, capability in re.findall(
                r'\{\s*"([^"]+)",\s*DCLAW_CAP_(\w+)\s*\}', C_TABLE.read_text()):
            self.assertNotIn(name, actual, 'duplicate C mapping: ' + name)
            actual[name] = capability
        self.assertGreater(len(expected), 100)
        self.assertEqual({name: actual.get(name) for name in expected}, expected)
        self.assertNotIn('unreviewed_custom_tool', actual)


if __name__ == '__main__':
    unittest.main()
