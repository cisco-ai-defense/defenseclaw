"""Keep Secure Client route availability aligned with the gateway API reference."""

import unittest
from pathlib import Path


class SecureClientAPIDocsTest(unittest.TestCase):
    def test_identity_and_ide_routes_are_documented_as_absent(self):
        text = (Path(__file__).resolve().parents[1] / "content/docs/reference/gateway-api.mdx").read_text()
        for route in ("/api/v1/agents/identities", "/api/v1/ai-usage/ide-plugins"):
            row = next(line for line in text.splitlines() if line.startswith("| `GET` | `" + route + "` |"))
            self.assertIn("404", row, route)
            self.assertIn("Secure Client", row, route)


if __name__ == "__main__":
    unittest.main()
