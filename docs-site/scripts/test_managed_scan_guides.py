"""Keep per-user scan examples from misleading managed-host readers."""

from pathlib import Path
import unittest


GUIDES = Path(__file__).resolve().parents[1] / "content/docs/scanning"


class ManagedScanGuideTest(unittest.TestCase):
    def test_skill_guide_gives_managed_route_before_per_user_steps(self):
        before_steps = (GUIDES / "skill-scanner.mdx").read_text().split("## Steps", 1)[0]
        self.assertIn("managed Linux and macOS", before_steps)
        self.assertIn("defenseclaw-gateway scan skill", before_steps)
        self.assertIn("install watcher", before_steps)

    def test_mcp_guide_gives_managed_route_before_per_user_steps(self):
        before_steps = (GUIDES / "mcp-scanner.mdx").read_text().split("## Steps", 1)[0]
        self.assertIn("managed Linux and macOS", before_steps)
        self.assertIn("defenseclaw-gateway scan mcp", before_steps)
        self.assertIn("connector's MCP configuration", before_steps)

    def test_managed_windows_reference_distinguishes_unfinished_mcp_scan(self):
        reference = (GUIDES.parent / "enterprise/windows.mdx").read_text()
        failed_scans = reference.split("- **Failed scans.**", 1)[1].split("- **`take_action: false`.**", 1)[0]
        self.assertIn("unverified_server: warn", failed_scans)
        self.assertIn("unverified_server: block", failed_scans)


if __name__ == "__main__":
    unittest.main()
