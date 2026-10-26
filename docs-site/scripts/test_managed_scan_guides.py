"""Keep per-user scan examples from misleading managed-host readers."""

from pathlib import Path
import unittest


GUIDES = Path(__file__).resolve().parents[1] / "content/docs/scanning"


class ManagedScanGuideTest(unittest.TestCase):
    def test_skill_guide_gives_managed_route_before_per_user_steps(self):
        before_steps = (GUIDES / "skill-scanner.mdx").read_text().split("## Steps", 1)[0]
        self.assertIn("managed Linux and macOS", before_steps)
        # GAP-1234: managed Linux and macOS have no skill scanner; the guide
        # gives the exact scan that runs there and never the one that cannot.
        self.assertNotIn("defenseclaw-gateway scan skill", before_steps)
        self.assertIn("sudo /opt/defenseclaw/bin/defenseclaw-gateway scan code /path/to/skill", before_steps)
        self.assertIn("sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway scan code /path/to/skill", before_steps)
        self.assertIn("known-limits#managed-linux-and-macos-scans", before_steps)

    def test_mcp_guide_gives_managed_route_before_per_user_steps(self):
        before_steps = (GUIDES / "mcp-scanner.mdx").read_text().split("## Steps", 1)[0]
        self.assertIn("managed Linux and macOS", before_steps)
        self.assertNotIn("defenseclaw-gateway scan mcp", before_steps)
        self.assertNotIn("install watcher scans it", before_steps)
        self.assertIn("connector's MCP configuration", before_steps)
        self.assertIn("known-limits#managed-linux-and-macos-scans", before_steps)

    def test_known_limits_names_the_managed_unix_scanner_limit(self):
        limits = (GUIDES.parents[1] / "troubleshooting/known-limits.mdx").read_text()
        section = limits.split("## Managed Linux and macOS scans", 1)[1].split("\n## ", 1)[0]
        self.assertIn("include no skill, MCP or plugin scanner", section)
        self.assertIn("scan code PATH", section)

    def test_managed_windows_reference_distinguishes_unfinished_mcp_scan(self):
        reference = (GUIDES.parent / "enterprise/windows.mdx").read_text()
        failed_scans = reference.split("- **Failed scans.**", 1)[1].split("- **`take_action: false`.**", 1)[0]
        self.assertIn("unverified_server: warn", failed_scans)
        self.assertIn("unverified_server: block", failed_scans)


if __name__ == "__main__":
    unittest.main()
