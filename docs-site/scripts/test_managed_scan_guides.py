"""Keep per-user scan examples from misleading managed-host readers."""

from pathlib import Path
import unittest


GUIDES = Path(__file__).resolve().parents[1] / "content/docs/scanning"


class ManagedScanGuideTest(unittest.TestCase):
    def test_skill_guide_gives_managed_route_before_per_user_steps(self):
        before_steps = (GUIDES / "skill-scanner.mdx").read_text().split("## Steps", 1)[0]
        self.assertIn("managed Linux and macOS", before_steps)
        # GAP-1527/GAP-1234: the managed Linux and macOS packages install the
        # scanners, so the guide gives the administrator's managed-gateway scan.
        self.assertIn("sudo /opt/defenseclaw/bin/defenseclaw-gateway scan skill /path/to/skill", before_steps)
        self.assertIn("sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway scan skill /path/to/skill", before_steps)
        self.assertIn("outside home and temporary folders", before_steps)
        self.assertIn("support-matrix#managed-linux-and-macos-scans", before_steps)

    def test_mcp_guide_gives_managed_route_before_per_user_steps(self):
        before_steps = (GUIDES / "mcp-scanner.mdx").read_text().split("## Steps", 1)[0]
        self.assertIn("managed Linux and macOS", before_steps)
        self.assertIn("sudo /opt/defenseclaw/bin/defenseclaw-gateway scan mcp URL", before_steps)
        self.assertIn("sudo /opt/cisco/defenseclaw/bin/defenseclaw-gateway scan mcp URL", before_steps)
        self.assertNotIn("install watcher scans it", before_steps)
        self.assertIn("connector's MCP configuration", before_steps)
        self.assertIn("support-matrix#managed-linux-and-macos-scans", before_steps)

    def test_known_limits_names_the_managed_unix_scanner_limit(self):
        limits = (GUIDES.parent / "support-matrix.mdx").read_text()
        section = limits.split("## Managed Linux and macOS scans", 1)[1].split("\n## ", 1)[0]
        self.assertIn("install the skill, MCP and plugin scanners", section)
        self.assertIn("cannot read home folders or temporary folders", section)
        self.assertIn("has no scanners", section)

    def test_managed_windows_reference_distinguishes_unfinished_mcp_scan(self):
        reference = (GUIDES.parent / "enterprise/windows.mdx").read_text()
        failed_scans = reference.split("- **Failed scans.**", 1)[1].split("- **`take_action: false`.**", 1)[0]
        self.assertIn("unverified_server: warn", failed_scans)
        self.assertIn("unverified_server: block", failed_scans)


if __name__ == "__main__":
    unittest.main()
