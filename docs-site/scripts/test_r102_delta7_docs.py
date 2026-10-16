"""Regression checks for round 1.0.2 DELTA-7 (rel-1-0-2:GAP-0487, GAP-0485).

The sandbox pages must name the OpenShell release setup installs, which is
InstallerVersion in internal/openshell/version.go, and the guide must say
how DefenseClaw checks a gateway's mTLS before bind mounts on 0.1.3.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs-site/content/docs"
PAGES = (
    "sandboxes/linux.mdx",
    "sandboxes/guide.mdx",
    "sandboxes/macos.mdx",
    "sandboxes/apps.mdx",
    "macos-app.mdx",
    "reference/sandbox-cli.mdx",
    "tui.mdx",
)


def installer_version():
    text = (ROOT / "internal/openshell/version.go").read_text()
    return re.search(r'InstallerVersion = "(\d+\.\d+\.\d+)"', text).group(1)


def page(path):
    return (DOCS / path).read_text()


class R102Delta7DocsTest(unittest.TestCase):
    def test_pages_name_the_release_setup_installs(self):
        v = installer_version()
        self.assertIn(f"**Installs OpenShell {v}**", page("sandboxes/guide.mdx"))
        self.assertIn(f"**Installs OpenShell {v}**", page("sandboxes/macos.mdx"))
        self.assertIn(f"- **OpenShell {v}** is installed", page("sandboxes/linux.mdx"))
        self.assertIn(f"Install OpenShell {v} with NVIDIA's installer?", page("sandboxes/linux.mdx"))
        self.assertIn(f"Release     v{v} (NVIDIA OpenShell upstream installer)", page("sandboxes/linux.mdx"))
        self.assertIn(f"older than {v} in place", page("reference/sandbox-cli.mdx"))

    def test_every_install_and_upgrade_target_is_the_pinned_release(self):
        v = installer_version()
        patterns = (
            r"[Ii]nstalls? OpenShell (\d+\.\d+\.\d+)",
            r"upgrades? (?:OpenShell |it )?(?:to )?(\d+\.\d+\.\d+) in\s+place",
            r"to (\d+\.\d+\.\d+)\s+in\s+place",
            r"the upgrade to\s+(\d+\.\d+\.\d+)",
            r"\((\d+\.\d+\.\d+) available\)",
            r"installs the (\d+\.\d+\.\d+) package",
            r"Release\s+v(\d+\.\d+\.\d+)",
        )
        for rel in PAGES:
            text = page(rel)
            for pat in patterns:
                for m in re.finditer(pat, text):
                    with self.subTest(page=rel, text=m.group(0)):
                        self.assertEqual(m.group(1), v)

    def test_guide_explains_the_api_level_mtls_check(self):
        text = page("sandboxes/guide.mdx")
        self.assertIn("From 0.1.3 the gateway lets a client without a certificate finish the", text)
        self.assertIn("and refuses that client's API calls. Before it enables bind mounts", text)
        self.assertIn("DefenseClaw checks that refusal, and that the gateway has no OIDC", text)


if __name__ == "__main__":
    unittest.main()
