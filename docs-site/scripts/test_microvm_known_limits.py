"""Keep the OpenShell 0.1.6 MicroVM known limit aligned across docs."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return " ".join((ROOT / path).read_text(encoding="utf-8").split())


def release_limit(version: str) -> str:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    release = changelog.split(f"## [Unreleased] — {version}", 1)[1]
    release = release.split("## [Unreleased]", 1)[0]
    release = release.split("### Known limits", 1)[-1] if "### Known limits" in release else ""
    for line in release.splitlines():
        if line.startswith("- **") and "OpenShell 0.1.6" in line and "MicroVM" in line:
            return " ".join(line.split())
    return ""


def section(path: str, start: str, end: str) -> str:
    body = read(path)
    if start not in body:
        return ""
    return body.split(start, 1)[1].split(end, 1)[0]


class MicroVMKnownLimitsTest(unittest.TestCase):
    def test_gap0615_linux_kvm_scope_and_remedies(self):
        pages = {
            "1.0.8 known limits": release_limit("1.0.8"),
            "1.0.9 known limits": release_limit("1.0.9"),
            "Linux sandbox guide": section(
                "docs-site/content/docs/sandboxes/linux.mdx",
                "## Run sandboxes in MicroVMs with KVM", "## One OpenShell gateway per machine"),
            "OpenShell sandbox guide": section(
                "docs-site/content/docs/sandboxes/guide.mdx",
                "#### MicroVM create is refused on Linux with KVM", "#### OpenShell issues"),
            "managed sandbox guide": section(
                "docs-site/content/docs/enterprise/sandboxes.mdx",
                "### The docker fallback", "### The MicroVM driver"),
        }
        for name, body in pages.items():
            with self.subTest(page=name):
                for phrase in (
                    "OpenShell 0.1.6", "Linux with KVM", "per-user", "managed",
                    "defenseclaw sandbox setup", "enterprise.openshell.driver: docker",
                    "driver_fallback: docker", "does not cover this refusal",
                ):
                    self.assertTrue(phrase in body, f"{name} lacks {phrase}")
        self.assertNotIn("per-user (non-root) OpenShell gateway", release_limit("1.0.8"))
        self.assertNotIn("Sandboxes created before 1.0.8 still start", release_limit("1.0.8"))
        changed = section("CHANGELOG.md", "## [Unreleased] — 1.0.8", "### Known limits")
        self.assertNotIn("Known limits for MicroVMs on a per-user OpenShell gateway", changed)

    def test_gap0615_docker_default_and_macos_caveat(self):
        self.assertIn("The compute driver is `docker` unless you choose MicroVMs.",
                      read("docs-site/content/docs/sandboxes/linux.mdx"))
        self.assertIn("The default is `vm` on macOS and `docker` on Linux.",
                      read("docs-site/content/docs/enterprise/sandboxes.mdx"))
        self.assertIn("macOS may be affected the same way.", release_limit("1.0.8"))


if __name__ == "__main__":
    unittest.main()
