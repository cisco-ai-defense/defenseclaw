"""Regression checks for enterprise guide commands and examples."""

import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

DOCS = Path(__file__).resolve().parents[1] / "content/docs/enterprise"


class EnterpriseGuideDocsTest(unittest.TestCase):
    def test_restaging_rule_pack_removes_deleted_files(self):
        guide = (DOCS / "mdm/index.mdx").read_text()
        section = guide.split("## Stage a custom macOS rule pack", 1)[1]
        script = section.split("```sh\n", 1)[1].split("```", 1)[0]
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "source"
            dest = Path(root) / "dest"
            source.mkdir()
            (source / "kept.yaml").write_text("kept")
            stale = source / "removed.yaml"
            stale.write_text("removed")
            script = script.replace(
                "PACK_SOURCE=/path/to/mdm-payload/acme",
                f"PACK_SOURCE={shlex.quote(str(source))}",
            ).replace(
                "PACK_DEST=/opt/cisco/defenseclaw/etc/policies/guardrail/acme",
                f"PACK_DEST={shlex.quote(str(dest))}",
            ).replace("install -d -o root -g wheel -m 0755", "install -d -m 0755")
            script = "\n".join(
                line for line in script.splitlines()
                if not line.startswith(("chown ", "find "))
            )
            subprocess.run(["sh", "-eu", "-c", script], check=True)
            self.assertTrue((dest / "removed.yaml").exists())
            stale.unlink()
            subprocess.run(["sh", "-eu", "-c", script], check=True)
            self.assertFalse((dest / "removed.yaml").exists())
            self.assertEqual((dest / "kept.yaml").read_text(), "kept")

    def test_windows_allow_rule_uses_site_specific_placeholders(self):
        guide = (DOCS / "windows.mdx").read_text()
        section = guide.split("### Release a blocked or quarantined skill", 1)[1]
        example = section.split('```yaml title="Admin config"\n', 1)[1].split("```", 1)[0]
        self.assertNotRegex(example, r"dcw-[a-z0-9]+|epa-high")
        self.assertIn("<account>", example)
        self.assertIn("Replace `<account>`", section)


if __name__ == "__main__":
    unittest.main()
