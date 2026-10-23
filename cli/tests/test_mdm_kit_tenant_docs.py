import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PAGE = ROOT / "docs-site/content/docs/enterprise/mdm/intune/tenant.mdx"


def test_macos_identity_row_stays_inside_the_table() -> None:
    page = PAGE.read_text(encoding="utf-8")
    section = page.split("## Identity through Intune", 1)[1].split("## ", 1)[0]
    rows = section.splitlines()
    linux = next(i for i, row in enumerate(rows) if row.startswith("| Linux, enrolled"))
    assert rows[linux + 1].startswith("| macOS, enrolled")
    assert "For that Linux pattern" in "\n".join(rows[linux + 2:])


def test_macos_script_example_uses_an_existing_file_from_helper_directory() -> None:
    page = PAGE.read_text(encoding="utf-8")
    section = page.split("## 5. Assign the package and the health check", 1)[1].split("## Identity through Intune", 1)[0]
    match = re.search(r"macos-script[^\n]*--file\s+(\S+)", section)
    assert match
    helper_dir = ROOT / "packaging/mdm/intune/tenant"
    assert (helper_dir / match.group(1)).is_file(), match.group(1)
    assert "packaging/mdm/intune/tenant" in section
