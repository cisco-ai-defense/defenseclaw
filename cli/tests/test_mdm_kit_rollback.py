from pathlib import Path


def test_intune_rollback_removes_the_new_required_assignment_first() -> None:
    root = Path(__file__).resolve().parents[2]
    page = (root / "docs-site/content/docs/enterprise/mdm/intune/windows.mdx").read_text(encoding="utf-8")
    section = page.split("**Roll back.**", 1)[1].split("## 7.", 1)[0]
    assert section.index("remove the newer **Required** Intune assignment") < section.index(
        "[Roll back](/docs/enterprise/operate/lifecycle#roll-back)"
    )
