import re
from pathlib import Path

README = Path(__file__).resolve().parents[2] / "packaging/mdm/intune/tenant/README.md"


def test_tenant_readme_relative_inline_paths_resolve() -> None:
    text = README.read_text(encoding="utf-8")
    paths = re.findall(r"`((?:\.\./)+[^`]+)`", text)
    assert paths
    for relative in paths:
        path = README.parent / relative
        if "*" in relative:
            assert list(path.parent.glob(path.name)), relative
        else:
            assert path.exists(), relative
