import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MDM = ROOT / "packaging/mdm"


def test_detect_value_formats_document_every_emitted_state() -> None:
    contract = (MDM / "contract/detection.md").read_text(encoding="utf-8")
    table = contract.split("## detect.sh output formats", 1)[1].split("## Versions", 1)[0]
    for os_name in ("linux", "macos"):
        script = (MDM / os_name / "detect.sh").read_text(encoding="utf-8")
        values = set(re.findall(r"dc_report 0 ([-a-z]+)\b", script))
        values.add("tetragon-not-ready")
        for value in values:
            assert f"`{value}`" in table or f"`{value}:" in table, (os_name, value)
    assert "`busy`" in table and "retry" in table.lower()
