from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "packaging/identity/entra/Add-EntraGroupToLocalGroup.ps1"


def test_qualified_group_cannot_fall_through_to_a_local_namesake() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    resolver = source.split("function Resolve-LocalGroup", 1)[1].split("\n$group =", 1)[0]
    assert "[Environment]::MachineName" in resolver
    assert "$localSid.Value -ne $sid.Value" in resolver
    assert "Exit-WithError" in resolver.split("$localSid.Value -ne $sid.Value", 1)[1]
    assert source.index("$localSid.Value -ne $sid.Value") < source.index(
        "[DcIdentityKit.LocalGroupApi]::Members"
    )
    assert "DisplayName" in resolver
    assert "$group.DisplayName" in source
