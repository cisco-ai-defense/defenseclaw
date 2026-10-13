from __future__ import annotations


def test_low_space_audit_open_error_names_disk_cause(tmp_path, monkeypatch) -> None:
    from types import SimpleNamespace

    from defenseclaw import audit_capacity

    monkeypatch.setattr(
        audit_capacity.shutil, "disk_usage",
        lambda _path: SimpleNamespace(free=119 * 1024 * 1024),
    )
    detail = audit_capacity.audit_open_failure_notice(
        str(tmp_path / "audit.db"), RuntimeError("unable to open database file")
    )
    assert "too little usable space" in detail
    assert "119 MiB" in detail
