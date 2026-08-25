"""Inventory sweeps must persist findings only when the inventory changes.

The sweep re-runs on ai_discovery.process_interval_s across every active
connector; unconditional persistence wrote ~42 identical INFO rows per minute.
"""

from types import SimpleNamespace

from defenseclaw.inventory.claw_inventory import (
    claw_aibom_changed,
    claw_aibom_digest,
)


def _cfg(tmp_path):
    return SimpleNamespace(data_dir=str(tmp_path))


def _inv(plugins=("a", "b")):
    return {
        "skills": [],
        "plugins": [{"name": n} for n in plugins],
        "mcp": [],
        "agents": [],
        "tools": [],
        "model_providers": [],
        "memory": [],
    }


def test_unchanged_inventory_is_persisted_once(tmp_path):
    cfg = _cfg(tmp_path)
    inv = _inv()
    assert claw_aibom_changed(inv, cfg) is True, "first sweep must persist"
    for _ in range(5):
        assert claw_aibom_changed(inv, cfg) is False, "repeat sweeps must not persist"


def test_real_change_is_persisted(tmp_path):
    cfg = _cfg(tmp_path)
    assert claw_aibom_changed(_inv(("a",)), cfg) is True
    assert claw_aibom_changed(_inv(("a",)), cfg) is False
    assert claw_aibom_changed(_inv(("a", "b")), cfg) is True
    assert claw_aibom_changed(_inv(("a", "b")), cfg) is False


def test_connectors_tracked_independently(tmp_path):
    cfg = _cfg(tmp_path)
    assert claw_aibom_changed(_inv(), cfg, connector="claudecode") is True
    assert claw_aibom_changed(_inv(), cfg, connector="codex") is True
    assert claw_aibom_changed(_inv(), cfg, connector="claudecode") is False
    assert claw_aibom_changed(_inv(), cfg, connector="codex") is False


def test_provenance_churn_is_not_a_change(tmp_path):
    cfg = _cfg(tmp_path)
    first = _inv()
    first["plugins"][0]["provenance"] = {"binary": "0.8.6", "run": "1"}
    assert claw_aibom_changed(first, cfg) is True

    second = _inv()
    second["plugins"][0]["provenance"] = {"binary": "0.8.6", "run": "2"}
    assert claw_aibom_changed(second, cfg) is False, "provenance stamp must not count as drift"


def test_digest_is_order_stable():
    a = {"plugins": [{"name": "x", "ver": 1}], "skills": []}
    b = {"skills": [], "plugins": [{"ver": 1, "name": "x"}]}
    assert claw_aibom_digest(a) == claw_aibom_digest(b)


def test_unwritable_state_dir_falls_back_to_logging(tmp_path):
    """Losing an inventory record is worse than writing a duplicate."""
    cfg = SimpleNamespace(data_dir=str(tmp_path / "missing" / "\x00bad"))
    assert claw_aibom_changed(_inv(), cfg) is True
