import argparse
import importlib.util
import json
import sys
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[2] / "packaging/identity/entra/entra_setup.py"


def load_entra():
    spec = importlib.util.spec_from_file_location("entra_setup", PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(("types", "mail", "allowed"), [([], False, True), (["DynamicMembership"], False, False), ([], True, False)])
def test_existing_group_must_allow_graph_membership_changes_before_writes(
    tmp_path: Path, types: list[str], mail: bool, allowed: bool
) -> None:
    entra = load_entra()
    plan = tmp_path / "plan.json"
    names = ["team"] if allowed else ["new-team", "team"]
    plan.write_text(json.dumps({"domain": "example.test", "groups": [{"name": name} for name in names]}), encoding="utf-8")
    writes = []

    class Graph:
        def get_all(self, path):
            if "/organization?" in path:
                return [{"verifiedDomains": [{"name": "example.test"}]}]
            if "/groups?" in path:
                return [] if "new-team" in path else [{"id": "group-id", "securityEnabled": True,
                                                        "groupTypes": types, "mailEnabled": mail}]
            raise AssertionError(path)

        def wait_for_named_object(self, path, headers=None):
            return []

        def request(self, method, path, body):
            writes.append((method, path))
            return {"id": "new-id"}

        def get_after_create(self, path):
            return {"id": "new-id"}

    args = argparse.Namespace(config=str(plan), apply=True, password_file=None)
    if allowed:
        assert entra.cmd_apply(Graph(), args) == 0
    else:
        with pytest.raises(entra.GraphError, match="membership"):
            entra.cmd_apply(Graph(), args)
    assert writes == []
