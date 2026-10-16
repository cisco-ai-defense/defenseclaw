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


def test_user_group_reference_uses_plan_group_casefold(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    entra = load_entra()
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"domain": "example.test", "groups": [{"name": "Dc-Group"}],
                                "users": [{"name": "alice", "groups": ["dc-group"]}]}), encoding="utf-8")

    class Graph:
        def get_all(self, path):
            if "/organization?" in path:
                return [{"verifiedDomains": [{"name": "example.test"}]}]
            if "/groups?" in path:
                return []
            raise AssertionError(path)

        def get(self, path):
            raise entra.GraphError(404, "NotFound", path)

    args = argparse.Namespace(config=str(plan), apply=False, password_file=None)
    assert entra.cmd_apply(Graph(), args) == 0
    output = capsys.readouterr().out
    assert "group Dc-Group: would create" in output
    assert "add alice@example.test to dc-group: would add" in output
    plan.write_text(json.dumps({"domain": "example.test", "groups": [{"name": "Dc-Group"}],
                                "users": [{"name": "alice", "groups": ["unknown-group"]}]}), encoding="utf-8")
    with pytest.raises(SystemExit, match="missing group"):
        entra.cmd_apply(Graph(), args)
