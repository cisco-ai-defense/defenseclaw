import importlib.util
import sys
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[2] / "packaging/mdm/intune/tenant/intune_tenant.py"


def load_intune():
    spec = importlib.util.spec_from_file_location("intune_tenant", PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_malformed_add_device_makes_no_tenant_change() -> None:
    intune = load_intune()
    writes = []

    class Graph:
        def get_all(self, path):
            return []

        def wait_for_named_object(self, path):
            return []

        def request(self, method, path, body):
            writes.append((method, path))
            return {"id": "created"}

        def get_after_create(self, path):
            return {"id": "created"}

    args = intune.build_parser().parse_args(["groups", "--name", "dc-r102-new", "--add-device", "badpair", "--apply"])
    with pytest.raises(SystemExit, match="--add-device wants DEVICE:GROUP"):
        intune.cmd_groups(Graph(), args)
    assert writes == []


def test_repeated_group_names_plan_and_create_once(capsys: pytest.CaptureFixture[str]) -> None:
    intune = load_intune()
    writes = []

    class Graph:
        def get_all(self, path):
            return []

        def wait_for_named_object(self, path):
            return []

        def request(self, method, path, body):
            writes.append((method, path, body))
            return {"id": "created"}

        def get_after_create(self, path):
            return {"id": "created"}

    preview = intune.build_parser().parse_args(["groups", "--name", "Dc-R102-Team", "--name", "dc-r102-team"])
    assert intune.cmd_groups(Graph(), preview) == 0
    output = capsys.readouterr().out
    assert output.count("would create a static security group") == 1
    assert "Dc-R102-Team" in output
    apply = intune.build_parser().parse_args(["groups", "--name", "Dc-R102-Team", "--name", "dc-r102-team", "--apply"])
    assert intune.cmd_groups(Graph(), apply) == 0
    assert len(writes) == 1
    assert writes[0][2]["displayName"] == "Dc-R102-Team"
