import importlib.util
import sys
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("benchmark_normalize_cyber_training_shell.py")
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("benchmark_normalize_cyber_training_shell", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_small_fixture_emits_runner_compatible_manifest(tmp_path: Path) -> None:
    source = tmp_path / "scenario" / "host-useractions.json"
    source.parent.mkdir(parents=True)
    source.write_text(
        '{"cmd":"echo safe","cmd_type":"bash-command","hostname":"workstation"}\n',
        encoding="utf-8",
    )

    cases, manifest = MODULE.normalize(tmp_path, enforce_release=False)

    assert len(cases) == 1
    assert manifest["datasets"] == [MODULE.SOURCE_ID]
    assert manifest["counts"] == {MODULE.SOURCE_ID: 1}
    assert manifest["cases"] == 1
    assert manifest["exact_payload_duplicates_removed"] == 0
    assert manifest["label_conflicts_excluded"] == 0
    assert set(manifest) == {
        "schema_version",
        "datasets",
        "cases",
        "counts",
        "exact_payload_duplicates_removed",
        "label_conflicts_excluded",
        "adapter_statistics",
    }
