"""Generated detector-catalog constants stay identical to the YAML authority."""

from pathlib import Path

import yaml
from defenseclaw.observability.detector_catalog_v1 import (
    DETECTOR_CATALOG_VERSION,
    DETECTOR_GROUP_MEMBERS,
    DETECTOR_GROUPS,
    DETECTOR_IDS,
)
from defenseclaw.observability.v8_config import DETECTOR_GROUPS as CONFIG_DETECTOR_GROUPS

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "schemas" / "telemetry" / "v8" / "redaction" / "detector-catalog-v1.yaml"


def test_generated_detector_catalog_matches_machine_manifest() -> None:
    document = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    expected_members = tuple((group["token"], tuple(group["detector_ids"])) for group in document["groups"])
    expected_ids = tuple(entry["id"] for entry in document["detectors"])

    assert DETECTOR_CATALOG_VERSION == document["catalog_version"] == 1
    assert DETECTOR_GROUPS == tuple(group["token"] for group in document["groups"])
    assert frozenset(CONFIG_DETECTOR_GROUPS) == frozenset(DETECTOR_GROUPS)
    assert DETECTOR_GROUP_MEMBERS == expected_members
    assert DETECTOR_IDS == expected_ids
    assert (
        tuple(detector_id for _, detector_ids in DETECTOR_GROUP_MEMBERS for detector_id in detector_ids) == DETECTOR_IDS
    )
