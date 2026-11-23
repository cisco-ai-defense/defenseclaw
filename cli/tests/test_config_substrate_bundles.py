"""Tests for ``substrate.bundles`` (Python twin of internal/config/substrate_bundles.go)."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.config import (  # noqa: E402
    SubstrateBundleOCIConfig,
    SubstrateBundlesConfig,
    _merge_substrate,
    load,
)
from defenseclaw.observability.v8_config import load_validate_v8  # noqa: E402

_BUNDLES = {
    "enabled": True,
    "anchors_file": "/etc/defenseclaw-substrate/bundle-anchors/bundle-anchors.json",
    "inbox": "team-bundles",
    "refresh_interval": "30s",
}


class TestSubstrateBundles(unittest.TestCase):
    def _load(self, tmpdir: str):
        with patch("defenseclaw.config.default_data_path") as mock_dp:
            mock_dp.return_value = Path(tmpdir)
            return load()

    def _write(self, tmpdir: str, doc: dict) -> str:
        path = os.path.join(tmpdir, "config.yaml")
        with open(path, "w") as f:
            yaml.safe_dump({"config_version": 9, "data_dir": tmpdir, **doc}, f)
        return path

    def test_merge_defaults(self):
        self.assertEqual(_merge_substrate({}).bundles, SubstrateBundlesConfig())
        got = _merge_substrate({"bundles": _BUNDLES}).bundles
        self.assertTrue(got.enabled)
        self.assertEqual(got.inbox, "team-bundles")
        self.assertEqual(got.refresh_interval, "30s")

    def test_round_trip_and_schema(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, {"substrate": {"enabled": True, "bundles": _BUNDLES}})
            load_validate_v8(Path(path).read_bytes(), source_name=path)
            cfg = self._load(tmpdir)
            self.assertEqual(cfg.substrate.bundles.anchors_file, _BUNDLES["anchors_file"])
            cfg.save()
            saved = yaml.safe_load(Path(path).read_text())["substrate"]
            self.assertEqual(saved["bundles"], _BUNDLES)

    def test_unset_bundles_are_not_written(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, {})
            cfg = self._load(tmpdir)
            cfg.substrate.identity.issuer = "https://idp.ate-system.svc"
            cfg.save()
            saved = yaml.safe_load(Path(path).read_text())["substrate"]
            self.assertNotIn("bundles", saved)
            cfg.substrate.bundles.inbox = "team-bundles"
            cfg.save()
            saved = yaml.safe_load(Path(path).read_text())["substrate"]
            self.assertEqual(saved["bundles"], {"inbox": "team-bundles"})

    def test_oci_round_trip_and_schema(self):
        # GAP-0437: substrate.bundles.oci mirrors Go and omits what Go omits.
        ref = "registry.example.com/policy/prod@sha256:" + "ab" * 32
        oci = {"enabled": True, "ca_file": "/etc/dc/ca.pem", "auth_hosts": ["auth.docker.io"], "stages": [
            {"stage": "prod", "ref": ref, "atespaces": ["team-a"]}, {"stage": "all", "ref": ref}]}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, {"substrate": {"enabled": True, "bundles": {"enabled": True, "oci": oci}}})
            load_validate_v8(Path(path).read_bytes(), source_name=path)
            cfg = self._load(tmpdir)
            got = cfg.substrate.bundles.oci
            self.assertTrue(got.enabled)
            self.assertEqual(got.auth_hosts, ["auth.docker.io"])  # GAP-0950
            self.assertEqual([s.stage for s in got.stages], ["prod", "all"])
            self.assertEqual(got.stages[1].atespaces, [])
            cfg.save()
            saved = yaml.safe_load(Path(path).read_text())["substrate"]
            self.assertEqual(saved["bundles"]["oci"], oci)
        self.assertEqual(_merge_substrate({}).bundles.oci, SubstrateBundleOCIConfig())

    def test_oci_tag_ref_fails_the_schema(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, {"substrate": {"bundles": {"oci": {"stages": [
                {"stage": "prod", "ref": "registry.example.com/policy/prod:v7"}]}}}})
            with self.assertRaises(Exception):
                load_validate_v8(Path(path).read_bytes(), source_name=path)


if __name__ == "__main__":
    unittest.main()
