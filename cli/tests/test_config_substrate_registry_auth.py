"""substrate.templates.registry_auth (GAP-0190) and substrate.identity.admin_groups
(GAP-0191): the Python twin loads, validates and writes them as Go does."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.config import Config, load  # noqa: E402
from defenseclaw.observability.v8_config import load_validate_v8  # noqa: E402

_ECR = "123456789012.dkr.ecr.us-east-1.amazonaws.com"

_SECTION = {
    "enabled": True,
    "identity": {
        "issuer": "https://idp.ate-system.svc",
        "oidc": {"issuer": "https://sso.example.com", "client_id": "dc"},
        "admin_groups": ["dc-admins", "platform"],
    },
    "templates": {
        "allowed_images": [_ECR + "/dc/*"],
        "registry_auth": {
            "docker_config": "/etc/defenseclaw/substrate/registry-auth/config.json",
            "ecr_hosts": [_ECR],
        },
    },
}


class TestSubstrateRegistryAuth(unittest.TestCase):
    def _load(self, tmpdir: str) -> Config:
        with patch("defenseclaw.config.default_data_path") as mock_dp:
            mock_dp.return_value = Path(tmpdir)
            return load()

    def _write(self, tmpdir: str, section: dict) -> str:
        path = os.path.join(tmpdir, "config.yaml")
        with open(path, "w") as f:
            yaml.safe_dump({"config_version": 9, "data_dir": tmpdir, "substrate": section}, f)
        return path

    def test_keys_load_validate_and_round_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, _SECTION)
            load_validate_v8(Path(path).read_bytes(), source_name=path)
            sub = self._load(tmpdir).substrate
            self.assertEqual(sub.templates.registry_auth.ecr_hosts, [_ECR])
            self.assertEqual(sub.templates.registry_auth.docker_config,
                             "/etc/defenseclaw/substrate/registry-auth/config.json")
            self.assertEqual(sub.identity.admin_groups, ["dc-admins", "platform"])
            cfg = self._load(tmpdir)
            cfg.save()
            saved = yaml.safe_load(Path(path).read_text())["substrate"]
            self.assertEqual(saved["templates"]["registry_auth"], _SECTION["templates"]["registry_auth"])
            self.assertEqual(saved["identity"]["admin_groups"], ["dc-admins", "platform"])

    def test_unset_registry_auth_is_not_written(self):
        section = {"enabled": True, "identity": {"issuer": "https://idp.ate-system.svc"}}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, section)
            cfg = self._load(tmpdir)
            self.assertEqual(cfg.substrate.templates.registry_auth.ecr_hosts, [])
            cfg.save()
            saved = yaml.safe_load(Path(path).read_text())["substrate"]
            self.assertNotIn("templates", saved)
            self.assertNotIn("admin_groups", saved.get("identity", {}))

    def test_schema_refuses_a_non_ecr_host(self):
        bad = {**_SECTION, "templates": {"registry_auth": {"ecr_hosts": ["ghcr.io"]}}}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, bad)
            with self.assertRaises(Exception):
                load_validate_v8(Path(path).read_bytes(), source_name=path)


if __name__ == "__main__":
    unittest.main()
