"""Tests for the ``substrate:`` config section (Python twin of internal/config/substrate.go)."""

import dataclasses
import json
import os
import sys
import tempfile
import typing
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.config import (  # noqa: E402
    Config,
    SubstrateConfig,
    SubstrateSecret,
    SubstrateSecretInject,
    _merge_substrate,
    load,
)
from defenseclaw.observability.v8_config import load_validate_v8  # noqa: E402

_REPO = Path(__file__).resolve().parents[2]
_SCHEMA = _REPO / "schemas" / "config" / "v8" / "defenseclaw-config.schema.json"

# The same document internal/config/substrate_test.go validates (substrateExample).
_FULL = {
    "enabled": True,
    "api": {"address": "api.ate-system.svc:443", "ca_file": "/var/run/ate/ca.crt", "auth": "serviceaccount"},
    "supported_versions": ">=1.0.0 <1.1.0",
    "identity": {
        "issuer": "https://idp.ate-system.svc",
        "audience": "defenseclaw",
        "token_lifetime_seconds": 300,
        "actor_cert_oid": "1.3.6.1.4.1.11129.2.12.2",
        "oidc": {"issuer": "https://login.example.com", "client_id": "defenseclaw-launcher", "groups_claim": "groups"},
        "workload_oidc": [
            {
                "issuer": "https://token.actions.githubusercontent.com",
                "audience": "defenseclaw-prod",
                "subject": "repo:acme/web:ref:refs/heads/*",
                "claims": {"repository": "acme/web"},
            }
        ],
    },
    "services": {"actor": "defenseclaw-actor.defenseclaw-system.svc", "admin": "defenseclaw-admin.defenseclaw-system.svc"},
    "launcher_atespaces": {"engineering": ["eng-payments", "eng-web"]},
    "require_attested_templates": False,
    "templates": {"trust_anchors": "/etc/defenseclaw/substrate/template-anchors/anchors.pem",
                  "min_policy_generation": 3, "max_age": "2160h", "allow_unverified_base": True,
                  "allowed_images": ["registry.example.com/defenseclaw/*"],
                  "profile_images": {"ci": ["registry.example.com/defenseclaw/ci-*"]},
                  "volume_images": ["registry.example.com/models/*"],
                  "plain_http_registries": ["10.0.0.5:5000"],
                  "revoked_digests": ["sha256:" + "0" * 64]},
    "default_sandbox_class": "gvisor",
    "idle_suspend_after": "30m",
    "unattended": {"asks": "deny", "ask_timeout": "30m", "telemetry_sampling": 0.5},
    "rate_limits": {"per_actor_rps": 20, "per_atespace_rps": 500},
    "extproc": {"enabled": True, "failure_mode": "closed", "body_inspection": "on", "body_max_bytes": 1048576,
                "mcp_hosts": ["mcp.example.com=docs"], "body_hosts": ["api.example.com"],
                "cluster_domains": ["svc.cluster.local"], "actor_trust_domain": "cluster.local",
                "egress_peers": ["spiffe://cluster.local/ns/ate-system/sa/atenet-egress"],
                "request_access": "security@example.com", "log_headers": True, "redact_headers": ["X-Team-Token"],
                "blocklist_files": ["/etc/defenseclaw/feeds/egress.yaml"], "actor_secrets_dir": "/var/run/dc/actor-secrets",
                "uid": {"cache_ttl": "60s", "stale_max": "60s"}, "chain": {"check_budget": "20ms", "queue_size": 4096},
                "ask": {"hold": "1500ms"},
                "judge": {"url": "https://defenseclaw-leader.defenseclaw-system.svc/api/v1/substrate/callout/verdict",
                          "token_file": "/var/run/dc/judge-token", "ca_file": "/var/run/dc/ca.crt", "timeout": "1500ms"},
                "dlp": {"credential_headers": "deny"}},
    "llm": {"providers": ["anthropic", "bedrock"],
            "credential": {"provider_uri": "ate-secret://k8s.io/default/defenseclaw-system/llm-keys"}},
    "egress": {"allow": ["github.com", "*.githubusercontent.com"], "ecosystem_packs": ["pypi", "npm"],
               "registries": ["ghcr.io"]},
    "secrets": [
        {"name": "github-push", "source": "ate-secret://k8s.io/default/dc-secrets/github-app/token",
         "inject": {"hosts": ["github.com", "api.github.com"], "header": "Authorization", "prefix": "Bearer ",
                    "placeholder": "DC_SECRET_GITHUB"},
         "scope": "shared", "profiles": ["eng-*"]},
        {"name": "npm-mine", "source": "ate-secret://k8s.io/default/dc-people/{person}-npm/token",
         "inject": {"hosts": ["registry.npmjs.org"], "header": "Authorization"},
         "scope": "per_person", "profiles": ["*"]},
    ],
    "allow_passthrough_for": ["pins.example.org"],
    "admin": {"egress_block": ["paste.example.com"], "allow_unblock": False},
}


def _schema_properties(node: dict, defs: dict) -> dict:
    while "$ref" in node:
        node = defs[node["$ref"].rsplit("/", 1)[-1]]
    return node


class TestSubstrateDataclassesMatchSchema(unittest.TestCase):
    def test_every_nested_dataclass_matches_the_closed_schema(self):
        schema = json.loads(_SCHEMA.read_text())
        defs = schema["$defs"]

        def check(cls, node, where):
            node = _schema_properties(node, defs)
            self.assertIs(node.get("additionalProperties"), False, where)
            hints = typing.get_type_hints(cls)
            fields = sorted(f.name for f in dataclasses.fields(cls))
            if cls.__name__ == "OpenShellAdminConfig":
                return  # shared with openshell.admin, covered by its own tests
            self.assertEqual(fields, sorted(node["properties"]), where)
            for f in dataclasses.fields(cls):
                hint = hints[f.name]
                inner = typing.get_args(hint)
                target = hint
                child = node["properties"][f.name]
                if typing.get_origin(hint) is list and inner and dataclasses.is_dataclass(inner[0]):
                    target, child = inner[0], child["items"]
                if dataclasses.is_dataclass(target):
                    check(target, child, f"{where}.{f.name}")

        check(SubstrateConfig, schema["properties"]["substrate"], "substrate")


class TestSubstrateLoadSave(unittest.TestCase):
    def _load(self, tmpdir: str) -> Config:
        with patch("defenseclaw.config.default_data_path") as mock_dp:
            mock_dp.return_value = Path(tmpdir)
            return load()

    def _write(self, tmpdir: str, doc: dict) -> str:
        path = os.path.join(tmpdir, "config.yaml")
        with open(path, "w") as f:
            yaml.safe_dump({"config_version": 9, "data_dir": tmpdir, **doc}, f)
        return path

    def test_untouched_section_is_not_written(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, {})
            cfg = self._load(tmpdir)
            self.assertEqual(cfg.substrate, SubstrateConfig())
            cfg.gateway.api_port = 19000
            cfg.save()
            self.assertNotIn("substrate", yaml.safe_load(Path(path).read_text()))

    def test_full_section_round_trips_and_validates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, {"substrate": _FULL})
            load_validate_v8(Path(path).read_bytes(), source_name=path)
            cfg = self._load(tmpdir)
            sub = cfg.substrate
            self.assertTrue(sub.enabled)
            self.assertIs(sub.require_attested_templates, False)
            self.assertEqual(sub.templates.min_policy_generation, 3)
            self.assertEqual(sub.templates.profile_images, {"ci": ["registry.example.com/defenseclaw/ci-*"]})
            self.assertEqual(sub.identity.workload_oidc[0].audience, "defenseclaw-prod")
            self.assertEqual(sub.identity.workload_oidc[0].subject, "repo:acme/web:ref:refs/heads/*")
            self.assertEqual(sub.identity.workload_oidc[0].claims, {"repository": "acme/web"})
            self.assertEqual(sub.secrets[1].scope, "per_person")
            self.assertEqual(sub.egress.ecosystem_packs, ["pypi", "npm"])
            self.assertEqual(sub.admin.egress_block, ["paste.example.com"])
            cfg.save()  # validates the merged document against the v8 schema
            saved = yaml.safe_load(Path(path).read_text())["substrate"]
            self.assertEqual(saved, _FULL)
            self.assertEqual(self._load(tmpdir).substrate, sub)

    def test_set_from_python_writes_only_what_is_set(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, {})
            cfg = self._load(tmpdir)
            cfg.substrate.identity.issuer = "https://idp.ate-system.svc"
            cfg.substrate.secrets.append(SubstrateSecret(
                name="gh", source="ate-secret://k8s.io/default/ns/gh/token",
                inject=SubstrateSecretInject(hosts=["github.com"], header="Authorization"), profiles=["eng-*"]))
            cfg.save()
            saved = yaml.safe_load(Path(path).read_text())["substrate"]
            self.assertEqual(saved, {
                "enabled": False,
                "identity": {"issuer": "https://idp.ate-system.svc"},
                "secrets": [{"name": "gh", "source": "ate-secret://k8s.io/default/ns/gh/token",
                             "inject": {"hosts": ["github.com"], "header": "Authorization"}, "profiles": ["eng-*"]}],
            })

    def test_empty_pack_list_differs_from_unset(self):
        self.assertIsNone(_merge_substrate({"egress": {}}).egress.ecosystem_packs)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._write(tmpdir, {"substrate": {"egress": {"ecosystem_packs": []}}})
            cfg = self._load(tmpdir)
            self.assertEqual(cfg.substrate.egress.ecosystem_packs, [])
            cfg.save()
            saved = yaml.safe_load(Path(path).read_text())["substrate"]
            # The writer applies a structural delta, so the operator's block is
            # kept as written; the explicit empty list survives the save.
            self.assertEqual(saved["egress"], {"ecosystem_packs": []})
            self.assertIsNot(saved.get("enabled"), True)

    def test_bad_types_load_as_unset(self):
        sub = _merge_substrate({"enabled": "yes", "identity": {"token_lifetime_seconds": "x"}, "secrets": [None]})
        self.assertFalse(sub.enabled)
        self.assertIsNone(sub.identity.token_lifetime_seconds)
        self.assertEqual(sub.secrets[0].name, "")


if __name__ == "__main__":
    unittest.main()


class TestProfileMatchSubstrate(unittest.TestCase):
    def test_round_trip(self):
        doc = {
            "profiles": {"ci": {}},
            "profile_assignments": [
                {"profile": "ci", "match": {"substrate": {"atespaces": ["ci-runs"], "templates": ["ci-runs/claude"]}}}
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "config.yaml")
            with open(path, "w") as f:
                yaml.safe_dump({"config_version": 9, "data_dir": tmpdir, "guardrail": doc}, f)
            load_validate_v8(Path(path).read_bytes(), source_name=path)
            with patch("defenseclaw.config.default_data_path") as mock_dp:
                mock_dp.return_value = Path(tmpdir)
                cfg = load()
            match = cfg.guardrail.profile_assignments[0].match
            self.assertEqual(match.substrate.atespaces, ["ci-runs"])
            self.assertEqual(match.substrate.workloads, [])
            cfg.save()
            saved = yaml.safe_load(Path(path).read_text())["guardrail"]["profile_assignments"][0]["match"]
            self.assertEqual(saved, {"substrate": {"atespaces": ["ci-runs"], "templates": ["ci-runs/claude"]}})
