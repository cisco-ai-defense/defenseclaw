"""Tests for sandbox helper functions in cmd_setup_sandbox.py."""

import hashlib
import json
import os
import shutil
import stat
import tempfile
import unittest

from defenseclaw.commands.cmd_setup_sandbox import (
    _generate_resolv_conf,
    _parse_host_resolv,
    _generate_systemd_units,
    _generate_launcher_scripts,
    _pre_pair_device,
)


class TestParseHostResolv(unittest.TestCase):
    def test_returns_list(self):
        result = _parse_host_resolv()
        self.assertIsInstance(result, list)

    def test_entries_are_nonempty_strings(self):
        result = _parse_host_resolv()
        for entry in result:
            self.assertIsInstance(entry, str)
            self.assertTrue(len(entry) > 0)


class TestGenerateResolvConf(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="dclaw-resolv-test-")

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)

    def test_explicit_dns(self):
        _generate_resolv_conf(self.data_dir, "8.8.8.8,1.1.1.1")
        path = os.path.join(self.data_dir, "sandbox-resolv.conf")
        self.assertTrue(os.path.isfile(path))
        with open(path) as f:
            content = f.read()
        self.assertIn("nameserver 8.8.8.8", content)
        self.assertIn("nameserver 1.1.1.1", content)

    def test_fallback_dns(self):
        _generate_resolv_conf(self.data_dir, "")
        path = os.path.join(self.data_dir, "sandbox-resolv.conf")
        self.assertTrue(os.path.isfile(path))
        with open(path) as f:
            content = f.read()
        self.assertIn("nameserver 8.8.8.8", content)
        self.assertIn("nameserver 1.1.1.1", content)

    def test_host_dns(self):
        _generate_resolv_conf(self.data_dir, "host")
        path = os.path.join(self.data_dir, "sandbox-resolv.conf")
        self.assertTrue(os.path.isfile(path))
        with open(path) as f:
            content = f.read()
        self.assertIn("nameserver", content)


class _MockOpenshell:
    def __init__(self):
        self.dns_override = True


class _MockGuardrail:
    def __init__(self):
        self.port = 4000
        self.enabled = True


class _MockGateway:
    def __init__(self):
        self.api_port = 18790


class _MockCfg:
    def __init__(self):
        self.gateway = _MockGateway()
        self.guardrail = _MockGuardrail()
        self.openshell = _MockOpenshell()


class TestGenerateSystemdUnits(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="dclaw-systemd-test-")
        self.sandbox_home = tempfile.mkdtemp(prefix="dclaw-sandbox-home-")

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)
        shutil.rmtree(self.sandbox_home, ignore_errors=True)

    def test_unit_files_created(self):
        _generate_systemd_units(
            self.data_dir, self.sandbox_home,
            "10.200.0.1", "10.200.0.2", _MockCfg(),
        )
        systemd_dir = os.path.join(self.data_dir, "systemd")
        expected_files = [
            "openshell-sandbox.service",
            "defenseclaw-gateway.service",
            "defenseclaw-sandbox.target",
        ]
        for name in expected_files:
            self.assertTrue(
                os.path.isfile(os.path.join(systemd_dir, name)),
                f"{name} not found",
            )

    def test_unit_files_contain_keywords(self):
        _generate_systemd_units(
            self.data_dir, self.sandbox_home,
            "10.200.0.1", "10.200.0.2", _MockCfg(),
        )
        systemd_dir = os.path.join(self.data_dir, "systemd")

        for name in ("openshell-sandbox.service", "defenseclaw-gateway.service"):
            with open(os.path.join(systemd_dir, name)) as f:
                content = f.read()
            self.assertIn("ExecStart", content)
            self.assertIn("WantedBy", content)

        with open(os.path.join(systemd_dir, "defenseclaw-sandbox.target")) as f:
            content = f.read()
        self.assertIn("WantedBy", content)

    def test_sidecar_unit_contains_readwritepaths(self):
        _generate_systemd_units(
            self.data_dir, self.sandbox_home,
            "10.200.0.1", "10.200.0.2", _MockCfg(),
        )
        sidecar_path = os.path.join(self.data_dir, "systemd", "defenseclaw-gateway.service")
        with open(sidecar_path) as f:
            content = f.read()
        self.assertIn(f'ReadWritePaths="{self.data_dir}"', content)


class TestGenerateLauncherScripts(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="dclaw-scripts-test-")
        self.sandbox_home = tempfile.mkdtemp(prefix="dclaw-sandbox-home-")

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)
        shutil.rmtree(self.sandbox_home, ignore_errors=True)

    def test_scripts_created(self):
        _generate_launcher_scripts(
            self.data_dir, self.sandbox_home, "10.200.0.1", _MockCfg(),
        )
        scripts_dir = os.path.join(self.data_dir, "scripts")
        expected = [
            "pre-sandbox.sh",
            "start-sandbox.sh",
            "post-sandbox.sh",
            "cleanup-sandbox.sh",
        ]
        for name in expected:
            self.assertTrue(
                os.path.isfile(os.path.join(scripts_dir, name)),
                f"{name} not found",
            )

    def test_scripts_are_executable(self):
        _generate_launcher_scripts(
            self.data_dir, self.sandbox_home, "10.200.0.1", _MockCfg(),
        )
        scripts_dir = os.path.join(self.data_dir, "scripts")
        for name in ("pre-sandbox.sh", "start-sandbox.sh", "post-sandbox.sh", "cleanup-sandbox.sh"):
            mode = os.stat(os.path.join(scripts_dir, name)).st_mode
            self.assertTrue(mode & stat.S_IXUSR, f"{name} is not executable")

    def test_start_sandbox_contains_openshell(self):
        _generate_launcher_scripts(
            self.data_dir, self.sandbox_home, "10.200.0.1", _MockCfg(),
        )
        with open(os.path.join(self.data_dir, "scripts", "start-sandbox.sh")) as f:
            content = f.read()
        self.assertIn("openshell-sandbox", content)

    def test_post_sandbox_contains_host_ip(self):
        host_ip = "10.200.0.1"
        _generate_launcher_scripts(
            self.data_dir, self.sandbox_home, host_ip, _MockCfg(),
        )
        with open(os.path.join(self.data_dir, "scripts", "post-sandbox.sh")) as f:
            content = f.read()
        self.assertIn(host_ip, content)


class _CfgFactory:
    """Build _MockCfg variants for the dns_override x guardrail_enabled matrix."""

    @staticmethod
    def make(dns_override: bool, guardrail_enabled: bool):
        cfg = _MockCfg()
        cfg.openshell = _MockOpenshell()
        cfg.openshell.dns_override = dns_override
        cfg.guardrail = _MockGuardrail()
        cfg.guardrail.enabled = guardrail_enabled
        return cfg


class TestLauncherScriptConditionals(unittest.TestCase):
    """Verify scripts respect dns_override and guardrail.enabled flags."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="dclaw-cond-test-")
        self.sandbox_home = tempfile.mkdtemp(prefix="dclaw-cond-home-")

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)
        shutil.rmtree(self.sandbox_home, ignore_errors=True)

    def _read_script(self, name):
        with open(os.path.join(self.data_dir, "scripts", name)) as f:
            return f.read()

    def _gen(self, dns_override, guardrail_enabled):
        cfg = _CfgFactory.make(dns_override, guardrail_enabled)
        _generate_launcher_scripts(
            self.data_dir, self.sandbox_home, "10.200.0.1", cfg,
        )

    # --- (True, True) — full rules ---

    def test_dns_on_guardrail_on_post_has_dns_rules(self):
        self._gen(True, True)
        content = self._read_script("post-sandbox.sh")
        self.assertIn("--dport 53", content)
        self.assertIn("MASQUERADE", content)

    def test_dns_on_guardrail_on_post_has_guardrail_rules(self):
        self._gen(True, True)
        content = self._read_script("post-sandbox.sh")
        self.assertIn("18790", content)
        self.assertIn("4000", content)

    def test_dns_on_guardrail_on_start_has_mount(self):
        self._gen(True, True)
        content = self._read_script("start-sandbox.sh")
        self.assertIn("mount --bind", content)

    def test_dns_on_guardrail_on_openclaw_has_dns_wait(self):
        self._gen(True, True)
        with open(os.path.join(self.sandbox_home, "start-openclaw.sh")) as f:
            content = f.read()
        self.assertIn("getaddrinfo", content)

    # --- (True, False) — DNS only ---

    def test_dns_on_guardrail_off_post_has_dns_no_guardrail(self):
        self._gen(True, False)
        content = self._read_script("post-sandbox.sh")
        self.assertIn("--dport 53", content)
        self.assertIn("MASQUERADE", content)
        self.assertNotIn('--dport "$API_PORT"', content)
        self.assertNotIn('--dport "$GUARDRAIL_PORT"', content)

    def test_dns_on_guardrail_off_start_has_mount(self):
        self._gen(True, False)
        content = self._read_script("start-sandbox.sh")
        self.assertIn("mount --bind", content)

    # --- (False, True) — guardrail only ---

    def test_dns_off_guardrail_on_post_has_guardrail_no_dns(self):
        self._gen(False, True)
        content = self._read_script("post-sandbox.sh")
        self.assertNotIn("--dport 53", content)
        self.assertNotIn("MASQUERADE", content)
        self.assertIn("18790", content)
        self.assertIn("4000", content)

    def test_dns_off_guardrail_on_start_no_mount(self):
        self._gen(False, True)
        content = self._read_script("start-sandbox.sh")
        self.assertNotIn("mount --bind", content)
        self.assertIn("openshell-sandbox", content)

    def test_dns_off_guardrail_on_openclaw_no_dns_wait(self):
        self._gen(False, True)
        with open(os.path.join(self.sandbox_home, "start-openclaw.sh")) as f:
            content = f.read()
        self.assertNotIn("getaddrinfo", content)

    # --- (False, False) — no rules ---

    def test_dns_off_guardrail_off_post_is_noop(self):
        self._gen(False, False)
        content = self._read_script("post-sandbox.sh")
        self.assertNotIn("NSENTER", content)
        self.assertNotIn("MASQUERADE", content)
        self.assertIn("exit 0", content)

    def test_dns_off_guardrail_off_start_no_mount(self):
        self._gen(False, False)
        content = self._read_script("start-sandbox.sh")
        self.assertNotIn("mount --bind", content)
        self.assertIn("openshell-sandbox", content)

    def test_dns_off_guardrail_off_openclaw_no_dns_wait(self):
        self._gen(False, False)
        with open(os.path.join(self.sandbox_home, "start-openclaw.sh")) as f:
            content = f.read()
        self.assertNotIn("getaddrinfo", content)
        self.assertIn("openclaw gateway run", content)



class TestPrePairDevice(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="dclaw-pair-test-")
        self.sandbox_home = tempfile.mkdtemp(prefix="dclaw-sandbox-home-")
        os.makedirs(os.path.join(self.sandbox_home, ".openclaw"), exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)
        shutil.rmtree(self.sandbox_home, ignore_errors=True)

    def test_no_device_key(self):
        result = _pre_pair_device(self.data_dir, self.sandbox_home)
        self.assertFalse(result)

    def _read_paired(self):
        paired_path = os.path.join(self.sandbox_home, ".openclaw", "devices", "paired.json")
        with open(paired_path) as f:
            return json.load(f)

    def test_with_ed25519_key(self):
        key_data = os.urandom(64)
        key_path = os.path.join(self.data_dir, "device.key")
        with open(key_path, "wb") as f:
            f.write(key_data)

        result = _pre_pair_device(self.data_dir, self.sandbox_home)
        self.assertTrue(result)

        paired = self._read_paired()
        self.assertIsInstance(paired, dict)
        self.assertEqual(len(paired), 1)
        device = list(paired.values())[0]
        self.assertEqual(device["displayName"], "defenseclaw-sidecar")
        self.assertEqual(device["role"], "operator")

    def test_updates_existing_device(self):
        key_data = os.urandom(64)
        key_path = os.path.join(self.data_dir, "device.key")
        with open(key_path, "wb") as f:
            f.write(key_data)

        _pre_pair_device(self.data_dir, self.sandbox_home)
        _pre_pair_device(self.data_dir, self.sandbox_home)

        paired = self._read_paired()
        self.assertEqual(len(paired), 1, "Should update, not duplicate")

    def test_32_byte_pubkey(self):
        key_data = os.urandom(32)
        key_path = os.path.join(self.data_dir, "device.key")
        with open(key_path, "wb") as f:
            f.write(key_data)

        result = _pre_pair_device(self.data_dir, self.sandbox_home)
        self.assertTrue(result)

        paired = self._read_paired()
        self.assertEqual(len(paired), 1)
        device = list(paired.values())[0]
        self.assertEqual(device["displayName"], "defenseclaw-sidecar")

    def test_pem_encoded_key(self):
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.generate()
        seed = priv.private_bytes_raw()
        pub = priv.public_key().public_bytes_raw()

        pem_data = (
            "-----BEGIN ED25519 PRIVATE KEY-----\n"
            + base64.b64encode(seed).decode() + "\n"
            + "-----END ED25519 PRIVATE KEY-----\n"
        )
        key_path = os.path.join(self.data_dir, "device.key")
        with open(key_path, "w") as f:
            f.write(pem_data)

        result = _pre_pair_device(self.data_dir, self.sandbox_home)
        self.assertTrue(result)

        paired = self._read_paired()
        self.assertEqual(len(paired), 1)
        device_id = hashlib.sha256(pub).hexdigest()
        self.assertIn(device_id, paired)
        device = paired[device_id]
        self.assertEqual(device["displayName"], "defenseclaw-sidecar")
        self.assertEqual(device["role"], "operator")
        self.assertEqual(device["deviceId"], device_id)

    def test_pem_key_matches_go_fingerprint(self):
        """Verify Python derives the same device ID as the Go gateway."""
        import base64
        import hashlib
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from defenseclaw.commands.cmd_setup_sandbox import _extract_ed25519_pubkey

        priv = Ed25519PrivateKey.generate()
        seed = priv.private_bytes_raw()
        pub = priv.public_key().public_bytes_raw()

        pem_data = (
            "-----BEGIN ED25519 PRIVATE KEY-----\n"
            + base64.b64encode(seed).decode() + "\n"
            + "-----END ED25519 PRIVATE KEY-----\n"
        ).encode()

        extracted_pub = _extract_ed25519_pubkey(pem_data)
        self.assertEqual(extracted_pub, pub)
        self.assertEqual(
            hashlib.sha256(extracted_pub).hexdigest(),
            hashlib.sha256(pub).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
