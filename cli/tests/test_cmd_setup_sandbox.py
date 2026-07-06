"""Tests for sandbox helper functions in cmd_setup_sandbox.py."""

import hashlib
import json
import os
import shutil
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import call, patch

from defenseclaw.commands import cmd_init_sandbox
from defenseclaw.commands.cmd_setup_sandbox import (
    _generate_launcher_scripts,
    _generate_resolv_conf,
    _generate_systemd_units,
    _parse_host_resolv,
    _pre_pair_device,
    write_device_key_provenance,
)

from tests.environment import requires_symlink_privilege


def _patch_no_sudo():
    return patch("defenseclaw.commands.cmd_init_sandbox._needs_sudo", return_value=False)


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
    def __init__(self, sandbox_home: str = "/home/sandbox"):
        self.host_networking = True
        self.sandbox_home = sandbox_home

    def effective_sandbox_home(self) -> str:
        return self.sandbox_home


class _MockGuardrail:
    def __init__(self):
        self.port = 4000
        self.enabled = True


class _MockGateway:
    def __init__(self):
        self.api_port = 18790
        self.port = 18789


class _MockClaw:
    """launcher generation now reads
    ``cfg.claw.openclaw_home_original`` to pin the privileged
    pre-sandbox repair to the operator-confirmed home path."""

    def __init__(self, openclaw_home_original: str = ""):
        self.openclaw_home_original = openclaw_home_original


class _MockCfg:
    def __init__(self, openclaw_home_original: str = ""):
        self.gateway = _MockGateway()
        self.guardrail = _MockGuardrail()
        self.openshell = _MockOpenshell()
        self.claw = _MockClaw(openclaw_home_original)


class TestGenerateSystemdUnits(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="dclaw-systemd-test-")
        self.sandbox_home = tempfile.mkdtemp(prefix="dclaw-sandbox-home-")

    def tearDown(self):
        shutil.rmtree(self.data_dir, ignore_errors=True)
        shutil.rmtree(self.sandbox_home, ignore_errors=True)

    def test_unit_files_created(self):
        _generate_systemd_units(
            self.data_dir,
            self.sandbox_home,
            "10.200.0.1",
            "10.200.0.2",
            _MockCfg(),
        )
        systemd_dir = os.path.join(self.data_dir, "systemd")
        expected_files = [
            "openshell-sandbox.service",
            "defenseclaw-sandbox.target",
        ]
        for name in expected_files:
            self.assertTrue(
                os.path.isfile(os.path.join(systemd_dir, name)),
                f"{name} not found",
            )

    def test_unit_files_contain_keywords(self):
        _generate_systemd_units(
            self.data_dir,
            self.sandbox_home,
            "10.200.0.1",
            "10.200.0.2",
            _MockCfg(),
        )
        systemd_dir = os.path.join(self.data_dir, "systemd")

        with open(os.path.join(systemd_dir, "openshell-sandbox.service")) as f:
            content = f.read()
        self.assertIn("ExecStart", content)
        self.assertIn("WantedBy", content)

        with open(os.path.join(systemd_dir, "defenseclaw-sandbox.target")) as f:
            content = f.read()
        self.assertIn("WantedBy", content)

    def test_no_gateway_service_generated(self):
        _generate_systemd_units(
            self.data_dir,
            self.sandbox_home,
            "10.200.0.1",
            "10.200.0.2",
            _MockCfg(),
        )
        sidecar_path = os.path.join(self.data_dir, "systemd", "defenseclaw-gateway.service")
        self.assertFalse(os.path.exists(sidecar_path))


class TestGenerateLauncherScripts(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="dclaw-scripts-test-")
        self.sandbox_home = tempfile.mkdtemp(prefix="dclaw-sandbox-home-")
        self._sudo_patcher = _patch_no_sudo()
        self._sudo_patcher.start()

    def tearDown(self):
        self._sudo_patcher.stop()
        shutil.rmtree(self.data_dir, ignore_errors=True)
        shutil.rmtree(self.sandbox_home, ignore_errors=True)

    def test_scripts_created(self):
        _generate_launcher_scripts(
            self.data_dir,
            self.sandbox_home,
            "10.200.0.1",
            "10.200.0.2",
            _MockCfg(),
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

    @unittest.skipIf(os.name == "nt", "Linux sandbox launcher executable bits have no Windows contract")
    def test_scripts_are_executable(self):
        _generate_launcher_scripts(
            self.data_dir,
            self.sandbox_home,
            "10.200.0.1",
            "10.200.0.2",
            _MockCfg(),
        )
        scripts_dir = os.path.join(self.data_dir, "scripts")
        for name in ("pre-sandbox.sh", "start-sandbox.sh", "post-sandbox.sh", "cleanup-sandbox.sh"):
            mode = os.stat(os.path.join(scripts_dir, name)).st_mode
            self.assertTrue(mode & stat.S_IXUSR, f"{name} is not executable")

    def test_start_sandbox_contains_openshell(self):
        _generate_launcher_scripts(
            self.data_dir,
            self.sandbox_home,
            "10.200.0.1",
            "10.200.0.2",
            _MockCfg(),
        )
        with open(os.path.join(self.data_dir, "scripts", "start-sandbox.sh")) as f:
            content = f.read()
        self.assertIn("openshell-sandbox", content)

    def test_post_sandbox_contains_host_ip(self):
        host_ip = "10.200.0.1"
        _generate_launcher_scripts(
            self.data_dir,
            self.sandbox_home,
            host_ip,
            "10.200.0.2",
            _MockCfg(),
        )
        with open(os.path.join(self.data_dir, "scripts", "post-sandbox.sh")) as f:
            content = f.read()
        self.assertIn(host_ip, content)


class _CfgFactory:
    """Build _MockCfg variants for the host_networking x guardrail_enabled matrix."""

    @staticmethod
    def make(host_networking: bool, guardrail_enabled: bool):
        cfg = _MockCfg()
        cfg.openshell = _MockOpenshell()
        cfg.openshell.host_networking = host_networking
        cfg.guardrail = _MockGuardrail()
        cfg.guardrail.enabled = guardrail_enabled
        return cfg


class TestLauncherScriptConditionals(unittest.TestCase):
    """Verify scripts respect host_networking and guardrail.enabled flags."""

    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="dclaw-cond-test-")
        self.sandbox_home = tempfile.mkdtemp(prefix="dclaw-cond-home-")
        self._sudo_patcher = _patch_no_sudo()
        self._sudo_patcher.start()

    def tearDown(self):
        self._sudo_patcher.stop()
        shutil.rmtree(self.data_dir, ignore_errors=True)
        shutil.rmtree(self.sandbox_home, ignore_errors=True)

    def _read_script(self, name):
        with open(os.path.join(self.data_dir, "scripts", name)) as f:
            return f.read()

    def _gen(self, host_networking, guardrail_enabled):
        cfg = _CfgFactory.make(host_networking, guardrail_enabled)
        _generate_launcher_scripts(
            self.data_dir,
            self.sandbox_home,
            "10.200.0.1",
            "10.200.0.2",
            cfg,
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

    # --- S3.HIGH_BUG: scoped sandbox cleanup regressions ---

    def test_cleanup_sandbox_uses_saved_namespace_marker(self):
        """cleanup-sandbox.sh must read the per-instance namespace marker
        rather than regex-matching all sandbox|openshell namespaces."""
        self._gen(True, True)
        content = self._read_script("cleanup-sandbox.sh")
        self.assertIn("sandbox.netns", content)
        self.assertIn("SAVED_NS=", content)
        # Legacy regex must only run when the operator explicitly opts in.
        self.assertIn("DEFENSECLAW_SANDBOX_FORCE_REGEX_CLEANUP", content)

    def test_cleanup_sandbox_no_unconditional_regex_namespace_delete(self):
        """The regex-based 'sandbox|openshell' namespace delete must NOT
        run unconditionally in cleanup-sandbox.sh."""
        self._gen(True, True)
        content = self._read_script("cleanup-sandbox.sh")
        # The legacy block, if present, MUST be guarded by the opt-in env var.
        if "grep -E 'sandbox|openshell'" in content:
            # Must appear inside an opt-in branch.
            self.assertIn(
                'DEFENSECLAW_SANDBOX_FORCE_REGEX_CLEANUP:-0}" = "1"',
                content,
            )

    def test_cleanup_sandbox_no_blanket_veth_delete(self):
        """Blanket `veth-h-*` delete is disallowed: it would remove other
        sandbox instances' interfaces."""
        self._gen(True, True)
        content = self._read_script("cleanup-sandbox.sh")
        self.assertNotIn("grep -oP 'veth-h-", content)

    def test_cleanup_iptables_restores_route_localnet(self):
        """cleanup-sandbox.sh must restore the saved route_localnet value
        instead of forcing it to 0."""
        self._gen(True, True)
        content = self._read_script("cleanup-sandbox.sh")
        self.assertIn("saved.route_localnet", content)
        self.assertNotIn("sysctl -w net.ipv4.conf.all.route_localnet=0", content)

    def test_post_sandbox_saves_route_localnet(self):
        """post-sandbox.sh must capture the prior route_localnet value
        before flipping it to 1."""
        self._gen(True, True)
        content = self._read_script("post-sandbox.sh")
        self.assertIn("saved.route_localnet", content)
        self.assertIn("sysctl -n net.ipv4.conf.all.route_localnet", content)

    def _gen_run_sandbox(self, pinned_home: str = "", sandbox_home: str = "/home/sandbox"):
        from defenseclaw.commands.cmd_setup_sandbox import (
            _generate_run_sandbox_script,
        )

        cfg = _CfgFactory.make(True, True)
        cfg.openshell = _MockOpenshell(sandbox_home=sandbox_home)
        cfg.claw = _MockClaw(openclaw_home_original=pinned_home)
        _generate_run_sandbox_script(self.data_dir, "10.200.0.1", cfg)

    def test_run_sandbox_acl_fixer_uses_pinned_home_not_root(self):
        """F-0427: the background ACL fixer in run-sandbox.sh must NOT
        blanket-grant the sandbox user rwX on a hardcoded /root/.openclaw.
        It must template the operator-confirmed pinned OpenClaw home plus
        the sandbox-owned $SANDBOX_HOME/.openclaw."""
        self._gen_run_sandbox(
            pinned_home="/home/operator/.openclaw",
            sandbox_home="/home/sandbox",
        )
        content = self._read_script("run-sandbox.sh")
        # The hardcoded root path must be gone from the ACL fixer loop.
        self.assertNotIn("/root/.openclaw", content)
        # The pinned home and the sandbox's own .openclaw must be present.
        self.assertIn("/home/operator/.openclaw", content)
        self.assertIn("/home/sandbox/.openclaw", content)

    def test_run_sandbox_acl_fixer_without_pin_skips_root(self):
        """F-0427: with no pinned home, the ACL fixer must fall back to
        ONLY the sandbox's own .openclaw — never root's."""
        self._gen_run_sandbox(pinned_home="", sandbox_home="/home/sandbox")
        content = self._read_script("run-sandbox.sh")
        self.assertNotIn("/root/.openclaw", content)
        self.assertIn("/home/sandbox/.openclaw", content)

    def test_run_sandbox_records_namespace_marker(self):
        """run-sandbox.sh must persist the discovered namespace name into
        $DATA_DIR/sandbox.netns so cleanup is scoped to this instance."""
        self._gen_run_sandbox()
        content = self._read_script("run-sandbox.sh")
        self.assertIn("sandbox.netns", content)
        self.assertIn("SANDBOX_NS=", content)

    def test_run_sandbox_strays_are_scoped_to_data_dir(self):
        """run-sandbox.sh stop must not kill processes by name only.
        The finding (#5) was that pgrep -f matches across the
        host. The replacement must verify processes belong to this
        instance via /proc/<pid>/cmdline or cwd referencing $DATA_DIR."""
        self._gen_run_sandbox()
        content = self._read_script("run-sandbox.sh")
        self.assertIn("_proc_is_ours", content)
        self.assertIn("_kill_scoped_strays", content)
        self.assertIn("/proc/$pid/cmdline", content)
        # The legacy unscoped helper must be gone.
        self.assertNotIn("_kill_strays openshell-sandbox", content)
        self.assertNotIn("_kill_strays defenseclaw-gateway", content)

    def test_pre_sandbox_skips_blanket_veth_delete(self):
        """pre-sandbox.sh must not delete every veth-h-* on the host."""
        self._gen(True, True)
        content = self._read_script("pre-sandbox.sh")
        self.assertNotIn("grep -oP 'veth-h-", content)

    def test_pre_sandbox_uses_saved_namespace_marker(self):
        """pre-sandbox.sh must prefer the saved namespace marker over
        regex-matching shared host state."""
        self._gen(True, True)
        content = self._read_script("pre-sandbox.sh")
        self.assertIn("sandbox.netns", content)
        self.assertIn("DEFENSECLAW_SANDBOX_FORCE_REGEX_CLEANUP", content)


@unittest.skipIf(os.name == "nt", "OpenShell pre-pairing is part of the unsupported Linux sandbox")
class TestPrePairDevice(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.mkdtemp(prefix="dclaw-pair-test-")
        self.sandbox_home = tempfile.mkdtemp(prefix="dclaw-sandbox-home-")
        os.makedirs(os.path.join(self.sandbox_home, ".openclaw"), exist_ok=True)
        self._sudo_patcher = _patch_no_sudo()
        self._sudo_patcher.start()

    def tearDown(self):
        self._sudo_patcher.stop()
        shutil.rmtree(self.data_dir, ignore_errors=True)
        shutil.rmtree(self.sandbox_home, ignore_errors=True)

    def _write_device_key(self, blob: bytes) -> str:
        """Write a device.key with mode 0o600 + a VALID gateway-minted
        provenance sentinel (HMAC over the key bytes keyed by the
        owner-only per-install secret). F-1441: a verifiable sentinel
        — not a forgeable literal — is what the hardened pre-pair flow
        now requires before it will touch paired.json."""
        path = os.path.join(self.data_dir, "device.key")
        with open(path, "wb") as f:
            f.write(blob)
        os.chmod(path, 0o600)
        write_device_key_provenance(self.data_dir, path)
        return path

    def test_no_device_key(self):
        result = _pre_pair_device(self.data_dir, self.sandbox_home)
        self.assertFalse(result)

    def _read_paired(self):
        paired_path = os.path.join(self.sandbox_home, ".openclaw", "devices", "paired.json")
        with open(paired_path) as f:
            return json.load(f)

    def test_with_ed25519_key(self):
        self._write_device_key(os.urandom(64))

        result = _pre_pair_device(self.data_dir, self.sandbox_home)
        self.assertTrue(result)

        paired = self._read_paired()
        self.assertIsInstance(paired, dict)
        self.assertEqual(len(paired), 1)
        device = list(paired.values())[0]
        self.assertEqual(device["displayName"], "defenseclaw-sidecar")
        self.assertEqual(device["role"], "operator")

    def test_updates_existing_device(self):
        self._write_device_key(os.urandom(64))

        _pre_pair_device(self.data_dir, self.sandbox_home)
        _pre_pair_device(self.data_dir, self.sandbox_home)

        paired = self._read_paired()
        self.assertEqual(len(paired), 1, "Should update, not duplicate")

    def test_32_byte_pubkey(self):
        self._write_device_key(os.urandom(32))

        result = _pre_pair_device(self.data_dir, self.sandbox_home)
        self.assertTrue(result)

        paired = self._read_paired()
        self.assertEqual(len(paired), 1)
        device = list(paired.values())[0]
        self.assertEqual(device["displayName"], "defenseclaw-sidecar")

    def test_f2551_overpermissive_mode_refused(self):
        """device.key mode 0o644 (group/world read)
        must be refused even with a VALID provenance sentinel present."""
        path = os.path.join(self.data_dir, "device.key")
        with open(path, "wb") as f:
            f.write(os.urandom(32))
        os.chmod(path, 0o600)
        # Mint a valid sentinel, THEN loosen the mode — proving the mode
        # gate fires independently of provenance.
        write_device_key_provenance(self.data_dir, path)
        os.chmod(path, 0o644)

        result = _pre_pair_device(self.data_dir, self.sandbox_home)
        self.assertFalse(result, "regression: 0o644 device.key was accepted")

    def test_f2551_missing_provenance_refused(self):
        """a 0o600 device.key without the gateway
        provenance sentinel must be refused (a local user could have
        planted the file before sandbox setup ran)."""
        path = os.path.join(self.data_dir, "device.key")
        with open(path, "wb") as f:
            f.write(os.urandom(32))
        os.chmod(path, 0o600)
        # No .provenance file alongside.

        result = _pre_pair_device(self.data_dir, self.sandbox_home)
        self.assertFalse(result, "regression: device.key without sentinel accepted")

    def test_f1441_forged_literal_provenance_refused(self):
        """F-1441: a sibling .provenance file containing an arbitrary
        literal (the legacy forgeable shape ``source=test``) must NOT be
        accepted — only a verifiable HMAC sentinel keyed by the owner-only
        per-install secret counts. A local attacker can plant both
        device.key and an arbitrary provenance literal; that path must
        fail closed."""
        path = os.path.join(self.data_dir, "device.key")
        with open(path, "wb") as f:
            f.write(os.urandom(32))
        os.chmod(path, 0o600)
        with open(path + ".provenance", "w", encoding="utf-8") as f:
            f.write("source=test\n")
        os.chmod(path + ".provenance", 0o600)

        result = _pre_pair_device(self.data_dir, self.sandbox_home)
        self.assertFalse(result, "regression: forgeable literal provenance was accepted")

    def test_f1441_tampered_device_key_invalidates_sentinel(self):
        """F-1441: the sentinel is bound to the device.key bytes via HMAC.
        If an attacker mints a valid sentinel for one key then swaps in a
        different device.key, the HMAC no longer matches and pairing is
        refused."""
        path = os.path.join(self.data_dir, "device.key")
        with open(path, "wb") as f:
            f.write(os.urandom(64))
        os.chmod(path, 0o600)
        write_device_key_provenance(self.data_dir, path)
        # Swap the key bytes AFTER the sentinel was minted.
        with open(path, "wb") as f:
            f.write(os.urandom(64))
        os.chmod(path, 0o600)

        result = _pre_pair_device(self.data_dir, self.sandbox_home)
        self.assertFalse(result, "regression: sentinel accepted for a swapped device.key")

    def test_f1441_wrong_secret_provenance_refused(self):
        """F-1441: a provenance HMAC computed with an attacker-chosen
        secret (i.e. without the owner-only per-install secret) must be
        refused. Simulates an attacker who knows the sentinel format but
        not the secret."""
        import hashlib
        import hmac

        from defenseclaw.commands.cmd_setup_sandbox import (
            _PROVENANCE_SENTINEL_PREFIX,
        )

        key_bytes = os.urandom(32)
        path = os.path.join(self.data_dir, "device.key")
        with open(path, "wb") as f:
            f.write(key_bytes)
        os.chmod(path, 0o600)
        forged = hmac.new(b"attacker-secret", key_bytes, hashlib.sha256).hexdigest()
        with open(path + ".provenance", "w", encoding="utf-8") as f:
            f.write(_PROVENANCE_SENTINEL_PREFIX + forged + "\n")
        os.chmod(path + ".provenance", 0o600)

        result = _pre_pair_device(self.data_dir, self.sandbox_home)
        self.assertFalse(result, "regression: HMAC with wrong secret was accepted")

    def test_f2551_legacy_optin_bypasses_sentinel(self):
        """The DEFENSECLAW_PREPAIR_TRUST_DEVICE_KEY=1 escape hatch
        keeps the legacy behavior for operators who can't yet
        regenerate device.key via the new gateway flow."""
        path = os.path.join(self.data_dir, "device.key")
        with open(path, "wb") as f:
            f.write(os.urandom(32))
        os.chmod(path, 0o600)

        prev = os.environ.get("DEFENSECLAW_PREPAIR_TRUST_DEVICE_KEY")
        try:
            os.environ["DEFENSECLAW_PREPAIR_TRUST_DEVICE_KEY"] = "1"
            result = _pre_pair_device(self.data_dir, self.sandbox_home)
        finally:
            if prev is None:
                os.environ.pop("DEFENSECLAW_PREPAIR_TRUST_DEVICE_KEY", None)
            else:
                os.environ["DEFENSECLAW_PREPAIR_TRUST_DEVICE_KEY"] = prev
        self.assertTrue(result, "legacy opt-in env var must keep working")

    def test_pem_encoded_key(self):
        import base64

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.generate()
        seed = priv.private_bytes_raw()
        pub = priv.public_key().public_bytes_raw()

        pem_data = (
            "-----BEGIN ED25519 PRIVATE KEY-----\n"
            + base64.b64encode(seed).decode()
            + "\n"
            + "-----END ED25519 PRIVATE KEY-----\n"
        )
        key_path = os.path.join(self.data_dir, "device.key")
        with open(key_path, "w") as f:
            f.write(pem_data)
        # regenerate the on-disk perms + a VALID gateway-minted provenance
        # sentinel that the hardened pre-pair flow now requires.
        os.chmod(key_path, 0o600)
        write_device_key_provenance(self.data_dir, key_path)

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
            + base64.b64encode(seed).decode()
            + "\n"
            + "-----END ED25519 PRIVATE KEY-----\n"
        ).encode()

        extracted_pub = _extract_ed25519_pubkey(pem_data)
        self.assertEqual(extracted_pub, pub)
        self.assertEqual(
            hashlib.sha256(extracted_pub).hexdigest(),
            hashlib.sha256(pub).hexdigest(),
        )


# ---------------------------------------------------------------------------
# S4.5 — connector-aware sandbox setup
# ---------------------------------------------------------------------------


class TestValidateSandboxConnector(unittest.TestCase):
    """``_validate_sandbox_connector`` must abort early on non-OpenClaw."""

    def _make_cfg(self, connector_value: str | None) -> object:
        """Build a stand-in for FullConfig that exposes the same surface
        the validator reads from."""

        class _Guardrail:
            def __init__(self, connector: str | None):
                self.connector = connector

        class _Cfg:
            def __init__(self, connector_value: str | None):
                self.guardrail = _Guardrail(connector_value)

            # If callers prefer the modern Config.active_connector
            # entry point, this matches the post-S4.1 shape.
            def active_connector(self) -> str:
                return (self.guardrail.connector or "openclaw").strip().lower() or "openclaw"

        return _Cfg(connector_value)

    def test_openclaw_passes(self):
        from defenseclaw.commands.cmd_setup_sandbox import (
            _validate_sandbox_connector,
        )

        # Should not raise.
        _validate_sandbox_connector(self._make_cfg("openclaw"))

    def test_empty_string_treated_as_openclaw(self):
        from defenseclaw.commands.cmd_setup_sandbox import (
            _validate_sandbox_connector,
        )

        _validate_sandbox_connector(self._make_cfg(""))

    def test_none_treated_as_openclaw(self):
        from defenseclaw.commands.cmd_setup_sandbox import (
            _validate_sandbox_connector,
        )

        _validate_sandbox_connector(self._make_cfg(None))

    def test_codex_aborts_with_clickexception(self):
        import click as _click
        from defenseclaw.commands.cmd_setup_sandbox import (
            _validate_sandbox_connector,
        )

        with self.assertRaises(_click.ClickException) as ctx:
            _validate_sandbox_connector(self._make_cfg("codex"))
        msg = str(ctx.exception.message)
        self.assertIn("guardrail.connector=openclaw", msg)
        self.assertIn("codex", msg.lower())
        # Remediation guidance must point at host mode.
        self.assertIn("defenseclaw setup", msg)

    def test_claudecode_aborts(self):
        import click as _click
        from defenseclaw.commands.cmd_setup_sandbox import (
            _validate_sandbox_connector,
        )

        with self.assertRaises(_click.ClickException):
            _validate_sandbox_connector(self._make_cfg("claudecode"))

    def test_zeptoclaw_aborts(self):
        import click as _click
        from defenseclaw.commands.cmd_setup_sandbox import (
            _validate_sandbox_connector,
        )

        with self.assertRaises(_click.ClickException):
            _validate_sandbox_connector(self._make_cfg("zeptoclaw"))

    def test_uppercase_connector_normalized(self):
        from defenseclaw.commands.cmd_setup_sandbox import (
            _validate_sandbox_connector,
        )

        # Case-insensitive — "OpenClaw" must be accepted.
        _validate_sandbox_connector(self._make_cfg("OpenClaw"))

    def test_whitespace_only_treated_as_openclaw(self):
        from defenseclaw.commands.cmd_setup_sandbox import (
            _validate_sandbox_connector,
        )

        _validate_sandbox_connector(self._make_cfg("   "))


class TestSandboxFrameworkRoots(unittest.TestCase):
    def _make_cfg(self, connector: str) -> object:
        class _Guardrail:
            def __init__(self, c):
                self.connector = c

        class _Cfg:
            def __init__(self, c):
                self.guardrail = _Guardrail(c)

            def active_connector(self) -> str:
                return (self.guardrail.connector or "openclaw").strip().lower()

        return _Cfg(connector)

    def test_openclaw_returns_dotopenclaw(self):
        from defenseclaw.commands.cmd_setup_sandbox import (
            _sandbox_framework_roots,
        )

        roots = _sandbox_framework_roots(self._make_cfg("openclaw"), "/home/sandbox")
        self.assertEqual(roots, ["/home/sandbox/.openclaw"])

    def test_unknown_connector_returns_empty(self):
        from defenseclaw.commands.cmd_setup_sandbox import (
            _sandbox_framework_roots,
        )

        # Defense-in-depth — even if a caller bypasses validation, the
        # iteration over [] is safe.
        self.assertEqual(
            _sandbox_framework_roots(self._make_cfg("codex"), "/home/sandbox"),
            [],
        )


class TestSupportedSandboxConnectors(unittest.TestCase):
    """Lock the supported set so adding a connector requires explicit intent."""

    def test_only_openclaw(self):
        from defenseclaw.commands.cmd_setup_sandbox import (
            SUPPORTED_SANDBOX_CONNECTORS,
        )

        self.assertEqual(SUPPORTED_SANDBOX_CONNECTORS, frozenset({"openclaw"}))


class TestTrustedPrivilegedCommands(unittest.TestCase):
    def test_attacker_path_entry_is_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            command = os.path.join(directory, "setfacl")
            with open(command, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\n")
            os.chmod(command, 0o755)
            with (
                patch.object(cmd_init_sandbox, "_TRUSTED_SYSTEM_DIRS", ()),
                patch.dict(os.environ, {"PATH": directory}),
            ):
                self.assertIsNone(cmd_init_sandbox._trusted_system_command("setfacl"))

    def test_group_writable_root_command_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            command = os.path.join(directory, "setfacl")
            with open(command, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\n")
            os.chmod(command, 0o755)
            fake_stat = SimpleNamespace(st_mode=stat.S_IFREG | 0o775, st_uid=0)
            with (
                patch.object(cmd_init_sandbox, "_TRUSTED_SYSTEM_DIRS", (directory,)),
                patch.object(cmd_init_sandbox.os, "stat", return_value=fake_stat),
            ):
                self.assertIsNone(cmd_init_sandbox._trusted_system_command("setfacl"))

    def test_privileged_argv_resolves_sudo_and_helper(self):
        resolved = {"sudo": "/usr/bin/sudo", "chown": "/usr/sbin/chown"}
        with (
            patch.object(cmd_init_sandbox, "_needs_sudo", return_value=True),
            patch.object(cmd_init_sandbox, "_trusted_system_command", side_effect=resolved.get) as trusted_command,
            patch.object(
                cmd_init_sandbox,
                "_trusted_root_owned_file",
                side_effect=lambda path, **_kwargs: path,
            ),
            patch.object(cmd_init_sandbox.os, "access", return_value=True),
        ):
            argv = cmd_init_sandbox._trusted_privileged_argv("chown", "-R", "sandbox:sandbox", "/srv/sandbox")
        self.assertEqual(argv, ["/usr/bin/sudo", "/usr/sbin/chown", "-R", "sandbox:sandbox", "/srv/sandbox"])
        self.assertEqual(trusted_command.call_args_list, [call("chown"), call("sudo")])

    def test_missing_trusted_apt_get_falls_back_without_executing(self):
        with (
            patch.object(cmd_init_sandbox, "_trusted_system_command", return_value=None) as trusted_command,
            patch.object(cmd_init_sandbox.subprocess, "run") as run,
        ):
            cmd_init_sandbox._ensure_iptables()
        self.assertEqual(trusted_command.call_args_list, [call("iptables"), call("apt-get")])
        run.assert_not_called()

    def test_sudo_validation_failure_aborts(self):
        with (
            patch.object(cmd_init_sandbox, "_needs_sudo", return_value=True),
            patch.object(cmd_init_sandbox, "_trusted_system_command", return_value="/usr/bin/sudo"),
            patch.object(
                cmd_init_sandbox.subprocess,
                "run",
                side_effect=[SimpleNamespace(returncode=1), SimpleNamespace(returncode=1)],
            ) as run,
        ):
            with self.assertRaisesRegex(cmd_init_sandbox.click.ClickException, "sudo authentication failed"):
                cmd_init_sandbox._ensure_sudo_cache()
        self.assertEqual(
            run.call_args_list,
            [call(["/usr/bin/sudo", "-n", "true"], capture_output=True), call(["/usr/bin/sudo", "-v"], check=False)],
        )

    def test_sudo_write_propagates_chmod_failure(self):
        with (
            patch.object(cmd_init_sandbox, "_needs_sudo", return_value=True),
            patch.object(cmd_init_sandbox, "_trusted_privileged_argv", return_value=["trusted"]) as trusted_argv,
            patch.object(
                cmd_init_sandbox.subprocess,
                "run",
                side_effect=[SimpleNamespace(returncode=0), SimpleNamespace(returncode=1)],
            ),
        ):
            self.assertFalse(cmd_init_sandbox._sudo_write("content", "/etc/example", 0o600))
        self.assertEqual(
            trusted_argv.call_args_list,
            [call("tee", "--", "/etc/example"), call("chmod", "600", "--", "/etc/example")],
        )

    @unittest.skipIf(os.name == "nt", "root-owned POSIX trust chain is Linux-only")
    def test_privileged_script_requires_trusted_ancestors(self):
        script = "/opt/defenseclaw/install.sh"
        trusted_file = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        trusted_dir = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        trusted_paths = {
            script: trusted_file,
            "/opt/defenseclaw": trusted_dir,
            "/opt": trusted_dir,
            "/": trusted_dir,
        }
        with (
            patch.object(cmd_init_sandbox.os.path, "realpath", return_value=script),
            patch.object(cmd_init_sandbox.os, "lstat", side_effect=lambda path: trusted_paths[path]),
        ):
            self.assertEqual(cmd_init_sandbox._trusted_root_owned_file(script), script)

        writable_dir = SimpleNamespace(st_mode=stat.S_IFDIR | 0o775, st_uid=0)
        writable_paths = {**trusted_paths, "/opt/defenseclaw": writable_dir}
        with (
            patch.object(cmd_init_sandbox.os.path, "realpath", return_value=script),
            patch.object(cmd_init_sandbox.os, "lstat", side_effect=lambda path: writable_paths[path]),
        ):
            self.assertIsNone(cmd_init_sandbox._trusted_root_owned_file(script))

    @unittest.skipIf(os.name == "nt", "root-owned alternatives chain is Linux-only")
    def test_trusted_system_command_accepts_root_owned_alternatives_chain(self):
        link = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        executable = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        metadata = {
            "/usr/sbin/iptables": link,
            "/etc/alternatives/iptables": link,
            "/usr/sbin/iptables-nft": executable,
            "/usr/sbin": directory,
            "/usr": directory,
            "/etc/alternatives": directory,
            "/etc": directory,
            "/": directory,
        }
        targets = {
            "/usr/sbin/iptables": "/etc/alternatives/iptables",
            "/etc/alternatives/iptables": "/usr/sbin/iptables-nft",
        }
        with (
            patch.object(cmd_init_sandbox, "_TRUSTED_SYSTEM_DIRS", ("/usr/sbin",)),
            patch.object(cmd_init_sandbox.os, "lstat", side_effect=lambda path: metadata[path]),
            patch.object(cmd_init_sandbox.os, "readlink", side_effect=lambda path: targets[path]),
            patch.object(cmd_init_sandbox.os.path, "realpath", side_effect=lambda path: path),
            patch.object(cmd_init_sandbox.os, "access", return_value=True),
        ):
            self.assertEqual(cmd_init_sandbox._trusted_system_command("iptables"), "/usr/sbin/iptables-nft")

    @requires_symlink_privilege
    def test_existing_openclaw_integration_requires_pin(self):
        with tempfile.TemporaryDirectory() as data_dir, tempfile.TemporaryDirectory() as sandbox_home:
            target = os.path.join(data_dir, "openclaw")
            os.makedirs(target)
            with open(os.path.join(data_dir, cmd_init_sandbox.OPENCLAW_OWNERSHIP_BACKUP), "w") as handle:
                handle.write("{}")
            os.symlink(target, os.path.join(sandbox_home, ".openclaw"))
            cfg = SimpleNamespace(data_dir=data_dir, claw=SimpleNamespace(openclaw_home_original=""))
            with (
                patch.object(cmd_init_sandbox, "_ensure_parent_traversal") as traversal,
                patch.object(cmd_init_sandbox, "_ensure_sandbox_acls") as acls,
            ):
                self.assertFalse(cmd_init_sandbox._integrate_openclaw_home(cfg, sandbox_home))
            traversal.assert_not_called()
            acls.assert_not_called()

    def test_install_preserves_openshell_version_across_sudo(self):
        cfg = SimpleNamespace(openshell=SimpleNamespace(sandbox_version="1.2.3"))
        command = ["/usr/bin/sudo", "/bin/bash", "/trusted/install", "--install-dir", "/usr/local/bin"]
        with (
            patch.object(cmd_init_sandbox, "_find_installer_script", return_value="/trusted/install"),
            patch.object(cmd_init_sandbox, "_trusted_privileged_argv", return_value=command.copy()),
            patch.object(cmd_init_sandbox, "_needs_sudo", return_value=True),
            patch.object(cmd_init_sandbox.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run,
            patch.object(cmd_init_sandbox.shutil, "which", return_value="/usr/local/bin/openshell-sandbox"),
        ):
            self.assertTrue(cmd_init_sandbox._install_openshell_sandbox(cfg))
        argv = run.call_args.args[0]
        self.assertEqual(argv[1], "--preserve-env=OPENSHELL_VERSION")
        self.assertEqual(run.call_args.kwargs["env"]["OPENSHELL_VERSION"], "1.2.3")


if __name__ == "__main__":
    unittest.main()
