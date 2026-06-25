# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import plistlib
from pathlib import Path


def test_systemd_enterprise_unit_pins_hardening_contract():
    root = Path(__file__).resolve().parents[2]
    unit = root / "packaging" / "systemd" / "defenseclaw-gateway.service"
    text = unit.read_text(encoding="utf-8")

    required = {
        "User=defenseclaw",
        "Group=defenseclaw",
        "Environment=DEFENSECLAW_HOME=/var/lib/defenseclaw",
        "Environment=DEFENSECLAW_CONFIG=/etc/defenseclaw/config.yaml",
        "StateDirectoryMode=0750",
        "RuntimeDirectoryMode=0750",
        "LogsDirectoryMode=0750",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ProtectProc=invisible",
        "ProcSubset=pid",
        "ReadOnlyPaths=/etc/defenseclaw /opt/defenseclaw",
        "ReadWritePaths=/var/lib/defenseclaw /var/log/defenseclaw /run/defenseclaw",
        "CapabilityBoundingSet=",
        "RestrictNamespaces=true",
        "RestrictSUIDSGID=true",
        "SystemCallArchitectures=native",
        "SystemCallFilter=@system-service",
        "NoNewPrivileges=true",
        "MemoryDenyWriteExecute=true",
    }
    missing = sorted(line for line in required if line not in text)
    assert not missing


def test_systemd_hook_guardian_is_oneshot_and_keeps_gateway_config_read_only():
    root = Path(__file__).resolve().parents[2]
    unit = root / "packaging" / "systemd" / "defenseclaw-hook-guardian@.service"
    text = unit.read_text(encoding="utf-8")

    required = {
        "Type=oneshot",
        "User=root",
        "Group=root",
        "Documentation=https://docs.defenseclaw.ai/docs/setup/enterprise-deployment",
        "Environment=DEFENSECLAW_CONFIG=/etc/defenseclaw/config.yaml",
        "EnvironmentFile=-/etc/defenseclaw/hook-guardian/%i.env",
        "ExecStart=/opt/defenseclaw/bin/defenseclaw-gateway enterprise hooks install --user %i",
        "UMask=0077",
        "ProtectSystem=strict",
        "ReadOnlyPaths=/etc/defenseclaw /opt/defenseclaw",
        "ReadWritePaths=/home -/var/home /var/lib/defenseclaw",
        "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETUID",
        "RestrictNamespaces=true",
        "RestrictSUIDSGID=true",
        "NoNewPrivileges=true",
    }
    missing = sorted(line for line in required if line not in text)
    assert not missing


def test_systemd_hook_guardian_reconcile_timer_and_manifest_contract():
    root = Path(__file__).resolve().parents[2]
    service = root / "packaging" / "systemd" / "defenseclaw-hook-guardian.service"
    timer = root / "packaging" / "systemd" / "defenseclaw-hook-guardian.timer"
    tmpfiles = root / "packaging" / "systemd" / "defenseclaw.conf"
    sample = root / "packaging" / "systemd" / "hook-guardian-targets.example.yaml"

    service_text = service.read_text(encoding="utf-8")
    timer_text = timer.read_text(encoding="utf-8")
    tmpfiles_text = tmpfiles.read_text(encoding="utf-8")
    sample_text = sample.read_text(encoding="utf-8")

    assert "enterprise hooks reconcile --manifest /etc/defenseclaw/hook-guardian/targets.yaml" in service_text
    assert "Documentation=https://docs.defenseclaw.ai/docs/setup/enterprise-deployment" in service_text
    assert "UMask=0077" in service_text
    assert "ReadOnlyPaths=/etc/defenseclaw /opt/defenseclaw" in service_text
    assert "ReadWritePaths=/home -/var/home /var/lib/defenseclaw" in service_text
    assert "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETGID CAP_SETUID" in service_text
    assert "OnUnitActiveSec=5min" in timer_text
    assert "Persistent=true" in timer_text
    assert "Documentation=https://docs.defenseclaw.ai/docs/setup/enterprise-deployment" in timer_text
    assert "d /etc/defenseclaw/hook-guardian 0750 root defenseclaw -" in tmpfiles_text
    assert "version: 1" in sample_text
    assert "connector: codex" in sample_text


def test_launchd_gateway_plist_uses_managed_paths():
    root = Path(__file__).resolve().parents[2]
    plist_path = root / "packaging" / "launchd" / "com.defenseclaw.gateway.plist"

    with plist_path.open("rb") as fh:
        payload = plistlib.load(fh)

    assert payload["Label"] == "com.defenseclaw.gateway"
    assert payload["ProgramArguments"] == ["/Library/DefenseClaw/bin/defenseclaw-gateway"]
    assert payload["WorkingDirectory"] == "/Library/Application Support/DefenseClaw"
    assert payload["EnvironmentVariables"]["DEFENSECLAW_HOME"] == "/Library/Application Support/DefenseClaw"
    assert payload["EnvironmentVariables"]["DEFENSECLAW_CONFIG"] == "/Library/Application Support/DefenseClaw/config.yaml"
    assert payload["RunAtLoad"] is True
    assert payload["KeepAlive"] is True
    assert payload["Umask"] == 0o77
    assert payload["StandardOutPath"] == "/Library/Logs/DefenseClaw/gateway.log"
    assert payload["StandardErrorPath"] == "/Library/Logs/DefenseClaw/gateway.err.log"
