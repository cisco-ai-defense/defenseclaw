// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The standalone Claude Code policy starts every hook through
// defenseclaw-hook-guard.exe beside the hook, so a payload without it is
// incomplete on every route: ensure planning, the extracted-payload folder and
// the direct install and upgrade flags. Secure Client has no guard.
func standaloneSourceOptions(withGuard bool) *windowsEnterpriseLifecycleOptions {
	opts := &windowsEnterpriseLifecycleOptions{
		profile: "standalone", resolvedProfile: "standalone", productVersion: "1.0.9", configPath: `C:\stage\config.yaml`,
		gatewayBinary: `C:\p\defenseclaw-gateway.exe`, acpBinary: `C:\p\defenseclaw-acp.exe`,
		hookBinary: `C:\p\defenseclaw-hook.exe`, sensorHelperBinary: `C:\p\defenseclaw-sensor-helper.exe`,
	}
	if withGuard {
		opts.hookGuardBinary = `C:\p\defenseclaw-hook-guard.exe`
	}
	return opts
}

func TestStandalonePayloadNeedsTheHookGuardSource(t *testing.T) {
	if missing := missingWindowsEnterpriseSources(standaloneSourceOptions(false)); len(missing) != 1 || missing[0] != "--hook-guard-binary" {
		t.Fatalf("standalone payload without the guard misses %v", missing)
	}
	if missing := missingWindowsEnterpriseSources(standaloneSourceOptions(true)); len(missing) != 0 {
		t.Fatalf("complete standalone payload misses %v", missing)
	}
	secureClient := standaloneSourceOptions(false)
	secureClient.profile, secureClient.resolvedProfile = "secure_client", "secure_client"
	if missing := missingWindowsEnterpriseSources(secureClient); len(missing) != 0 {
		t.Fatalf("Secure Client payload needs no guard but misses %v", missing)
	}
}

func TestDirectStandaloneInstallAndUpgradeRefuseAMissingHookGuardSource(t *testing.T) {
	for _, action := range []string{"install", "upgrade"} {
		err := refuseWindowsEnterpriseStandaloneWithoutHookGuard(action, standaloneSourceOptions(false))
		if !errors.Is(err, errWindowsEnterpriseInvalidArguments) || !strings.Contains(err.Error(), "--hook-guard-binary") ||
			!strings.Contains(err.Error(), "nothing was changed") {
			t.Errorf("%s without the guard source = %v", action, err)
		}
		if err := refuseWindowsEnterpriseStandaloneWithoutHookGuard(action, standaloneSourceOptions(true)); err != nil {
			t.Errorf("%s with the guard source = %v", action, err)
		}
		secureClient := standaloneSourceOptions(false)
		secureClient.profile, secureClient.resolvedProfile = "secure_client", "secure_client"
		if err := refuseWindowsEnterpriseStandaloneWithoutHookGuard(action, secureClient); err != nil {
			t.Errorf("Secure Client %s = %v", action, err)
		}
	}
	// Repair restores from the payload or the installed files and is not an
	// install of new sources; the installed CLI repairs without any payload.
	if err := refuseWindowsEnterpriseStandaloneWithoutHookGuard("repair", standaloneSourceOptions(false)); err != nil {
		t.Errorf("repair = %v", err)
	}
}

func TestEnsureFromAnExtractedPayloadWithoutTheHookGuardIsRefused(t *testing.T) {
	folder := t.TempDir()
	script := filepath.Join(folder, "install-enterprise.ps1")
	for _, name := range []string{"defenseclaw-gateway.exe", "defenseclaw-acp.exe", "defenseclaw-hook.exe", "defenseclaw-sensor-helper.exe"} {
		if err := os.WriteFile(filepath.Join(folder, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plan := func(installed bool) (windowsEnterpriseEnsurePlan, *windowsEnterpriseLifecycleOptions, error) {
		opts := &windowsEnterpriseLifecycleOptions{profile: "standalone", resolvedProfile: "standalone", productVersion: "1.0.9", configPath: `C:\stage\config.yaml`}
		defaultWindowsEnterpriseEnsurePayload(opts, script)
		status := &windowsEnterpriseInstallerReport{OK: true}
		if installed {
			status = &windowsEnterpriseInstallerReport{OK: true, Installed: true, InstalledVersion: "1.0.8"}
		}
		got, err := planWindowsEnterpriseEnsure(status, opts, script)
		return got, opts, err
	}
	for _, installed := range []bool{false, true} {
		if _, _, err := plan(installed); !errors.Is(err, errWindowsEnterpriseInvalidArguments) || !strings.Contains(err.Error(), "--hook-guard-binary") {
			t.Fatalf("installed=%v: payload folder without the guard = %v", installed, err)
		}
	}
	// The same folder with the guard beside the other programs installs and upgrades.
	if err := os.WriteFile(filepath.Join(folder, "defenseclaw-hook-guard.exe"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for installed, action := range map[bool]string{false: "install", true: "upgrade"} {
		got, opts, err := plan(installed)
		if err != nil || got.Action != action || opts.hookGuardBinary != filepath.Join(folder, "defenseclaw-hook-guard.exe") {
			t.Fatalf("installed=%v: complete payload folder = %+v, %v (guard %q)", installed, got, err, opts.hookGuardBinary)
		}
	}
}
