// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Setup /repair over a hand-edited config.yaml puts the approved config source
// back. The installer does that before any later Go check, so a copy an
// earlier release left at an older config (installed B, approved A, a digest
// that matches A) is refused first, naming the ensure that publishes the
// installed config. A proven copy, a repair that supplies its own config, a
// config that is not a hand edit and a bundle deployment are left to the
// installer.
func TestWindowsEnterpriseRepairOverAHandEditStopsOnAnUnprovenApprovedSource(t *testing.T) {
	originalInspector, originalPending, originalLayout := windowsEnterpriseDeploymentInspector, windowsEnterpriseStandaloneRecoveryPending, windowsEnterpriseHotConfigLayout
	t.Cleanup(func() {
		windowsEnterpriseDeploymentInspector, windowsEnterpriseStandaloneRecoveryPending, windowsEnterpriseHotConfigLayout = originalInspector, originalPending, originalLayout
	})
	windowsEnterpriseDeploymentInspector = func(profile string) (winpath.EnterpriseDeployment, error) {
		return winpath.EnterpriseDeployment{Profile: profile, State: winpath.EnterpriseDeploymentInstalled, ProductVersion: "1.0.9"}, nil
	}
	windowsEnterpriseStandaloneRecoveryPending = func(*windowsEnterpriseLifecycleOptions) bool { return false }

	dir := approvedSourceFolder(t) // an earlier release: approved A, no proof
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.yaml")
	windowsEnterpriseHotConfigLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{LifecycleDir: dir, ConfigDir: configDir, ConfigPath: configPath}, nil
	}
	if err := os.WriteFile(configPath, []byte(approvedSourceConfigB), 0o600); err != nil {
		t.Fatal(err)
	}
	stageConfigGeneration(t, configPath, approvedSourceConfigB, "lifecycle")
	setup := func() *windowsEnterpriseLifecycleOptions {
		return &windowsEnterpriseLifecycleOptions{profile: "standalone", resolvedProfile: "standalone", jsonOutput: true, productVersion: "1.0.9"}
	}

	// Not a hand edit: Repair restores nothing from the approved copy.
	if err := refuseWindowsEnterpriseRepairOverUnprovenApprovedSource("repair", setup()); err != nil {
		t.Fatalf("a config the lifecycle recorded: %v", err)
	}
	handEditAfter(t, configPath, approvedSourceConfigB)
	err := refuseWindowsEnterpriseRepairOverUnprovenApprovedSource("repair", setup())
	if !errors.Is(err, errWindowsEnterpriseInvalidArguments) || !strings.Contains(err.Error(), "/ensure") ||
		!strings.Contains(err.Error(), "CONFIG=<approved absolute config path>") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("an unproven approved source: %v", err)
	}
	for _, action := range []string{"ensure", "upgrade", "install", "status", "verify"} {
		if err := refuseWindowsEnterpriseRepairOverUnprovenApprovedSource(action, setup()); err != nil {
			t.Fatalf("%s refused: %v", action, err)
		}
	}
	withConfig := setup()
	withConfig.configPath = `C:\approved\config.yaml`
	if err := refuseWindowsEnterpriseRepairOverUnprovenApprovedSource("repair", withConfig); err != nil {
		t.Fatalf("a repair that supplies its config refused: %v", err)
	}
	windowsEnterpriseStandaloneRecoveryPending = func(*windowsEnterpriseLifecycleOptions) bool { return true }
	if err := refuseWindowsEnterpriseRepairOverUnprovenApprovedSource("repair", setup()); err != nil {
		t.Fatalf("recovery of a pending transaction refused: %v", err)
	}
	windowsEnterpriseStandaloneRecoveryPending = func(*windowsEnterpriseLifecycleOptions) bool { return false }
	if err := os.MkdirAll(filepath.Join(configDir, "bundles", "v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := refuseWindowsEnterpriseRepairOverUnprovenApprovedSource("repair", setup()); err != nil {
		t.Fatalf("a signed-bundle deployment refused (the installer names the CLI repair): %v", err)
	}
	if err := os.RemoveAll(filepath.Join(configDir, "bundles")); err != nil {
		t.Fatal(err)
	}

	// A run of this release proved the copy: Repair goes ahead.
	if err := os.WriteFile(configPath, []byte(approvedSourceConfigB), 0o600); err != nil {
		t.Fatal(err)
	}
	stageConfigGeneration(t, configPath, approvedSourceConfigB, "lifecycle")
	if err := refreshManagedApprovedConfigSource(dir, configPath, []byte(approvedSourceConfigB)); err != nil {
		t.Fatal(err)
	}
	handEditAfter(t, configPath, approvedSourceConfigB)
	if err := refuseWindowsEnterpriseRepairOverUnprovenApprovedSource("repair", setup()); err != nil {
		t.Fatalf("a proven approved source refused: %v", err)
	}
	if got := approvedRepairRestores(t, dir); got != approvedSourceConfigB {
		t.Fatalf("Repair restores %q, want B", got)
	}
}
