// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/configs"
)

// Tests in this package swap providerDomains directly; load the registry up
// front so a later lazy load cannot replace their injected entries.
func init() {
	ensureProviderRegistry()
}

// unmanagedProviderRegistry runs the test in the unmanaged provider posture
// whatever an earlier test left: a managed sidecar boot (NewSidecar, a config
// reload) makes the process ignore DEFENSECLAW_CUSTOM_PROVIDERS_PATH, so in a
// shuffled order the overlay tests read a registry without their overlay
// (rel-1-0-10:GAP-1305). The earlier posture is restored with the test.
func unmanagedProviderRegistry(t *testing.T) {
	t.Helper()
	providerRegistryMu.Lock()
	previous := providerRegistryManagedEnterprise
	providerRegistryMu.Unlock()
	setProviderRegistryManagedEnterprise(false)
	t.Cleanup(func() { setProviderRegistryManagedEnterprise(previous) })
}

// The provider overlay tests pass after a managed boot left the process in
// the managed posture, as they do in the declared order.
func TestProviderOverlayTestsIgnoreAnEarlierManagedBoot(t *testing.T) {
	providerRegistryMu.Lock()
	previous := providerRegistryManagedEnterprise
	providerRegistryMu.Unlock()
	setProviderRegistryManagedEnterprise(true)
	t.Cleanup(func() { setProviderRegistryManagedEnterprise(previous) })
	t.Run("malformed overlay not applied", TestProviderResponsesReportMalformedOverlayNotApplied)
	t.Run("env overlay path", TestCustomProvidersPath_EnvOverride)
	t.Run("managed posture ignores the path override", TestSetProviderRegistryManagedEnterpriseIgnoresPathOverride)
}

// Entering managed posture rebuilds a loaded registry without the
// environment-selected overlay, and leaving it restores the override.
func TestSetProviderRegistryManagedEnterpriseIgnoresPathOverride(t *testing.T) {
	unmanagedProviderRegistry(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	overlay := filepath.Join(t.TempDir(), "custom-providers.json")
	body := `{"providers":[{"name":"EnvOverlay","domains":["env-overlay.example.com"]}]}`
	if err := os.WriteFile(overlay, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", overlay)
	if err := ReloadProviderRegistry(); err != nil {
		t.Fatalf("ReloadProviderRegistry: %v", err)
	}
	t.Cleanup(func() {
		setProviderRegistryManagedEnterprise(false)
		configs.SetIgnoreCustomProvidersPathEnv(false)
		t.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", "")
		_ = ReloadProviderRegistry()
	})
	if !isKnownProviderDomain("https://env-overlay.example.com/v1") {
		t.Fatal("env overlay not applied in unmanaged posture")
	}

	setProviderRegistryManagedEnterprise(true)
	if isKnownProviderDomain("https://env-overlay.example.com/v1") {
		t.Fatal("managed posture still honors DEFENSECLAW_CUSTOM_PROVIDERS_PATH")
	}

	setProviderRegistryManagedEnterprise(false)
	if !isKnownProviderDomain("https://env-overlay.example.com/v1") {
		t.Fatal("unmanaged posture did not restore the override")
	}
}
