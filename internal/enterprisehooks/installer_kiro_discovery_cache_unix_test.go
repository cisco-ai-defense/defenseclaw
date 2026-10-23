//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeKiroDiscoveryCache writes the agent_discovery.json Python discovery
// records for Kiro: version is the selected surface's (a kiro-cli as its
// `kiro-cli X` banner, the IDE bare), and the per-surface fields next to it.
func writeKiroDiscoveryCache(t *testing.T, home, selected, cli, ide string) {
	t.Helper()
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"version": 7,
		"agents": map[string]any{"kiro": map[string]any{
			"name": "kiro", "installed": true, "version": selected,
			"binary_path":      "/usr/local/bin/kiro",
			"kiro_cli_version": cli, "kiro_ide_version": ide,
		}},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "agent_discovery.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// kiroInstallProfiles are the three install profiles of the Go installer:
// the standalone guardian, Secure Client, and a non-standalone process on a
// host without Secure Client (the Linux admin CLI).
var kiroInstallProfiles = []string{"standalone", "secure-client", "managed-cli"}

func useKiroInstallProfile(t *testing.T, profile string) {
	t.Helper()
	setStandaloneProfileForTest(t, profile == "standalone")
	switch profile {
	case "secure-client":
		useSecureClientHookDelivery(t)
	case "managed-cli":
		previous := secureClientHookDeliveryHost
		secureClientHookDeliveryHost = false
		t.Cleanup(func() { secureClientHookDeliveryHost = previous })
	}
}

// An install or verify that names no agent version reads it from the
// per-user discovery cache. Python discovery records the Kiro IDE there as a
// bare version, and the installer read 1.0.182 as a kiro-cli below 2.27.1, so
// a supported IDE that setup accepts was refused in every profile. The cached
// IDE version is now the IDE's, mixed installs follow the surface discovery
// selected, and each surface keeps its own floor.
func TestKiroInstallFromDiscoveryCacheAppliesTheSelectedSurfaceFloor(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	cases := []struct {
		name, selected, cli, ide string
		recorded, refusal        string
	}{
		{name: "IDE only", selected: "1.0.182", ide: "1.0.182", recorded: "1.0.182" + KiroIDEVersionSuffix},
		{name: "newer IDE only", selected: "1.2.0", ide: "1.2.0", recorded: "1.2.0" + KiroIDEVersionSuffix},
		{name: "IDE beside an older CLI", selected: "1.0.182", cli: "kiro-cli 2.26.1", ide: "1.0.182", recorded: "1.0.182" + KiroIDEVersionSuffix},
		{name: "CLI beside an IDE", selected: "kiro-cli 2.27.1", cli: "kiro-cli 2.27.1", ide: "1.0.182", recorded: "kiro-cli 2.27.1"},
		{name: "CLI beside an older IDE", selected: "kiro-cli 2.28.0", cli: "kiro-cli 2.28.0", ide: "1.0.150", recorded: "kiro-cli 2.28.0"},
		{name: "IDE below its floor", selected: "1.0.150", ide: "1.0.150", refusal: "Kiro IDE version 1.0.150 is below the certified minimum 1.0.182"},
		{name: "both below their floors", selected: "kiro-cli 2.26.1", cli: "kiro-cli 2.26.1", ide: "1.0.150", refusal: "is below 2.27.1"},
		{name: "CLI only below its floor", selected: "kiro-cli 2.20.0", cli: "kiro-cli 2.20.0", refusal: "is below 2.27.1"},
	}
	for _, profile := range kiroInstallProfiles {
		for _, mode := range []string{"observe", "action"} {
			for _, tc := range cases {
				t.Run(profile+"/"+mode+"/"+tc.name, func(t *testing.T) {
					useKiroInstallProfile(t, profile)
					home := newTestHome(t)
					writeKiroDiscoveryCache(t, home, tc.selected, tc.cli, tc.ide)
					opts := kiroStandaloneInstallOptions(home, "")
					opts.GuardrailMode = mode
					result, err := Install(context.Background(), opts)
					if tc.refusal != "" {
						if err == nil || !strings.Contains(err.Error(), tc.refusal) {
							t.Fatalf("install = %v, want a refusal naming %q", err, tc.refusal)
						}
						return
					}
					if err != nil {
						t.Fatalf("install from the discovery cache: %v", err)
					}
					if result.AgentVersion != tc.recorded {
						t.Fatalf("install recorded %q, want %q", result.AgentVersion, tc.recorded)
					}
					verified, err := Verify(context.Background(), opts)
					if err != nil {
						t.Fatalf("verify from the discovery cache: %v", err)
					}
					if verified.AgentVersion != tc.recorded {
						t.Fatalf("verify read %q, want %q", verified.AgentVersion, tc.recorded)
					}
				})
			}
		}
	}
}

// Earlier releases installed a cached Kiro IDE under its bare version, so
// that is what their contract locks record. The same IDE build now arrives
// marked as the IDE's; that alone is no agent change and the repair goes
// ahead in action mode. A real IDE version change is still drift outside the
// standalone profile, which follows only versions at or above the floor.
func TestKiroIDELockFromAnEarlierCacheInstallIsRepaired(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	for _, profile := range kiroInstallProfiles {
		t.Run(profile, func(t *testing.T) {
			useKiroInstallProfile(t, profile)
			home := newTestHome(t)
			seedEarlierKiroLock(t, kiroStandaloneInstallOptions(home, "1.0.182"))
			writeKiroDiscoveryCache(t, home, "1.0.182", "", "1.0.182")
			opts := kiroStandaloneInstallOptions(home, "")
			result, err := Install(context.Background(), opts)
			if err != nil {
				t.Fatalf("repair of an earlier IDE install: %v", err)
			}
			if result.AgentVersion != "1.0.182"+KiroIDEVersionSuffix {
				t.Fatalf("repair recorded %q", result.AgentVersion)
			}
			if _, err := Verify(context.Background(), opts); err != nil {
				t.Fatalf("verify after the repair: %v", err)
			}

			changed := newTestHome(t)
			seedEarlierKiroLock(t, kiroStandaloneInstallOptions(changed, "1.0.181"))
			writeKiroDiscoveryCache(t, changed, "1.0.190", "", "1.0.190")
			_, err = Install(context.Background(), kiroStandaloneInstallOptions(changed, ""))
			switch profile {
			case "managed-cli":
				if err == nil || !strings.Contains(err.Error(), "hook contract drift detected") {
					t.Fatalf("an IDE version change = %v, want the drift refusal", err)
				}
			default:
				// The standalone guardian follows an IDE at or above its floor;
				// Secure Client installs a changed version in open delivery.
				if err != nil {
					t.Fatalf("an IDE upgrade at or above its floor: %v", err)
				}
			}
		})
	}
}
