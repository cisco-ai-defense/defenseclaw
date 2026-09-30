// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const standaloneContractRefusal = "not verified against a known hook contract"

func TestStandaloneRowAdmissionRefusesVersionsAboveTheFloorWithoutAContract(t *testing.T) {
	home := t.TempDir()
	for _, tc := range []struct{ connector, version string }{
		{"cursor", "4.1.0"},              // above cursor-hooks-v1's upper bound
		{"cursor", "2026.08.01-abc1234"}, // an unpinned date-hash build
		{"devin", "1.0.0"},               // Devin has no minimum, only exact pins
		{"devin", "3000.11.3"},           // pinned on Linux only
		{"hermes", "0.22.1"},             // above hermes-hooks-v2
		{"opencode", "1.19.2"},           // above opencode-hooks-v1
	} {
		if minimum := windowsEnterpriseStandaloneAgentMinimum(tc.connector); minimum != "" &&
			compareWindowsEnterpriseVersion(connector.NormalizeAgentVersion(tc.connector, tc.version), minimum) < 0 {
			t.Fatalf("fixture %s %s must clear the lowest-contract floor %s", tc.connector, tc.version, minimum)
		}
		ok, reason := windowsStandaloneRowAdmission(home, tc.connector, tc.version)
		if ok || !strings.Contains(reason, standaloneContractRefusal) {
			t.Errorf("%s %s admitted (ok=%t reason=%q), want the known-contract refusal", tc.connector, tc.version, ok, reason)
		}
	}
}

func cursorProfile(t *testing.T, version string) string {
	t.Helper()
	home := t.TempDir()
	writeWindowsAgentPackageJSON(t, filepath.Join(home, "AppData", "Local", "Programs", "cursor", "resources", "app"), version)
	return home
}

func TestEnumerateWindowsStandaloneSkipsNewRowsOutsideEveryContract(t *testing.T) {
	stubMachineWinGet(t, nil)
	const outsideSID = "S-1-5-21-1004336348-1177238915-682003330-1002"
	injectWindowsProfileList(t, map[string]string{
		testLocalUserSID: cursorProfile(t, "2.5.0"),
		outsideSID:       cursorProfile(t, "4.1.0"),
	})
	var logged []string
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("cursor"), EnumerateOptions{
		Logger: func(subject, reason string) { logged = append(logged, subject+": "+reason) },
	})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].SID != testLocalUserSID {
		t.Fatalf("targets = %+v, want only the user whose Cursor has a known contract", manifest.Targets)
	}
	if !strings.Contains(strings.Join(logged, "\n"), outsideSID+": newly-discovered (SID, cursor) row skipped: version 4.1.0 is "+standaloneContractRefusal) {
		t.Fatalf("the skipped row must be logged with its reason; log:\n%s", strings.Join(logged, "\n"))
	}
}

func TestApplyStandaloneRowStateDropsKnownRowsWithoutAContract(t *testing.T) {
	enabled := true
	prior := ManifestTarget{SID: testLocalUserSID, Connector: "codex", AgentVersion: "0.100.0", Enabled: &enabled, Deferred: true}
	row := ManifestTarget{SID: testLocalUserSID, Connector: "codex", UserHome: codexProfile(t, "0.150.0")}
	previous := map[string]ManifestTarget{previousManifestKey(prior.SID, prior.Connector): prior}
	if applyStandaloneRowState(&row, previous, nil) {
		t.Fatalf("known enabled row at %s has no hook contract and must be dropped, got %+v", prior.AgentVersion, row)
	}

	disabled := false
	prior.Enabled = &disabled
	previous[previousManifestKey(prior.SID, prior.Connector)] = prior
	row = ManifestTarget{SID: testLocalUserSID, Connector: "codex", UserHome: codexProfile(t, "0.150.0")}
	if !applyStandaloneRowState(&row, previous, nil) || row.IsEnabled() {
		t.Fatalf("an administrator-disabled row must be kept disabled, got %+v", row)
	}
}

// A known contract below the Windows platform minimum still cannot install:
// Codex 0.125.0 and 0.130.0 resolve to known contracts, but install and verify
// refuse anything below 0.131.0. Such a row, new or already in the manifest,
// is dropped for that user instead of failing every reconcile.
func TestStandaloneRowAdmissionAppliesTheWindowsPlatformMinimum(t *testing.T) {
	home := t.TempDir()
	for _, version := range []string{"0.125.0", "0.130.0"} {
		if connector.ResolveHookContract("codex", version).Status != connector.HookCompatibilityKnown {
			t.Fatalf("fixture codex %s must resolve to a known contract", version)
		}
		if err := requireWindowsEnterpriseManagedAgentVersion("codex", version); err == nil {
			t.Fatalf("fixture codex %s must be below the install minimum", version)
		}
		ok, reason := windowsStandaloneRowAdmission(home, "codex", version)
		if ok || !strings.Contains(reason, "below the Windows enterprise minimum 0.131.0") {
			t.Errorf("codex %s admitted (ok=%t reason=%q), want the platform-minimum refusal", version, ok, reason)
		}
	}
	if ok, reason := windowsStandaloneRowAdmission(home, "codex", "0.131.0"); !ok {
		t.Fatalf("codex 0.131.0 refused: %s", reason)
	}

	enabled := true
	prior := ManifestTarget{SID: testLocalUserSID, Connector: "codex", AgentVersion: "0.125.0", Enabled: &enabled}
	row := ManifestTarget{SID: testLocalUserSID, Connector: "codex", UserHome: codexProfile(t, "0.150.0")}
	previous := map[string]ManifestTarget{previousManifestKey(prior.SID, prior.Connector): prior}
	var logged []string
	if applyStandaloneRowState(&row, previous, func(_, reason string) { logged = append(logged, reason) }) {
		t.Fatalf("known enabled row at %s is below the Windows minimum and must be dropped, got %+v", prior.AgentVersion, row)
	}
	if !strings.Contains(strings.Join(logged, "\n"), "row dropped: version 0.125.0 is below the Windows enterprise minimum") {
		t.Fatalf("the dropped row must be logged with its reason; log:\n%s", strings.Join(logged, "\n"))
	}
}
