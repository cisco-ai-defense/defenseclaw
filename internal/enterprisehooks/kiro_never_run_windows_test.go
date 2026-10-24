// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// kiroNeverRunProfile is a profile with kiro-cli.exe and no run copy: the
// CLI has not run since it was installed, so nothing names its version.
func kiroNeverRunProfile(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	launcher := filepath.Join(home, "AppData", "Local", "Kiro-Cli", "kiro-cli.exe")
	if err := os.MkdirAll(filepath.Dir(launcher), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcher, []byte("MZ-current"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

func writeKiroIDEProduct(t *testing.T, home, version string) {
	t.Helper()
	product := filepath.Join(home, "AppData", "Local", "Programs", "Kiro", "resources", "app", "product.json")
	if err := os.MkdirAll(filepath.Dir(product), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(product, []byte(`{"nameShort":"Kiro","applicationName":"kiro","version":"`+version+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

// rel-1-0-4 GAP-0829: a never-run kiro-cli was enrolled at the standalone
// floor, so a 2.24.1 install whose headless runs load no hooks counted as a
// supported one. Its version is never assumed: a new row is not written and
// is reported, a row an earlier build enrolled at an assumed version is kept
// (its hooks stay installed) and reported uncovered, and a supported IDE
// beside it still enrolls while the CLI is reported.
func TestWindowsKiroCLIWithNoReadableVersionIsNotEnrolledAtAnAssumedVersion(t *testing.T) {
	setStandaloneProfileForTest(t, true)
	collect := func(reports *[]UnprotectedAgent, active bool) windowsStandaloneRowContext {
		return windowsStandaloneRowContext{sessionActive: active, user: "alice", report: func(a UnprotectedAgent) { *reports = append(*reports, a) }}
	}
	uncovered := func(t *testing.T, reports []UnprotectedAgent, version, consequence string) {
		t.Helper()
		if len(reports) != 1 || reports[0].Code != UnprotectedCodeHookContractUnverified || reports[0].Version != version ||
			!strings.Contains(reports[0].Reason, "its version is unknown") || !strings.Contains(reports[0].Reason, consequence) {
			t.Fatalf("reports = %+v, want one uncovered kiro-cli with version %q and %q", reports, version, consequence)
		}
	}

	home := kiroNeverRunProfile(t)
	if got := discoverWindowsKiroAgentVersion(home); got != "" {
		t.Fatalf("never-run kiro-cli enrolls at %q, want no assumed version", got)
	}
	for _, active := range []bool{true, false} {
		var reports []UnprotectedAgent
		row := ManifestTarget{SID: testLocalUserSID, Connector: "kiro", UserHome: home}
		if applyStandaloneRowStateFor(&row, map[string]ManifestTarget{}, nil, collect(&reports, active)) {
			t.Fatalf("session active %v: new row written at %q", active, row.AgentVersion)
		}
		uncovered(t, reports, "", "runs without DefenseClaw hooks")
	}

	// 1.0.3 assumed 2.24.1 and earlier 1.0.4 builds 2.27.1. The row stays
	// (upgrade compatibility) but is not counted as protected, and it does
	// not claim a below-floor version the CLI never named.
	enabled := true
	for _, assumed := range []string{"2.24.1", "2.27.1"} {
		for _, active := range []bool{true, false} {
			prior := ManifestTarget{SID: testLocalUserSID, Connector: "kiro", AgentVersion: assumed, Enabled: &enabled}
			previous := map[string]ManifestTarget{previousManifestKey(prior.SID, prior.Connector): prior}
			var reports []UnprotectedAgent
			row := ManifestTarget{SID: testLocalUserSID, Connector: "kiro", UserHome: home}
			if !applyStandaloneRowStateFor(&row, previous, nil, collect(&reports, active)) || row.AgentVersion != assumed {
				t.Fatalf("assumed %s, session active %v: row = %+v, want it kept", assumed, active, row)
			}
			uncovered(t, reports, assumed, "the row stays enrolled at "+assumed+", which this kiro-cli has not confirmed")
		}
	}

	// A supported IDE beside it enrolls; the CLI is reported.
	writeKiroIDEProduct(t, home, "1.0.190")
	var reports []UnprotectedAgent
	row := ManifestTarget{SID: testLocalUserSID, Connector: "kiro", UserHome: home}
	if !applyStandaloneRowStateFor(&row, map[string]ManifestTarget{}, nil, collect(&reports, true)) ||
		row.AgentVersion != "1.0.190"+KiroIDEVersionSuffix {
		t.Fatalf("supported IDE beside an unversioned CLI: row = %+v reports = %+v", row, reports)
	}
	uncovered(t, reports, "", "is not counted as protected until its version is read")

	// Once a run copy names a supported version, the CLI enrolls with no report.
	runCopy := filepath.Join(home, "AppData", "Local", "Kiro-Cli", "run", "chat-cli-2.27.1.exe")
	if err := os.MkdirAll(filepath.Dir(runCopy), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runCopy, []byte("MZ-current"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(home, "AppData", "Local", "Programs", "Kiro", "resources", "app", "product.json")); err != nil {
		t.Fatal(err)
	}
	reports = nil
	row = ManifestTarget{SID: testLocalUserSID, Connector: "kiro", UserHome: home}
	if !applyStandaloneRowStateFor(&row, map[string]ManifestTarget{}, nil, collect(&reports, true)) ||
		row.AgentVersion != "2.27.1" || len(reports) != 0 {
		t.Fatalf("kiro-cli after its first run: row = %+v reports = %+v", row, reports)
	}
}
