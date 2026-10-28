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

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// kiroCLIProfile is a profile whose kiro-cli last ran as version.
func kiroCLIProfile(t *testing.T, version string) string {
	t.Helper()
	home := t.TempDir()
	root := filepath.Join(home, "AppData", "Local", "Kiro-Cli")
	for path, content := range map[string]string{
		filepath.Join(root, "kiro-cli.exe"):                    "MZ-current",
		filepath.Join(root, "run", "chat-cli-"+version+".exe"): "MZ-current",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// 1.0.3 enrolled kiro-cli from 2.24.1. After the upgrade to the 2.27.1
// floor, such a row is kept and repaired at its version, as on Unix, instead
// of being dropped to unprotected; only new enrollments and version changes
// below the floor are refused.
func TestApplyStandaloneRowStateKeepsAKiroRowAnEarlierReleaseEnrolledBelowTheFloor(t *testing.T) {
	setStandaloneProfileForTest(t, true)
	enabled := true
	prior := ManifestTarget{SID: testLocalUserSID, Connector: "kiro", AgentVersion: "2.24.1", Enabled: &enabled}
	previous := map[string]ManifestTarget{previousManifestKey(prior.SID, prior.Connector): prior}

	for _, tc := range []struct {
		name, installed, want string
		session               bool
		keptReport            bool
	}{
		{name: "signed out", installed: "2.24.1", want: "2.24.1", keptReport: true},
		{name: "unchanged", installed: "2.24.1", want: "2.24.1", session: true, keptReport: true},
		{name: "change below the floor", installed: "2.26.1", want: "2.24.1", session: true, keptReport: true},
		{name: "upgrade to the floor", installed: "2.27.1", want: "2.27.1", session: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reports []UnprotectedAgent
			var logged []string
			row := ManifestTarget{SID: testLocalUserSID, Connector: "kiro", UserHome: kiroCLIProfile(t, tc.installed)}
			ctx := windowsStandaloneRowContext{sessionActive: tc.session, user: "alice", report: func(a UnprotectedAgent) { reports = append(reports, a) }}
			if !applyStandaloneRowStateFor(&row, previous, func(_, reason string) { logged = append(logged, reason) }, ctx) {
				t.Fatalf("row dropped; log:\n%s\nreports: %+v", strings.Join(logged, "\n"), reports)
			}
			if row.AgentVersion != tc.want || !row.IsEnabled() {
				t.Fatalf("row = %+v, want enabled at %s", row, tc.want)
			}
			wantReports := 0
			if tc.keptReport {
				wantReports = 1
			}
			if len(reports) != wantReports {
				t.Fatalf("reports = %+v, want kept report %t", reports, tc.keptReport)
			}
			if tc.keptReport {
				report := reports[0]
				if report.Version != tc.installed || report.Code != "kiro_cli_below_hook_floor" ||
					!strings.Contains(report.Reason, "is below 2.27.1") {
					t.Fatalf("report = %+v, want the installed version below the floor", report)
				}
				if tc.installed != tc.want {
					if !strings.Contains(report.Reason, "the row stays enrolled at "+tc.want) {
						t.Fatalf("report = %+v, want the prior enrollment consequence", report)
					}
				} else if !strings.Contains(report.Reason, "non-interactive runs do not load them") {
					t.Fatalf("report = %+v, want the unhooked non-interactive consequence", report)
				}
			}
		})
	}

	// A new row below the floor is not written.
	var reports []UnprotectedAgent
	row := ManifestTarget{SID: testLocalUserSID, Connector: "kiro", UserHome: kiroCLIProfile(t, "2.26.1")}
	ctx := windowsStandaloneRowContext{sessionActive: true, user: "alice", report: func(a UnprotectedAgent) { reports = append(reports, a) }}
	if applyStandaloneRowStateFor(&row, map[string]ManifestTarget{}, nil, ctx) {
		t.Fatalf("new kiro-cli 2.26.1 row written: %+v", row)
	}
	if len(reports) != 1 || reports[0].Version != "2.26.1" || !strings.Contains(reports[0].Reason, "is below 2.27.1") {
		t.Fatalf("reports = %+v, want the new row below the floor reported", reports)
	}
}

func TestWindowsKiroIDEVersionIsNotJudgedByTheCLIFloor(t *testing.T) {
	if reason := windowsKiroCLIBelowHookFloor("1.0.182" + KiroIDEVersionSuffix); reason != "" {
		t.Fatalf("a supported IDE was judged as an unhooked CLI: %s", reason)
	}
	setStandaloneProfileForTest(t, true)
	enabled := true
	prior := ManifestTarget{SID: testLocalUserSID, Connector: "kiro", AgentVersion: "1.0.182" + KiroIDEVersionSuffix, Enabled: &enabled}
	previous := map[string]ManifestTarget{previousManifestKey(prior.SID, prior.Connector): prior}
	var reports []UnprotectedAgent
	row := ManifestTarget{SID: testLocalUserSID, UserHome: t.TempDir(), Connector: "kiro"}
	ctx := windowsStandaloneRowContext{user: "alice", report: func(a UnprotectedAgent) { reports = append(reports, a) }}
	if !applyStandaloneRowStateFor(&row, previous, nil, ctx) || row.AgentVersion != prior.AgentVersion || len(reports) != 0 {
		t.Fatalf("signed-out supported IDE was reported uncovered: row=%+v reports=%+v", row, reports)
	}
}

func TestWindowsKiroOldCLIStillEnrollsSupportedIDE(t *testing.T) {
	setStandaloneProfileForTest(t, true)
	home := kiroCLIProfile(t, "2.26.1")
	product := filepath.Join(home, "AppData", "Local", "Programs", "Kiro", "resources", "app", "product.json")
	if err := os.MkdirAll(filepath.Dir(product), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(product, []byte(`{"nameShort":"Kiro","applicationName":"kiro","version":"1.0.182"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := discoverWindowsKiroAgentVersion(home); got != "1.0.182"+KiroIDEVersionSuffix {
		t.Fatalf("selected Kiro version = %q, want supported IDE", got)
	}
	var reports []UnprotectedAgent
	row := ManifestTarget{SID: testLocalUserSID, UserHome: home, Connector: "kiro"}
	ctx := windowsStandaloneRowContext{sessionActive: true, user: "alice", report: func(a UnprotectedAgent) { reports = append(reports, a) }}
	if !applyStandaloneRowStateFor(&row, map[string]ManifestTarget{}, nil, ctx) ||
		row.AgentVersion != "1.0.182"+KiroIDEVersionSuffix || !row.IsEnabled() {
		t.Fatalf("supported IDE was not enrolled: row=%+v reports=%+v", row, reports)
	}
	if len(reports) != 1 || reports[0].Version != "2.26.1" || !strings.Contains(reports[0].Reason, "is below 2.27.1") {
		t.Fatalf("old CLI was not reported separately: %+v", reports)
	}

	enabled := true
	prior := ManifestTarget{SID: testLocalUserSID, Connector: "kiro", AgentVersion: "2.24.1", Enabled: &enabled}
	previous := map[string]ManifestTarget{previousManifestKey(prior.SID, prior.Connector): prior}
	reports = nil
	row = ManifestTarget{SID: testLocalUserSID, UserHome: home, Connector: "kiro"}
	if !applyStandaloneRowStateFor(&row, previous, nil, ctx) || row.AgentVersion != "1.0.182"+KiroIDEVersionSuffix {
		t.Fatalf("earlier CLI row did not follow supported IDE: row=%+v reports=%+v", row, reports)
	}
	if len(reports) != 1 || reports[0].Version != "2.26.1" {
		t.Fatalf("earlier CLI row hid the installed unsupported CLI: %+v", reports)
	}

	if err := os.WriteFile(product, []byte(`{"nameShort":"Kiro","applicationName":"kiro","version":"1.0.181"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	reports = nil
	row = ManifestTarget{SID: testLocalUserSID, UserHome: home, Connector: "kiro"}
	if applyStandaloneRowStateFor(&row, map[string]ManifestTarget{}, nil, ctx) || len(reports) != 2 {
		t.Fatalf("two unsupported Kiro surfaces were not both reported: row=%+v reports=%+v", row, reports)
	}
	for _, report := range reports {
		if strings.Contains(report.Reason, "stays enrolled") {
			t.Fatalf("unprotected Kiro surface claims an enrollment: %+v", reports)
		}
	}
}

// The guardian install keeps repairing the hooks 1.0.3 installed at kiro-cli
// 2.24.1, refuses a change to another version below the floor as drift,
// follows an upgrade to the floor, and refuses a new enrollment below it.
func TestValidateHookContractRepairsAWindowsKiroLockBelowTheFloor(t *testing.T) {
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	setStandaloneProfileForTest(t, true)
	conn := connector.NewKiroConnector()
	opts := func(dataDir, version string) connector.SetupOpts {
		return connector.SetupOpts{DataDir: dataDir, AgentVersion: version, HookContractID: connector.KiroWindowsManagedCLIContractID}
	}
	enrolled := t.TempDir()
	if err := connector.SaveHookContractLockEntry(enrolled, connector.NewHookContractLockEntry(opts(enrolled, "2.24.1"), conn, "1.0.3")); err != nil {
		t.Fatalf("seed the 1.0.3 lock: %v", err)
	}
	if err := validateHookContract("action", conn, opts(enrolled, "2.24.1")); err != nil {
		t.Fatalf("repair at the enrolled version: %v", err)
	}
	if err := validateHookContract("action", conn, opts(enrolled, "2.26.1")); err == nil ||
		!strings.Contains(err.Error(), "hook contract drift detected") || !strings.Contains(err.Error(), "is below 2.27.1") {
		t.Fatalf("a change below the floor = %v, want the drift refusal", err)
	}
	if err := validateHookContract("action", conn, opts(enrolled, "2.27.1")); err != nil {
		t.Fatalf("upgrade to the floor: %v", err)
	}

	fresh := t.TempDir()
	if err := validateHookContract("action", conn, opts(fresh, "2.24.1")); err == nil ||
		!strings.Contains(err.Error(), "cannot load hooks") || !strings.Contains(err.Error(), "is below 2.27.1") {
		t.Fatalf("new enrollment below the floor = %v, want the certified-minimum refusal", err)
	}
	if err := validateHookContract("action", conn, opts(fresh, "2.27.1")); err != nil {
		t.Fatalf("new enrollment at the floor: %v", err)
	}
}
