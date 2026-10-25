// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// An agent the enumerator found installed for a user but could not enroll
// runs without DefenseClaw hooks. Status and verify name it as a warning for
// that account and report the deployment security-incomplete; verify does
// not fail the host for it.
func TestUnprotectedAgentsAreVisible(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	data, err := enterprisehooks.MarshalUnprotectedAgents([]enterprisehooks.UnprotectedAgent{{
		User:      "alice",
		Connector: "opencode",
		Code:      enterprisehooks.UnprotectedCodeAgentUnprotected,
		Reason:    "installed, but its version could not be read: /home/alice/.local/bin/opencode; it runs without DefenseClaw hooks",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), data, 0o600); err != nil {
		t.Fatal(err)
	}
	status := h.run(Options{Action: ActionStatus})
	requireOK(t, status)
	if status.SecurityComplete {
		t.Fatal("status reports security_complete with an unprotected agent")
	}
	found := false
	for _, w := range status.Warnings {
		if w.Code == codeAgentUnprotected && strings.Contains(w.Message, "opencode for user alice is not protected: installed, but its version could not be read") {
			found = true
		}
	}
	if !found {
		t.Fatalf("status warnings do not name the unprotected agent: %+v", status.Warnings)
	}
	writeFreshLedger(t, h)
	verify := h.run(Options{Action: ActionVerify})
	requireOK(t, verify)
	if verify.SecurityComplete || messagesOf(verify.Warnings, codeAgentUnprotected) == "" {
		t.Fatalf("verify does not keep the unprotected agent as a warning: %+v", verify)
	}

	// An empty record (every agent enrolled again) clears the finding.
	empty, _ := enterprisehooks.MarshalUnprotectedAgents(nil)
	if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), empty, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, w := range h.run(Options{Action: ActionStatus}).Warnings {
		if w.Code == codeAgentUnprotected {
			t.Fatalf("an empty record still reports: %+v", w)
		}
	}
}

func TestPrivateClaudeInstallMakesUnixStatusAndVerifyIncomplete(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			h := newTestHost(t, platform)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			uid := 1001
			install := "/home/alice/private/node_modules/@anthropic-ai/claude-code"
			if platform == "darwin" {
				install = "/Users/alice/private/node_modules/@anthropic-ai/claude-code"
			}
			data, err := enterprisehooks.MarshalUnprotectedAgents([]enterprisehooks.UnprotectedAgent{{
				User: "alice", UID: &uid, Connector: "claudecode", Version: "2.0.77", InstallPath: install,
				Code:   enterprisehooks.UnprotectedCodeHookContractUnverified,
				Reason: "version 2.0.77 has no managed hook contract",
			}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), data, 0o600); err != nil {
				t.Fatal(err)
			}
			var audited []managed.LaunchCoverageReport
			h.env.ReportLaunchCoverage = func(_ context.Context, report managed.LaunchCoverageReport) error {
				audited = append(audited, report)
				return nil
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				if result.SecurityComplete || result.CoverageComplete || !strings.Contains(messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeHookContractUnverified), install) {
					t.Fatalf("%s %s hid private Claude: coverage=%v security=%v warnings=%+v", platform, action, result.CoverageComplete, result.SecurityComplete, result.Warnings)
				}
			}
			if len(audited) != 2 || audited[0].InstallPath != install || audited[0].Version != "2.0.77" || audited[0].Reason != "unsupported_installed_version" {
				t.Fatalf("private install audit = %+v", audited)
			}
		})
	}
}

// A manifest-mode install starts the enumerator but does not itself publish
// its scan. Run bypasses testHost.run, whose fake adds an empty record after
// install, so status and verify exercise the real first-cycle contract.
func TestManifestModeStatusAndVerifyWaitForPrivateInstallScan(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			h := newTestHost(t, platform)
			body := strings.Replace(string(DefaultConfig(h.env.Layout)),
				"enterprise:\n  profile: standalone\n",
				"enterprise:\n  profile: standalone\n  enrollment:\n    mode: manifest\n", 1)
			configPath := filepath.Join(t.TempDir(), "manifest-config.yaml")
			if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			install := Run(context.Background(), h.env, Options{Action: ActionInstall,
				PayloadDir: h.payload("1.0.4"), ConfigFile: configPath})
			requireOK(t, install)
			writeFreshLedger(t, h)
			recordPath := h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath))
			if _, err := os.Stat(recordPath); !os.IsNotExist(err) {
				t.Fatalf("fake install unexpectedly published scan: %v", err)
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := Run(context.Background(), h.env, Options{Action: action})
				messages := messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
				if result.CoverageComplete || result.SecurityComplete || !strings.Contains(messages, "NOT COVERED (scan pending)") ||
					!result.OK || result.ExitCode != 0 {
					t.Fatalf("%s %s claimed complete coverage before its scan: %+v", platform, action, result)
				}
			}
			data, err := enterprisehooks.MarshalUnprotectedAgents([]enterprisehooks.UnprotectedAgent{{
				User: "alice", Connector: "claudecode", Version: "2.0.77",
				Code:   enterprisehooks.UnprotectedCodeHookContractUnverified,
				Reason: "version 2.0.77 has no managed hook contract",
			}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(recordPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := Run(context.Background(), h.env, Options{Action: action})
				if result.CoverageComplete || result.SecurityComplete ||
					messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeHookContractUnverified) == "" ||
					messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete) != "" ||
					messagesOf(result.Errors, enterprisehooks.UnprotectedCodeInstallScanIncomplete) != "" {
					t.Fatalf("%s %s hid the manifest-mode private copy: %+v", platform, action, result)
				}
			}
		})
	}
}

// GAP-1430: an upgraded host keeps the previous release's record until the
// new enumerator finishes a scan. A missing, stale or future-dated record is
// one NOT COVERED (scan pending) warning naming its age and the remedy, and
// one gateway audit row; status and verify still exit 0 for it alone.
func TestPendingUnprotectedRecordIsAWarningNotAVerifyFailure(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, tc := range []struct {
			name, want, audit string
			mtime             time.Duration // 0 removes the record
		}{
			{"stale", " old (limit 16m0s)", `"scan_state":"1h0m`, -time.Hour},
			{"future", " in the future (limit 16m0s)", `in the future"`, time.Hour},
			{"missing", "record is missing (no scan has published it yet) (limit 16m0s)",
				`"scan_state":"missing (no scan has published it yet)"`, 0},
		} {
			t.Run(platform+"/"+tc.name, func(t *testing.T) {
				h := newTestHost(t, platform)
				requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
				writeFreshLedger(t, h)
				var audited []string
				h.env.ReportLaunchCoverage = func(_ context.Context, report managed.LaunchCoverageReport) error {
					data, _ := json.Marshal(report)
					audited = append(audited, string(data))
					return nil
				}
				path := h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath))
				if tc.mtime == 0 {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				} else if at := time.Now().Add(tc.mtime); os.Chtimes(path, at, at) != nil {
					t.Fatal("chtimes")
				}
				remedy := "sudo systemctl restart defenseclaw-hook-enumerator.service"
				if platform == "darwin" {
					remedy = "sudo launchctl kickstart -k system/com.cisco.defenseclaw.hook-enumerator"
				}
				for _, action := range []string{ActionStatus, ActionVerify} {
					result := h.run(Options{Action: action})
					messages := messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
					if !result.OK || result.ExitCode != 0 || result.CoverageComplete || result.SecurityComplete ||
						strings.Count(messages, "NOT COVERED (scan pending)") != 1 || !strings.Contains(messages, tc.want) ||
						!strings.Contains(messages, remedy) || len(result.Errors) != 0 {
						t.Fatalf("%s %s: ok=%v exit=%d coverage=%v security=%v errors=%+v warnings=%q", platform, action,
							result.OK, result.ExitCode, result.CoverageComplete, result.SecurityComplete, result.Errors, messages)
					}
				}
				if len(audited) != 2 || !strings.Contains(audited[1], `"reason":"agent_install_scan_pending"`) ||
					!strings.Contains(audited[1], `"connector":""`) || !strings.Contains(audited[1], tc.audit) {
					t.Fatalf("scan-pending audit = %q", audited)
				}
			})
		}
	}
}

// Only the pending scan is softened: an unreadable record and every other
// verify failure still fail verify beside a stale record (GAP-1430).
func TestPendingUnprotectedRecordKeepsRealVerifyFailures(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			h := newTestHost(t, platform)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			h.env.ReportLaunchCoverage = func(context.Context, managed.LaunchCoverageReport) error { return nil }
			path := h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath))
			old := time.Now().Add(-time.Hour)
			stale := func(data []byte) {
				t.Helper()
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chtimes(path, old, old); err != nil {
					t.Fatal(err)
				}
			}
			stale([]byte("{not json"))
			if r := h.run(Options{Action: ActionVerify}); r.OK || r.ExitCode == 0 ||
				!strings.Contains(messagesOf(r.Errors, enterprisehooks.UnprotectedCodeInstallScanIncomplete), "unreadable") {
				t.Fatalf("verify passed an unreadable record: %+v", r)
			}
			kiro, _ := enterprisehooks.MarshalUnprotectedAgents([]enterprisehooks.UnprotectedAgent{{
				User: "alice", Connector: "kiro", Version: "1.0.181", Code: enterprisehooks.UnprotectedCodeKiroIDEBelowGlobalHooksFloor,
				Reason: "Kiro IDE 1.0.181 cannot read the global hooks file",
			}})
			stale(kiro)
			if r := h.run(Options{Action: ActionVerify}); r.OK || r.ExitCode == 0 ||
				messagesOf(r.Errors, enterprisehooks.UnprotectedCodeKiroIDEBelowGlobalHooksFloor) == "" ||
				!hasWarningContaining(r, enterprisehooks.UnprotectedCodeInstallScanIncomplete, "scan pending") {
				t.Fatalf("a stale record hid an agent that fails verify: %+v", r)
			}
			empty, _ := enterprisehooks.MarshalUnprotectedAgents(nil)
			stale(empty)
			requireOK(t, h.run(Options{Action: ActionVerify}))
			if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.BinDir, binHook)), []byte("replaced\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			r := h.run(Options{Action: ActionVerify})
			requireError(t, r, codeVerify)
			if !hasWarningContaining(r, enterprisehooks.UnprotectedCodeInstallScanIncomplete, "scan pending") {
				t.Fatalf("verify with a replaced hook binary: %+v", r)
			}
		})
	}
}

func TestEnrolledKiroCLIBelowHookFloorIsUncoveredInStatusAndVerify(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	data, err := enterprisehooks.MarshalUnprotectedAgents([]enterprisehooks.UnprotectedAgent{{
		User: "alice", Connector: "kiro", Version: "2.24.1", Code: "kiro_cli_below_hook_floor",
		Reason: "kiro-cli 2.24.1 is below 2.27.1: non-interactive runs do not load hooks; the earlier enrollment remains installed",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		messages := messagesOf(r.Warnings, "kiro_cli_below_hook_floor")
		if action == ActionVerify {
			messages = messagesOf(r.Errors, "kiro_cli_below_hook_floor")
		}
		if r.CoverageComplete || r.SecurityComplete ||
			!strings.Contains(messages, "kiro 2.24.1 for user alice is not protected") ||
			(action == ActionVerify && (r.OK || r.ExitCode == 0)) ||
			(action == ActionStatus && (!r.OK || r.ExitCode != 0)) {
			t.Fatalf("%s counted an unhooked Kiro CLI as covered: coverage=%t security=%t warnings=%+v",
				action, r.CoverageComplete, r.SecurityComplete, r.Warnings)
		}
	}
}

func TestKiroIDEBelowGlobalHookFloorFailsVerify(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	data, err := enterprisehooks.MarshalUnprotectedAgents([]enterprisehooks.UnprotectedAgent{{
		User: "alice", Connector: "kiro", Version: "1.0.181", Code: enterprisehooks.UnprotectedCodeKiroIDEBelowGlobalHooksFloor,
		Reason: "Kiro IDE 1.0.181 cannot read the global hooks file",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), data, 0o600); err != nil {
		t.Fatal(err)
	}
	status := h.run(Options{Action: ActionStatus})
	verify := h.run(Options{Action: ActionVerify})
	if status.CoverageComplete || !status.OK || verify.CoverageComplete || verify.OK || verify.ExitCode == 0 ||
		!strings.Contains(messagesOf(verify.Errors, enterprisehooks.UnprotectedCodeKiroIDEBelowGlobalHooksFloor), "Kiro IDE 1.0.181") {
		t.Fatalf("old IDE appears covered: status=%+v verify=%+v", status, verify)
	}
}
