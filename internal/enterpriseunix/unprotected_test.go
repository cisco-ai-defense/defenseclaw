// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
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

func TestMissingUnprotectedRecordMakesUnixCoverageUnknown(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			h := newTestHost(t, platform)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			path := h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath))
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				messages := messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
				if action == ActionVerify {
					messages = messagesOf(result.Errors, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
				}
				if result.CoverageComplete || result.SecurityComplete ||
					!strings.Contains(messages, "unprotected-agents record") {
					t.Fatalf("%s %s hid missing install evidence: %+v", platform, action, result)
				}
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
				if action == ActionVerify {
					messages = messagesOf(result.Errors, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
				}
				if result.CoverageComplete || result.SecurityComplete || messages == "" {
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

func TestStaleUnprotectedRecordMakesUnixCoverageUnknown(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			h := newTestHost(t, platform)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			path := h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath))
			old := time.Now().Add(-time.Hour)
			if err := os.Chtimes(path, old, old); err != nil {
				t.Fatal(err)
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				messages := messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
				if action == ActionVerify {
					messages = messagesOf(result.Errors, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
				}
				if result.CoverageComplete || result.SecurityComplete || !strings.Contains(messages, "stale") {
					t.Fatalf("%s %s hid stale scan evidence: %+v", platform, action, result)
				}
			}
		})
	}
}
