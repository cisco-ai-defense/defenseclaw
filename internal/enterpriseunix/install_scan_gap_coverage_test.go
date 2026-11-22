// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-10 GAP-0802 (Linux and macOS share the rule with Windows): a gap
// in the bounded scan of an account whose managed hook is verified (a
// connector in vendor machine policy, or a per-user target the guardian
// attested current) is a warning that names the reason and the folder, and
// coverage_complete stays true. A copy the scan found that the hook contract
// does not cover, and a gap of an account whose per-user hook the guardian
// did not verify (failed, pending or not attested), still leave coverage
// incomplete.
func TestInstallScanGapOfAVerifiedAccountKeepsCoverage(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			file := "linux-standalone.yaml"
			if goos == "darwin" {
				file = "macos-standalone.yaml"
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, readSampleConfig(t, file))}))
			record, err := h.env.loadDeployment()
			if err != nil {
				t.Fatal(err)
			}
			// machine is a scanned connector the install put in vendor machine
			// policy (a machine-wide hook, no per-user target); perUser is one
			// it did not, judged by its attested guardian target.
			machine, perUser := "", ""
			for _, name := range []string{"claudecode", "codex", "copilot", "opencode"} {
				switch {
				case slices.Contains(record.MachinePolicyConnectors, name) && machine == "":
					machine = name
				case !slices.Contains(record.MachinePolicyConnectors, name) && perUser == "":
					perUser = name
				}
			}
			if machine == "" || perUser == "" {
				t.Fatalf("machine policy connectors %q leave no machine and per-user connector to test", record.MachinePolicyConnectors)
			}
			home := "/home/alice"
			if goos == "darwin" {
				home = "/Users/alice"
			}
			folder := filepath.Join(home, "work", "huge")
			writeHostFile(t, h, h.env.Layout.ManifestPath, "version: 1\ntargets:\n"+
				"  - user: alice\n    uid: 1001\n    user_home: "+home+"\n    connector: "+perUser+"\n    agent_version: 2.1.0\n")
			attest := func(state string) {
				t.Helper()
				ledger, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format(time.RFC3339), "ok": true})
				h.publishLedger(ledger, enterprisehooks.CredentialAttestationTarget{Connector: perUser, User: "alice", UserHome: home, UID: 1001, State: state})
			}
			writeState := func(row map[string]any) {
				t.Helper()
				results := []map[string]any{}
				if row != nil {
					results = append(results, row)
				}
				state, _ := json.Marshal(map[string]any{"results": results})
				if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.DataDir, guardianStateFile)), state, 0o640); err != nil {
					t.Fatal(err)
				}
			}
			// writeRecord publishes the record the enumerator writes, with the
			// scan gap code and folder of each gap entry.
			writeRecord := func(agents []enterprisehooks.UnprotectedAgent, gaps ...int) {
				t.Helper()
				data, err := h.marshalCompletedScan(agents)
				if err != nil {
					t.Fatal(err)
				}
				var published map[string]any
				if err := json.Unmarshal(data, &published); err != nil {
					t.Fatal(err)
				}
				entries, _ := published["agents"].([]any)
				for _, index := range gaps {
					entries[index].(map[string]any)["skipped"] = enterprisehooks.PrivateInstallSkippedHome
					entries[index].(map[string]any)["folder"] = folder
				}
				if data, err = json.Marshal(published); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			gap := func(connector string) enterprisehooks.UnprotectedAgent {
				return enterprisehooks.UnprotectedAgent{User: "alice", Connector: connector, Code: enterprisehooks.UnprotectedCodeInstallScanIncomplete,
					Reason: "the bounded scan of the private agent installs of this account was incomplete; use application control to exclude unapproved agent binaries"}
			}
			found := enterprisehooks.UnprotectedAgent{User: "alice", Connector: machine, Version: "1.0.0",
				InstallPath: filepath.Join(home, "old", "node_modules", "pkg"), Code: enterprisehooks.UnprotectedCodeHookContractUnverified,
				Reason: "version 1.0.0 is below the supported range; this copy may ignore managed hooks or the documented version floor, so its tool calls are not protected"}
			verifiedRow := map[string]any{"user": "alice", "user_home": home, "connector": perUser, "ok": true}

			attest(enterprisehooks.CredentialTargetCurrent)
			writeState(verifiedRow)
			writeRecord(nil)
			if baseline := h.run(Options{Action: ActionStatus}); !baseline.CoverageComplete {
				t.Fatalf("baseline status is not coverage complete: %+v", baseline.Warnings)
			}

			// (1) Verified managed hooks (machine policy, attested per-user
			// target), scan gaps: covered, with a warning that names the folder.
			writeRecord([]enterprisehooks.UnprotectedAgent{gap(machine), gap(perUser)}, 0, 1)
			for _, action := range []string{ActionStatus, ActionVerify} {
				r := h.run(Options{Action: action})
				requireOK(t, r)
				partial := messagesOf(r.Warnings, enterprisehooks.UnprotectedCodeInstallScanPartial)
				if !r.CoverageComplete || strings.Count(partial, folder) != 2 || !strings.Contains(partial, machine+" for user alice") ||
					!strings.Contains(partial, perUser+" for user alice") || strings.Contains(partial, "not protected") ||
					messagesOf(r.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete) != "" ||
					strings.Contains(messagesOf(r.Warnings, "security_incomplete"), "agent_install_scan") {
					t.Fatalf("%s: verified hooks with scan gaps: coverage_complete=%t warnings=%+v", action, r.CoverageComplete, r.Warnings)
				}
			}

			// (2) Verified managed hook, but the scan found a copy outside the
			// hook contract: not protected.
			writeRecord([]enterprisehooks.UnprotectedAgent{gap(machine), found}, 0)
			for _, action := range []string{ActionStatus, ActionVerify} {
				r := h.run(Options{Action: action})
				if r.CoverageComplete || !strings.Contains(messagesOf(r.Warnings, enterprisehooks.UnprotectedCodeHookContractUnverified), "is not protected") {
					t.Fatalf("%s: a found copy outside the hook contract: coverage_complete=%t warnings=%+v", action, r.CoverageComplete, r.Warnings)
				}
			}

			// (3) The guardian did not verify the per-user hook: the gap keeps
			// coverage incomplete and names the folder.
			writeRecord([]enterprisehooks.UnprotectedAgent{gap(perUser)}, 0)
			for name, setup := range map[string]func(){
				"failed row": func() {
					writeState(map[string]any{"user": "alice", "user_home": home, "connector": perUser, "ok": false, "error": "setup failed"})
				},
				"pending row": func() {
					writeState(map[string]any{"user": "alice", "user_home": home, "connector": perUser, "ok": false, "pending": true})
				},
				"pending target": func() { writeState(nil); attest(enterprisehooks.CredentialTargetPending) },
				"no attestation": func() {
					writeState(verifiedRow)
					if err := os.Remove(h.env.P(filepath.Join(h.env.Layout.GuardianAuthDir, managed.HookGuardianCredentialAttestationFile))); err != nil {
						t.Fatal(err)
					}
				},
			} {
				setup()
				r := h.run(Options{Action: ActionStatus})
				incomplete := messagesOf(r.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
				if r.CoverageComplete || !strings.Contains(incomplete, perUser+" for user alice is not protected") || !strings.Contains(incomplete, folder) {
					t.Fatalf("%s: unverified hook with a scan gap: coverage_complete=%t warnings=%+v", name, r.CoverageComplete, r.Warnings)
				}
				attest(enterprisehooks.CredentialTargetCurrent)
			}
		})
	}
}
