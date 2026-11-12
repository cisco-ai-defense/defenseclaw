// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-1454: a record the previous install wrote a few minutes before an
// upgrade is not wall-clock stale, so status and verify accepted it as the
// current scan. Every record carries the install generation that wrote it;
// one from another generation (or none, 1.0.4 and earlier) is scan pending
// until the current enumerator publishes, whatever its age. A record of the
// current generation still counts.
func TestUnprotectedRecordFromAnEarlierInstallIsPending(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, tc := range []struct {
			name, record, want string
			pending            bool
		}{
			{"previous release without a generation", `{"version":1,"agents":[]}` + "\n", "written by an earlier release", true},
			{"previous release with a generation", `{"version":1,"generation":"1.0.0-earlier","agents":[]}` + "\n", "written by 1.0.0-earlier", true},
			{"current generation", "", "", false},
		} {
			t.Run(platform+"/"+tc.name, func(t *testing.T) {
				h := newTestHost(t, platform)
				requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
				writeFreshLedger(t, h)
				path := h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath))
				data := []byte(tc.record)
				if tc.record == "" {
					var err error
					current, generationErr := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
					if generationErr != nil || current.Generation == 0 {
						t.Fatalf("read current config generation: %+v, %v", current, generationErr)
					}
					if data, err = enterprisehooks.MarshalUnprotectedAgentsForConfig(nil, current.Generation, current.ConfigSHA256); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				// Five minutes old: inside the 16-minute freshness window.
				if at := time.Now().Add(-5 * time.Minute); os.Chtimes(path, at, at) != nil {
					t.Fatal("chtimes")
				}
				for _, action := range []string{ActionStatus, ActionVerify} {
					result := h.run(Options{Action: action})
					messages := messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
					if !result.OK || result.ExitCode != 0 || len(result.Errors) != 0 {
						t.Fatalf("%s: a record of another install must not fail on its own: ok=%v exit=%d errors=%+v", action, result.OK, result.ExitCode, result.Errors)
					}
					if !tc.pending {
						if strings.Contains(messages, "scan pending") || !result.CoverageComplete {
							t.Fatalf("%s: a current record must count: coverage=%v warnings=%q", action, result.CoverageComplete, messages)
						}
						continue
					}
					if result.CoverageComplete || result.SecurityComplete ||
						strings.Count(messages, "NOT COVERED (scan pending)") != 1 || !strings.Contains(messages, "from an earlier install") ||
						!strings.Contains(messages, tc.want) {
						t.Fatalf("%s: coverage=%v security=%v warnings=%q, want one scan-pending row for the earlier install",
							action, result.CoverageComplete, result.SecurityComplete, messages)
					}
				}
			})
		}
	}
}

// GAP-0640: a connector added by a config generation must not inherit the
// previous enumerator scan's complete result. Until a scan of this generation
// finishes, status, verify and ensure show pending coverage. A later scan
// with the same empty agent list restores complete coverage.
func TestUnprotectedRecordPredatingConfigGenerationIsPending(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			h := newTestHost(t, platform)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			recordPath := h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath))
			generationPath := h.env.P(configwrite.GenerationPath(h.env.Layout.ConfigPath))
			current, err := configwrite.ReadGenerationState(generationPath)
			if err != nil || current.Generation == 0 {
				t.Fatalf("read installed config generation: %+v, %v", current, err)
			}
			writeRecord := func(generation uint64) {
				t.Helper()
				data, err := enterprisehooks.MarshalUnprotectedAgents(nil)
				if err != nil {
					t.Fatal(err)
				}
				var record map[string]any
				if err := json.Unmarshal(data, &record); err != nil {
					t.Fatal(err)
				}
				record["config_generation"] = generation
				record["config_sha256"] = current.ConfigSHA256
				data, err = json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(recordPath, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			writeRecord(current.Generation)
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				if !result.CoverageComplete || messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete) != "" {
					t.Fatalf("%s with the current scan: coverage=%t warnings=%+v", action, result.CoverageComplete, result.Warnings)
				}
			}
			current.Generation++
			data, err := json.Marshal(current)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(generationPath, data, 0o640); err != nil {
				t.Fatal(err)
			}
			for _, action := range []string{ActionStatus, ActionVerify, ActionEnsure} {
				result := h.run(Options{Action: action})
				warnings := messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
				if result.CoverageComplete || result.SecurityComplete || !strings.Contains(warnings, "NOT COVERED (scan pending)") ||
					!strings.Contains(warnings, "different config generation") {
					t.Fatalf("%s with an earlier scan: coverage=%t security=%t warnings=%+v", action, result.CoverageComplete, result.SecurityComplete, result.Warnings)
				}
			}
			writeRecord(0)
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				warnings := messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
				if result.CoverageComplete || result.SecurityComplete || !strings.Contains(warnings, "different config generation") {
					t.Fatalf("%s with an unstamped scan: coverage=%t security=%t warnings=%+v", action, result.CoverageComplete, result.SecurityComplete, result.Warnings)
				}
			}
			legacy, err := enterprisehooks.MarshalUnprotectedAgents(nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(recordPath, legacy, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				warnings := messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
				if result.CoverageComplete || result.SecurityComplete || !strings.Contains(warnings, "different config generation") {
					t.Fatalf("%s with a missing scan stamp: coverage=%t security=%t warnings=%+v", action, result.CoverageComplete, result.SecurityComplete, result.Warnings)
				}
			}
			writeRecord(current.Generation)
			result := h.run(Options{Action: ActionStatus})
			if !result.CoverageComplete || messagesOf(result.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete) != "" {
				t.Fatalf("status after the current scan: coverage=%t warnings=%+v", result.CoverageComplete, result.Warnings)
			}
		})
	}
}
