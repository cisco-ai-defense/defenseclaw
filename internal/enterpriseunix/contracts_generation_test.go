// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterpriseunix

import (
	"os"
	"strings"
	"testing"
	"time"

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
					if data, err = enterprisehooks.MarshalUnprotectedAgents(nil); err != nil {
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
