// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-1031 (the per-user Windows flood, calls with no row and no line): a
// tool call the gateway answered while its store refused the audit write had
// neither a row nor a hook line, since the hook got an ordinary answer. The
// gateway keeps the call in the data directory log, and the failure report
// writes the call row once the store works again. The call that was audited
// at once leaves no line and one row.
func TestToolCallAnsweredWhileTheAuditWriteFailedGetsItsRowFromTheFailureLog(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want string
	}{
		{"balanced", "allow"},
		{"strict", "block"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			f := newAuditFailureHookFixture(t, "")
			if tc.mode == "strict" {
				f.api.scannerCfg.Guardrail.RulePack = "strict"
			}
			data := t.TempDir()
			f.api.scannerCfg.DataDir = data
			logPath := filepath.Join(data, "logs", hookFailuresFile)

			f.emitter.fail = false
			f.preToolUse(t, "toolu_healthy")
			if _, err := os.Stat(logPath); err == nil {
				t.Fatal("a call audited at once left a line")
			}

			f.emitter.fail = true
			f.preToolUse(t, "toolu_gap")
			f.emitter.fail = false
			raw, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("the unaudited call left no line: %v", err)
			}
			if lines := strings.Count(string(raw), "\n"); lines != 1 || !strings.Contains(string(raw), `"tool_id":"toolu_gap"`) {
				t.Fatalf("log = %q, want one line naming toolu_gap", raw)
			}

			if joined := joinByToolID(t, f.api.store)["toolu_gap"]; len(joined) != 0 {
				t.Fatalf("rows before the report = %v, want none", joined)
			}
			if err := reportHookFailureCallsIn(filepath.Dir(logPath), f.api.logger, time.Now()); err != nil {
				t.Fatal(err)
			}
			joined := joinByToolID(t, f.api.store)
			if got := joined["toolu_gap"]; len(got) != 1 || got[0] != tc.want {
				t.Fatalf("rows for the unaudited call = %v, want one %s", got, tc.want)
			}
			if got := joined["toolu_healthy"]; len(got) != 1 {
				t.Fatalf("rows for the audited call = %v, want one", got)
			}
		})
	}
}
