// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
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

			// Before the report the call has its decision record only: the
			// fail-mode verdict the gateway answered (#1384). The report row
			// carries the same correlation event, so the call stays one
			// record after the report (S8 R4 review P3-2).
			if joined := joinByToolID(t, f.api.store)["toolu_gap"]; len(joined) != 1 || joined[0] != tc.want {
				t.Fatalf("rows before the report = %v, want the one %s decision", joined, tc.want)
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

// serveAuditFaultCall posts one PreToolUse to the fixture the way a script
// hook does (no delivery receipt) while its audit write fails; a client that
// has already left carries a cancelled context.
func serveAuditFaultCall(t *testing.T, f auditFailureHookFixture, body string, clientLeft bool) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(body))
	if clientLeft {
		gone, hangUp := context.WithCancel(t.Context())
		hangUp()
		request = request.WithContext(gone)
	}
	f.emitter.fail = true
	f.api.handleAgentHook("claudecode").ServeHTTP(httptest.NewRecorder(), request)
	f.emitter.fail = false
}

// GAP-1028 and GAP-1031 together: a script call whose client left cannot show
// which answer the agent got. When the audit write of that same call also
// fails, the recovery line and the row the report writes from it stay
// unconfirmed, whatever the gateway proposed: an ordinary call and a call the
// policy proposed to block alike. The call answered to its present client and
// the call under a hook that fails closed keep their allow and block rows.
func TestAuditFaultOnACallWhoseClientLeftKeepsItUnconfirmed(t *testing.T) {
	for _, tc := range []struct {
		name       string
		strict     bool
		body       string
		clientLeft bool
		want       string
	}{
		{"ordinary call, client left", false, preToolUseBodyOf(t, "toolu_gap"), true, "unconfirmed"},
		{"proposed block, client left", false, protectedWriteBody("gap"), true, "unconfirmed"},
		{"ordinary call, client present", false, preToolUseBodyOf(t, "toolu_gap"), false, "allow"},
		{"proposed block, client present", false, protectedWriteBody("gap"), false, "block"},
		{"ordinary call, client left, hook fails closed", true, preToolUseBodyOf(t, "toolu_gap"), true, "block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAuditFailureHookFixture(t, "")
			if tc.strict {
				f.api.scannerCfg.Guardrail.RulePack = "strict"
				f.api.scannerCfg.Guardrail.HookFailMode = "closed"
			}
			data := t.TempDir()
			f.api.scannerCfg.DataDir = data
			serveAuditFaultCall(t, f, tc.body, tc.clientLeft)
			if err := reportHookFailureCallsIn(filepath.Join(data, "logs"), f.api.logger, time.Now()); err != nil {
				t.Fatal(err)
			}
			toolID := "toolu_gap"
			if strings.Contains(tc.body, "gap-tool") {
				toolID = "gap-tool"
			}
			got := joinByToolID(t, f.api.store)[toolID]
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("rows for the call = %v, want exactly one %s", got, tc.want)
			}
		})
	}
}

func preToolUseBodyOf(t *testing.T, toolUseID string) string {
	t.Helper()
	return string(preToolUseBody(t, toolUseID))
}
