// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// gap1986Body is corpus row wsh/atomic/65704cd4 (atomic-red-team T1112): a
// cmd /c chain of reg add calls, the first on the per-user Run key.
const gap1986Body = `cmd /c reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v NetWire /t REG_SZ  /d "C:\Users\alice\AppData\Roaming\Install\Host.exe" /f & reg add HKCU\SOFTWARE\NetWire /v HostId /t REG_SZ /d HostId-kai6Ci /f & reg add HKCU\SOFTWARE\NetWire /v "Install Date" /t REG_SZ /d "2021-08-30 07:17:27" /f`

// gap1986StartProcessDQ is the det111 r1 start-process-dq spelling of body:
// Start-Process powershell with body as a quoted -Command argument, with the
// PowerShell escapes of a double-quoted string.
func gap1986StartProcessDQ(body string) string {
	inner := "\"" + strings.ReplaceAll(body, "\"", "\\\"") + "\""
	quoted := strings.NewReplacer("`", "``", "$", "`$", "\"", "\\`\"").Replace("-NoProfile -Command " + inner)
	return "Start-Process powershell -ArgumentList \"" + quoted + "\" -Wait"
}

// gap1986CodexBash sends command as a Codex Bash PreToolUse call and returns
// "action severity rule_ids".
func gap1986CodexBash(t *testing.T, h http.HandlerFunc, command string, managedTier bool) (action, verdict string) {
	t.Helper()
	raw, _ := json.Marshal(shapeParityEnvelope("PreToolUse", t.TempDir(), "Bash", map[string]any{"command": command}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Hook-Event", "PreToolUse")
	req.Header.Set("X-DefenseClaw-Hook-Contract", defaultTestCodexHookContract)
	if managedTier {
		if ev := hookpaths.ResolveConnector("codex", "", "PreToolUse", raw); ev != "" {
			req.Header.Set(hookpaths.Header, ev)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("http %d", w.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("answer is not JSON: %v", err)
	}
	action = fmt.Sprint(out["action"])
	return action, fmt.Sprint(action, " ", out["severity"], " ", out["rule_ids"])
}

// The longer syntax-tail reading of GAP-0745 only raises: a PowerShell
// Start-Process line sent on the Codex Bash route has a Bash syntax error,
// and the cut of its first statement found past the word steps of the
// cut-back holds the Run-key text, which the Bash reading turns into
// HKCUSoftware... . Taking that text out of the strict and managed
// parser-differential scan turned the 1.0.10 alert CRITICAL
// ACTION-PARSE-FAILURE into an allow (rel-1-0-10:GAP-1986, R-NOLOSS row
// r1/start-process-dq/corpus/wsh/atomic/65704cd4 hook-codex). The same line
// around a benign reg query does not block in any tier.
func TestGAP1986LongerSyntaxTailReadingKeepsTheUnreadScan(t *testing.T) {
	attack := gap1986StartProcessDQ(gap1986Body)
	benign := gap1986StartProcessDQ(`cmd /c reg query HKCU\Software\Contoso /v Theme & echo "theme read" & echo "done"`)
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		cx := gap0437Server(t, p, "codex", "action")
		installToolCallCorpusProfileConnector(t, "codex", p.pack)
		hook := cx.handleAgentHook("codex")
		if p.pack == "strict" || p.managed {
			action, verdict := gap1986CodexBash(t, hook, attack, p.managed)
			if gap0745ActionRank[action] < gap0745ActionRank["alert"] || !strings.Contains(verdict, "CRITICAL") ||
				!strings.Contains(verdict, parseFailureRuleID) {
				t.Errorf("%s: %s, want at least alert CRITICAL %s as in 1.0.10", p.name, verdict, parseFailureRuleID)
			}
		}
		if action, verdict := gap1986CodexBash(t, hook, benign, p.managed); action == "block" {
			t.Errorf("%s benign twin: %s", p.name, verdict)
		}
	})
}
