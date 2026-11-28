// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// Claude Code tool calls that carry a literal key (Write content, a Bash
// printf) are captured at PreToolUse and denied; the value is stored exposed.
func TestSandboxVaultCapturesClaudeToolCalls(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"Write", `{"file_path":"/work/app/local.env","content":"STRIPE_KEY=` + vaultTestStripeKey() + `\n"}`},
		{"Bash", `{"command":"printf 'STRIPE_KEY=` + vaultTestStripeKey() + `\\n' > local.env","description":"write env"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := vault.Open(filepath.Join(t.TempDir(), "vault"))
			f := newSandboxIngressFixture(t, withTestVault(st))
			rec := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok,
				`{"hook_event_name":"PreToolUse","session_id":"sess-ct","tool_name":"`+tc.name+`","tool_input":`+tc.input+`,"tool_use_id":"toolu_ct","cwd":"/work/app"}`)
			if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), vaultTestStripeKey()) {
				t.Fatalf("hook: %d %s", rec.Code, rec.Body.String())
			}
			var resp map[string]interface{}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			out, _ := resp["claude_code_output"].(map[string]interface{})
			specific, _ := out["hookSpecificOutput"].(map[string]interface{})
			if resp["action"] != "block" || specific["permissionDecision"] != "deny" {
				t.Fatalf("answer = %v", resp)
			}
			if e, err := st.Get("STRIPE_API_KEY"); err != nil || e.Status() != vault.StatusExposed {
				t.Fatalf("entry = %+v (%v)", e, err)
			}
		})
	}
}
