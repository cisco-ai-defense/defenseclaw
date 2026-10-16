// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestAgentHookStatementPrefixRecovery(t *testing.T) {
	prefixes := []struct{ name, text string }{
		{"bare", ">x; "},
		{"append", ">>x; "},
		{"fd", "2>x; "},
		{"input", "<x; "},
		{"inout", "<>x; "},
		{"dynamic", ">$X; "},
		{"dup", "2>&1; "},
		{"multiple", ">x 2>y; "},
		{"quoted", "<<'EOF'\nbody\nEOF\n"},
	}
	targets := []struct {
		name, command string
		protected     bool
	}{
		{"protected_key_read", "cat ~/.ssh/id_rsa", true},
		{"root_delete", "rm -rf /", true},
		{"benign_list", "ls", false},
		{"benign_build", "make", false},
	}
	modes := []struct{ name, decisionMode, failMode string }{
		{"action_closed", "action", "closed"},
		{"action_open", "action", "open"},
		{"observe_closed", "observe", "closed"},
	}
	for _, mode := range modes {
		for _, prefix := range append([]struct{ name, text string }{{"plain", ""}}, prefixes...) {
			for _, target := range targets {
				t.Run(strings.Join([]string{mode.name, prefix.name, target.name}, "/"), func(t *testing.T) {
					store, logger := testStoreAndLogger(t)
					cfg := &config.Config{}
					cfg.Guardrail.Mode = mode.decisionMode
					cfg.Guardrail.Connector = "claudecode"
					cfg.Guardrail.HookFailMode = mode.failMode
					cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
					api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
					response := postDecisionForTest(t, api, "claudecode", "PreToolUse", prefix.text+target.command)
					wantAction := "allow"
					wantResult := "ok"
					if prefix.text != "" {
						wantResult = "panic" // rel/1.0.2 evaluator recovery
						if mode.decisionMode == "action" && mode.failMode == "closed" {
							wantAction = "block"
						}
					} else if target.protected && mode.decisionMode == "action" {
						wantAction = "block"
					}
					if response["action"] != wantAction || response["mode"] != mode.decisionMode {
						t.Fatalf("action/mode=%v/%v, want %s/%s", response["action"], response["mode"], wantAction, mode.decisionMode)
					}
					if prefix.text != "" && wantAction == "allow" && response["would_block"] != true {
						t.Fatalf("recovered allow would_block=%v, want true", response["would_block"])
					}
					if got := decisionIsDenied(response["claude_code_output"]); got != (wantAction == "block") {
						t.Fatalf("harness denial=%v, want %v, output=%v", got, wantAction == "block", response["claude_code_output"])
					}
					if prefix.text != "" && mode.decisionMode == "action" && mode.failMode == "closed" && !target.protected {
						if reason, _ := response["reason"].(string); !strings.Contains(reason, "internal evaluator error") {
							t.Fatalf("benign recovery reason=%q, want internal error", reason)
						}
					}
					row := soleHookDecisionForTest(t, store)
					if row.Structured["result"] != wantResult {
						t.Fatalf("audit result=%v, want %s", row.Structured["result"], wantResult)
					}
					if wantResult == "panic" {
						extra, _ := row.Structured["extra"].(map[string]any)
						if extra["panic"] != "true" {
							t.Fatalf("audit extra=%v, want panic=true", extra)
						}
					}
				})
			}
		}
	}
}
