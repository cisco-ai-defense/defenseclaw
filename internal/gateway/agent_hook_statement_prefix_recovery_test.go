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

func TestAgentHookRedirectOnlyPrefixDoesNotPanic(t *testing.T) {
	prefixes := []struct{ name, text string }{
		{"bare", ">x; "},
		{"append", ">>x; "},
		{"fd", "2>x; "},
		{"input", "<x; "},
		{"inout", "<>x; "},
		{"multiple", ">x 2>y; "},
		{"quoted", "<<'EOF'\nbody\nEOF\n"},
	}
	targets := []struct{ name, command string }{
		{"list", "ls"},
		{"build", "make"},
	}
	modes := []struct{ name, decisionMode, failMode string }{
		{"action_closed", "action", "closed"},
		{"action_open", "action", "open"},
		{"observe_closed", "observe", "closed"},
	}
	for _, mode := range modes {
		for _, prefix := range prefixes {
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
					if response["action"] != "allow" || response["mode"] != mode.decisionMode || response["would_block"] == true {
						t.Fatalf("ordinary redirect prefix response=%v, want allow without would_block in %s mode", response, mode.decisionMode)
					}
					if decisionIsDenied(response["claude_code_output"]) {
						t.Fatalf("ordinary redirect prefix denied: %v", response["claude_code_output"])
					}
					row := soleHookDecisionForTest(t, store)
					if row.Structured["result"] != "ok" {
						t.Fatalf("audit result=%v, want ok", row.Structured["result"])
					}
				})
			}
		}
	}
}

// GAP-0651: each form executes a protected command despite a preceding or
// trailing shell construct. The hook must evaluate the executed command.
func TestR103B07GAP0651ProtectedCommandGroups(t *testing.T) {
	forms := []struct{ name, command string }{
		{"colon_spaced", ": ; cat ~/.ssh/id_ed25519"},
		{"colon_tight", ":;cat ~/.ssh/id_ed25519"},
		{"colon_redirect", ": >marker; cat ~/.ssh/id_ed25519"},
		{"brace_group", "{ :; }; cat ~/.ssh/id_ed25519"},
		{"subshell_group", "(:); cat ~/.ssh/id_ed25519"},
		{"colon_and", ": && cat ~/.ssh/id_ed25519"},
		{"preceding_newline", ":\ncat ~/.ssh/id_ed25519"},
		{"trailing_colon_redirect", "cat ~/.ssh/id_ed25519; : >marker"},
		// GAP-0701: sed reads the key as cat does.
		{"sed_read", "sed -n 1p ~/.ssh/id_ed25519"},
		{"colon_then_sed", ": ; sed -n 1p ~/.ssh/id_ed25519"},

		{"colon_root_delete", ":; rm -rf /"},
		{"brace_root_delete", "{ :; }; rm -rf /"},
		{"subshell_root_delete", "(:); rm -rf /"},
		{"newline_root_delete", ":\nrm -rf /"},
		{"trailing_colon_root_delete", "rm -rf /; : >marker"},
	}
	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			store, logger := testStoreAndLogger(t)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "claudecode"
			cfg.Guardrail.HookFailMode = "closed"
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
			api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
			response := postDecisionForTest(t, api, "claudecode", "PreToolUse", form.command)
			if response["action"] != "block" || !decisionIsDenied(response["claude_code_output"]) {
				t.Fatalf("command=%q action=%v output=%v", form.command, response["action"], response["claude_code_output"])
			}
			row := soleHookDecisionForTest(t, store)
			if row.Structured["result"] != "ok" {
				t.Fatalf("audit result=%v", row.Structured["result"])
			}
		})
	}
}
