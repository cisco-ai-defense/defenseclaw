// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func operandWords(n int) string {
	words := make([]string, n)
	for i := range words {
		words[i] = fmt.Sprintf("f%d", i)
	}
	return strings.Join(words, " ")
}

// A statement with more operands than actionfacts.MaxOperandsPerStatement is
// unresolved (GAP-0943, GAP-0963): a protected file or link the call names
// directly, or through a value it knows, or within the bound, is blocked in
// every tier; the plain names past the bound are not asked whether they are
// links, so the default tier allows with an alert that names the bound and
// the strict tier keeps the evaluation-limit block. A call within the bound
// is judged as before and raises neither.
func TestStatementOverOperandBoundIsJudgedByTheTier(t *testing.T) {
	bound := actionfacts.MaxOperandsPerStatement
	rows := []struct {
		name, command string
		def, strict   string
		over          bool // the default tier alerts and the strict tier adds the limit rule
	}{
		{"ordinary below the bound", "touch " + operandWords(bound-24), "allow", "allow", false},
		{"ordinary at the bound", "echo " + operandWords(bound), "allow", "allow", false},
		{"ordinary past the bound", "echo " + operandWords(5000), "alert", "block", true},
		{"ordinary touch past the bound", "touch " + operandWords(bound+1), "alert", "block", true},
		{"link below the bound", "touch " + operandWords(bound-24) + " alias; echo m >> alias", "block", "block", false},
		{"link as first operand past the bound", "tee alias " + operandWords(5000), "block", "block", true},
		{"redirect to link past the bound", "echo " + operandWords(5000) + " >> alias", "block", "block", true},
		{"redirect with a descriptor past the bound", "echo " + operandWords(5000) + " 2>/dev/null >> alias", "block", "block", true},
		{"keys file named last", "touch " + operandWords(5000) + " ../.ssh/authorized_keys", "block", "block", true},
		{"keys file named by a value", "k=../.ssh/authorized_keys; echo " + operandWords(5000) + " >> $k", "block", "block", true},
		{"keys file in a quoted word", "tee " + operandWords(5000) + " \"../.ssh/authorized_keys\"", "block", "block", true},
		{"keys file in the second statement", "echo " + operandWords(5000) + " > out.txt; echo m >> ../.ssh/authorized_keys", "block", "block", true},
		{"keys file by a glob", "tee " + operandWords(5000) + " ../.ssh/authorized_k*", "block", "block", true},
		{"link named plainly past the bound", "tee " + operandWords(5000) + " alias", "alert", "block", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			home, cwd := r104ReviewHome(t)
			for _, strict := range []bool{false, true} {
				func() {
					defer hookpaths.HookCall()()
					request := trustedActionRequest{
						Input: actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home,
							DialectHint: actionfacts.DialectPOSIX},
						Connector: "claudecode", EnforcementCapable: true, StrictPolicy: strict,
					}
					ctx := withShareBodyStrict(t.Context(), func() bool { return strict })
					findings := dispatchTrustedAction(ctx, request)
					got, want := buildVerdict(findings, "tool_call").Action, row.def
					if strict {
						want = row.strict
					}
					if got != want {
						t.Errorf("strict=%v: %s, want %s (findings %v)", strict, got, want, findings)
					}
					alert := slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == operandBoundRuleID })
					limit := slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == "ACTION-COMPOUND-LIMIT" })
					if !strict && alert != row.over {
						t.Errorf("default tier alert: %v, want %v", alert, row.over)
					}
					if strict && limit != row.over {
						t.Errorf("strict tier ACTION-COMPOUND-LIMIT: %v, want %v", limit, row.over)
					}
					if strict && alert || !strict && limit {
						t.Errorf("the other tier verdict is present: %v", findings)
					}
				}()
			}
		})
	}
}
