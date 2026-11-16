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

// quotedOperandWords is n quoted ordinary names.
func quotedOperandWords(n int) string {
	words := make([]string, n)
	for i := range words {
		words[i] = fmt.Sprintf("\"q%d\"", i)
	}
	return strings.Join(words, " ")
}

// pathOperandWords is n ordinary names written as paths.
func pathOperandWords(n int) string {
	words := make([]string, n)
	for i := range words {
		words[i] = fmt.Sprintf("./p%d", i)
	}
	return strings.Join(words, " ")
}

// redirectTargets is n redirections to ordinary files.
func redirectTargets(n int) string {
	words := make([]string, n)
	for i := range words {
		words[i] = fmt.Sprintf(">r%d", i)
	}
	return strings.Join(words, " ")
}

// A call with more operands than actionfacts.MaxOperandsPerCall, counted over
// all its statements and redirection targets, is unresolved (GAP-0943): a
// protected file or link the call names directly, or through a value it
// knows, or within the bound, is blocked in every tier, whatever stands
// before it, and so is a later name that is a link; the other plain names
// past the bound are not resolved further, so the default tier allows with an
// alert that names the bound and the strict tier keeps the evaluation-limit
// block. A call within the bound is judged as before and raises neither.
func TestCallOverOperandBoundIsJudgedByTheTier(t *testing.T) {
	bound := actionfacts.MaxOperandsPerCall
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
		{"redirect to a link that is named plainly past the bound", "echo " + operandWords(5000) + " >> alias", "block", "block", true},
		{"redirect to link within the bound", "echo " + operandWords(900) + " >> alias", "block", "block", false},
		{"redirect with a descriptor past the bound", "echo " + operandWords(5000) + " 2>/dev/null >> alias", "block", "block", true},
		{"redirect with a descriptor within the bound", "echo " + operandWords(900) + " 2>/dev/null >> alias", "block", "block", false},
		{"keys file named last", "touch " + operandWords(5000) + " ../.ssh/authorized_keys", "block", "block", true},
		{"keys file named by a value", "k=../.ssh/authorized_keys; echo " + operandWords(5000) + " >> $k", "block", "block", true},
		{"keys file in a quoted word", "tee " + operandWords(5000) + " \"../.ssh/authorized_keys\"", "block", "block", true},
		{"keys file in the second statement", "echo " + operandWords(5000) + " > out.txt; echo m >> ../.ssh/authorized_keys", "block", "block", true},
		{"keys file by a glob", "tee " + operandWords(5000) + " ../.ssh/authorized_k*", "block", "block", true},
		{"link named plainly past the bound", "tee " + operandWords(5000) + " alias", "block", "block", true},
		{"five statements of a thousand ordinary names", strings.Repeat("touch "+operandWords(1000)+"; ", 5), "alert", "block", true},
		{"five thousand ordinary redirect targets", "echo x " + redirectTargets(5000), "alert", "block", true},
		{"five thousand ordinary quoted names", "touch " + quotedOperandWords(5000), "alert", "block", true},
		{"a here-document body is no operand list", "cat > out.txt <<\x27EOF\x27\n" + operandWords(5000) + "\nEOF\n", "allow", "allow", false},
		{"keys file after more quoted names than the bound", "touch " + operandWords(1023) + " " + quotedOperandWords(1025) + " ../.ssh/authorized_keys", "block", "block", true},
		{"keys file after thousands of quoted names", "touch " + quotedOperandWords(5000) + " ../.ssh/authorized_keys", "block", "block", true},
		{"keys file after thousands of path names", "touch " + pathOperandWords(5000) + " ../.ssh/authorized_keys", "block", "block", true},
		{"keys file as the last redirect target", "echo x " + redirectTargets(5000) + " >> ../.ssh/authorized_keys", "block", "block", true},
		{"keys file in the last of five statements", strings.Repeat("touch "+operandWords(1000)+"; ", 4) + "echo m >> ../.ssh/authorized_keys", "block", "block", true},
		{"link named plainly in the last of five statements", strings.Repeat("touch "+operandWords(1000)+"; ", 4) + "echo m >> alias", "block", "block", true},
		{"keys file named by a value after quoted names", "k=../.ssh/authorized_keys; touch " + quotedOperandWords(5000) + " $k", "block", "block", true},
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
