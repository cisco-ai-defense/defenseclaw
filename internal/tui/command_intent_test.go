// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"
	"testing"
)

func TestCommandIntentMasksSecretArgs(t *testing.T) {
	intent := NewCommandIntent(
		"defenseclaw",
		[]string{"keys", "set", "DEFENSECLAW_LLM_KEY", "--value", "sk-test-1234567890"},
		"keys set DEFENSECLAW_LLM_KEY --value sk-test-1234567890",
		"setup",
		"credentials",
	)
	if !intent.HasSecretArgs() {
		t.Fatal("expected secret-bearing intent")
	}
	line := intent.MaskedCommandLine()
	if strings.Contains(line, "sk-test-1234567890") {
		t.Fatalf("masked command leaked secret: %s", line)
	}
	if !strings.Contains(line, "****7890") {
		t.Fatalf("masked command missing secret suffix preview: %s", line)
	}
	if !intent.NeedsConfirmation() {
		t.Fatal("secret-bearing command must require confirmation")
	}
}

func TestCommandIntentRiskInference(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want CommandRisk
	}{
		{"doctor", []string{"doctor"}, CommandRiskReadOnly},
		{"doctor-fix", []string{"doctor", "--fix", "--yes"}, CommandRiskSetup},
		{"restart", []string{"restart"}, CommandRiskRestart},
		{"remove", []string{"plugin", "remove", "x"}, CommandRiskDestructive},
		{"plugin-info", []string{"plugin", "info", "x"}, CommandRiskReadOnly},
		{"skill-scan", []string{"skill", "scan", "x"}, CommandRiskReadOnly},
		{"keys-check", []string{"keys", "check"}, CommandRiskReadOnly},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := NewCommandIntent("defenseclaw", tc.args, strings.Join(tc.args, " "), "", "test").Risk
			if got != tc.want {
				t.Fatalf("risk=%s want %s", got, tc.want)
			}
		})
	}
}

func TestCommandIntentFromEntryRequiresArgs(t *testing.T) {
	reg := BuildRegistry()
	var entry *CmdEntry
	for i := range reg {
		if reg[i].TUIName == "keys set" {
			entry = &reg[i]
			break
		}
	}
	if entry == nil {
		t.Fatal("missing keys set entry")
	}
	if _, err := CommandIntentFromEntry(entry, "", "palette"); err == nil {
		t.Fatal("expected missing argument guidance")
	}
}

func TestCommandIntentNormalizedPreservesInteractive(t *testing.T) {
	intent := NewCommandIntent("defenseclaw", []string{"init"}, "init", "setup", "first-run")
	intent.Interactive = true
	if !intent.Normalized().Interactive {
		t.Fatal("normalized intent must preserve interactive execution")
	}
}
