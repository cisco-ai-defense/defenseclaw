// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestWindowsHookKeepsWhatThePowerShellReadingProves transforms every
// PowerShell attack fixture of the tool-call corpus: the unreadable statement
// of TestWindowsReadingTwinRequests is placed before and after it, joined by a
// newline or "; ". When the hook places such a call in no dialect and its own
// reading is ambiguous PowerShell, the hook verdict (with its readings) is at
// least the verdict of the PowerShell reading of the same call
// (rel-1-0-10:GAP-0405, GAP-0425). At least one of those calls has no
// statement readable on its own, so the whole PowerShell reading is the extra
// reading (GAP-0425), and at least one has a readable-statements reading.
func TestWindowsHookKeepsWhatThePowerShellReadingProves(t *testing.T) {
	rank := func(action string) int {
		got, _ := bounded.ParseAction(action)
		return int(got)
	}
	var unplaced, whole, readable int
	for _, fixture := range readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl") {
		if !fixture.IsAttack || fixture.Dialect != actionfacts.DialectPowerShell || fixture.Command == "" {
			continue
		}
		cwd := fixture.CWD
		if cwd == "" {
			cwd = `C:\repo`
		}
		for _, layout := range []struct{ name, before, after string }{
			{"before/nl", windowsUnreadableStatement + "\n", ""}, {"after/nl", "", "\n" + windowsUnreadableStatement},
			{"before/sc", windowsUnreadableStatement + "; ", ""}, {"after/sc", "", "; " + windowsUnreadableStatement},
		} {
			command := layout.before + fixture.Command + layout.after
			input := windowsHookShellCall(command, cwd)
			if input.DialectHint != "" {
				continue
			}
			own := actionfacts.Analyze(input)
			if own.Parse.Status != actionfacts.StatusAmbiguous || own.Parse.Dialect != actionfacts.DialectPowerShell {
				continue
			}
			hinted := input
			hinted.DialectHint = actionfacts.DialectPowerShell
			hintedFacts := actionfacts.Analyze(hinted)
			if hintedFacts.Parse.Status != actionfacts.StatusPartial {
				continue
			}
			unplaced++
			var trunc bounded.Truncated
			if _, ok := actionfacts.PowerShellReadableStatementsTwin(hinted, hintedFacts, &trunc); ok {
				readable++
			} else {
				whole++
			}
			for _, pack := range []string{"default", "strict"} {
				want := evaluateDeterministicAction(context.Background(), hinted, command, "benchmark-"+pack, pack, true)
				got := evaluateDeterministicAction(context.Background(), input, command, "benchmark-"+pack, pack, true)
				if rank(got.Action) < rank(want.Action) {
					t.Errorf("%s/%s/%s: hook %s %v, the PowerShell reading %s %v",
						fixture.ID, layout.name, pack, got.Action, got.RuleIDs, want.Action, want.RuleIDs)
				}
			}
		}
	}
	if whole == 0 || readable == 0 {
		t.Fatalf("unplaced calls %d: %d with no readable statement, %d with one; the test no longer pins both readings", unplaced, whole, readable)
	}
}

// TestWindowsHookCappedReadingIsAtLeastTheUnknownTier sends, through the
// Codex hook as on a Windows host, calls of N copies of an atomic parity
// fixture and the unreadable statement: the hook's own reading of them stops
// at the command cap, under the statement budget. The call is truncated at
// the unknown tier of the pack (alert in default and permissive, block in
// strict) through internal/guardrail/bounded, never allowed
// (rel-1-0-10:GAP-0426).
func TestWindowsHookCappedReadingIsAtLeastTheUnknownTier(t *testing.T) {
	unit := windowsAtomicParityPositives[2].command
	for _, copies := range []int{63, 64, 127, 128} {
		parts := make([]string, 0, copies+1)
		for range copies {
			parts = append(parts, unit)
		}
		command := strings.Join(append(parts, windowsUnreadableStatement), "\n")
		own := actionfacts.Analyze(windowsHookShellCall(command, `C:\repo`))
		if own.Parse.Status != actionfacts.StatusLimitExceeded {
			t.Fatalf("%d copies: the hook's reading is %s/%s, want a capped reading", copies, own.Parse.Status, own.Parse.Dialect)
		}
		for _, pack := range []struct {
			name string
			tier bounded.Tier
		}{{"default", bounded.TierDefault}, {"permissive", bounded.TierPermissive}, {"strict", bounded.TierStrict}} {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, pack.name)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack.name)
			previous := windowsHookHost
			windowsHookHost = func() bool { return true }
			response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse",
				ToolName:      "shell",
				CWD:           `C:\repo`,
				ToolInput:     map[string]interface{}{"command": command},
			})
			windowsHookHost = previous
			got, _ := bounded.ParseAction(response.Action)
			t.Logf("%d copies, %s pack: the Codex hook answers %s", copies, pack.name, response.Action)
			if want := bounded.Unknown(pack.tier); got < want {
				t.Errorf("%d copies, %s pack: action %q, want at least %s (the unknown tier of a capped reading)",
					copies, pack.name, response.Action, want)
			}
		}
	}
}

// TestWindowsHookFixtureRunMoreThanOnceKeepsItsFinding runs the tool-call
// corpus fixture of rel-1-0-10:GAP-0427 two, three and eight times in one
// call, one run per line, with and without a further unreadable statement:
// its rule and verdict stay those of one run. (A call whose statements are
// joined by ";" is a partial reading by the lexer's own rule and is not
// proven even once; that is not a repeat effect.)
func TestWindowsHookFixtureRunMoreThanOnceKeepsItsFinding(t *testing.T) {
	const id = "windows-uac-eventvwr-autoelevation-hijack"
	var fixture *toolCallCorpusCase
	for _, test := range readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl") {
		if test.ID == id {
			test := test
			fixture = &test
		}
	}
	if fixture == nil {
		t.Fatalf("fixture %s not found", id)
	}
	for _, pack := range []string{"default", "strict"} {
		once := evaluateDeterministicAction(context.Background(), windowsHookShellCall(fixture.Command, fixture.CWD),
			fixture.Command, "benchmark-"+pack, pack, true)
		if !findingIDsHave(once.RuleIDs, fixture.RuleID) {
			t.Fatalf("%s: the fixture alone has no %s: %v", pack, fixture.RuleID, once.RuleIDs)
		}
		for _, runs := range []int{2, 3, 8, 32} {
			for _, withUnreadable := range []bool{false, true} {
				parts := make([]string, runs)
				for i := range parts {
					parts[i] = fixture.Command
				}
				if withUnreadable {
					parts = append(parts, windowsUnreadableStatement)
				}
				command := strings.Join(parts, "\n")
				got := evaluateDeterministicAction(context.Background(), windowsHookShellCall(command, fixture.CWD),
					command, "benchmark-"+pack, pack, true)
				if got.Action != once.Action || !findingIDsHave(got.RuleIDs, fixture.RuleID) {
					t.Errorf("%s, %d runs, unreadable statement %t: action %q rules %v, want %q with %s",
						pack, runs, withUnreadable, got.Action, got.RuleIDs, once.Action, fixture.RuleID)
				}
			}
		}
	}
}

func findingIDsHave(ids []string, id string) bool {
	for _, got := range ids {
		if got == id {
			return true
		}
	}
	return false
}
