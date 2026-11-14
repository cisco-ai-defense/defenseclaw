// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestWindowsHookJudgesTheReadableStatementsOfAPartialPowerShellCall keeps the
// finding of statements the PowerShell reading can read when another statement
// of the call cannot be read (rel-1-0-10:GAP-0367). The attack is the atomic
// case named below (two statements that hijack a UAC auto-elevation handler
// together, from windowsAtomicParityPositives); the unreadable statement is a
// subexpression the reader does not model, placed before and after it. Without
// the Windows hook's readings the parse is partial and the multi-statement
// finding is lost, which this test pins as the reason for the twin (the
// script reading off as well: either one recovers the finding).
func TestWindowsHookJudgesTheReadableStatementsOfAPartialPowerShellCall(t *testing.T) {
	const caseName, rule = "UAC event viewer handler chain", "privilege.windows_uac_autoelevation_hijack"
	var positive *windowsAtomicParityCase
	for i := range windowsAtomicParityPositives {
		if windowsAtomicParityPositives[i].name == caseName {
			positive = &windowsAtomicParityPositives[i]
		}
	}
	if positive == nil {
		t.Fatalf("atomic case %q not found", caseName)
	}
	unreadable := "Write-Output $(Get-Date)"
	layouts := map[string]string{
		"before": unreadable + "\n" + positive.command,
		"after":  positive.command + "\n" + unreadable,
	}
	for name, command := range layouts {
		for _, pack := range []string{"default", "strict"} {
			input := actionfacts.Input{
				Tool: positive.tool, Command: command, CWD: `C:\repo`, DialectHint: actionfacts.DialectPowerShell,
			}
			t.Run(name+"/"+pack, func(t *testing.T) {
				alone := input
				alone.Command = positive.command
				whole := evaluateDeterministicAction(context.Background(), alone, positive.command, "benchmark-"+pack, pack, false)
				if !slices.Contains(whole.RuleIDs, rule) {
					t.Fatalf("the atomic case alone has no %s: %v", rule, whole.RuleIDs)
				}
				// Without the readings: the Windows hook's readable-statements
				// reading off, and the script reading (actionfacts.
				// HostScriptReadings, whose statement list can find the same
				// rule, rel-1-0-10:GAP-0481) off too.
				var plainFacts actionfacts.Facts
				plain := dispatchTrustedAction(context.Background(), trustedActionRequest{
					Input: input, LegacyText: command, Connector: "benchmark-" + pack, EnforcementCapable: true,
					hostScriptTwinOff: true,
					record:            func(facts actionfacts.Facts, _ []RuleFinding) { plainFacts = facts },
				})
				if plainFacts.Authoritative() {
					t.Fatalf("the unreadable statement left the parse %q: the test no longer pins the partial reading", plainFacts.Parse.Status)
				}
				if slices.ContainsFunc(plain, func(f RuleFinding) bool { return f.RuleID == rule }) {
					t.Fatalf("without the readings the partial call already has %s: %v", rule, FindingStrings(plain))
				}
				got := evaluateDeterministicAction(context.Background(), input, command, "benchmark-"+pack, pack, true)
				if !slices.Contains(got.RuleIDs, rule) || got.Action != whole.Action {
					t.Fatalf("action=%q rules=%v, want %s with %s", got.Action, got.RuleIDs, whole.Action, rule)
				}
			})
		}
	}
}

// TestWindowsReadingTwinRequests pins which calls get the readable-statements
// reading: only a Windows hook's call, only when its reading is partial, never
// a reading itself, and never the other shell (a Git Bash call read as
// PowerShell blocked benign copies, TestR105GAP2304WindowsGitBashHomeDrivePaths).
func TestWindowsReadingTwinRequests(t *testing.T) {
	const unreadable = "Write-Output $(Get-Date)"
	input := actionfacts.Input{
		Tool: "shell", CWD: `C:\repo`, DialectHint: actionfacts.DialectPowerShell,
		Command: "Get-Location\n" + unreadable + "\nGet-Date",
	}
	partial := actionfacts.Analyze(input)
	if partial.Authoritative() || partial.Parse.Dialect != actionfacts.DialectPowerShell {
		t.Fatalf("fixture is not a partial PowerShell reading: %+v", partial.Parse)
	}
	hook := trustedActionRequest{Input: input, windowsDialectReadings: true}
	twins := windowsReadingTwinRequests(hook, partial)
	if len(twins) != 1 {
		t.Fatalf("got %d twins, want the readable-statements one", len(twins))
	}
	twin := twins[0]
	if !twin.readingTwin || twin.windowsDialectReadings || twin.record != nil ||
		twin.Input.DialectHint != actionfacts.DialectPowerShell ||
		strings.Contains(twin.Input.Command, unreadable) || twin.LegacyText != twin.Input.Command {
		t.Fatalf("twin is not a recording-free readable-statements reading: %+v", twin)
	}
	for name, request := range map[string]trustedActionRequest{
		"not a Windows hook call": {Input: input},
		"already a reading":       {Input: input, windowsDialectReadings: true, readingTwin: true},
		"a simple-command pass":   {Input: input, windowsDialectReadings: true, simpleCommandPass: true},
	} {
		if got := windowsReadingTwinRequests(request, partial); len(got) != 0 {
			t.Fatalf("%s got %d twins", name, len(got))
		}
	}
	posix := hook
	posix.Input.DialectHint = actionfacts.DialectPOSIX
	posixPartial := partial
	posixPartial.Parse.Dialect = actionfacts.DialectPOSIX
	if got := windowsReadingTwinRequests(posix, posixPartial); len(got) != 0 {
		t.Fatalf("a POSIX reading got %d twins: the other shell is never read", len(got))
	}
	complete := partial
	complete.Parse.Status = actionfacts.StatusComplete
	if got := windowsReadingTwinRequests(hook, complete); len(got) != 0 {
		t.Fatalf("a complete reading got %d twins", len(got))
	}
}
