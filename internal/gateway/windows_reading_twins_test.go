// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
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
// finding is lost, which this test pins as the reason for the twin.
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
				plain := evaluateDeterministicAction(context.Background(), input, command, "benchmark-"+pack, pack, false)
				if plain.Authoritative {
					t.Fatalf("the unreadable statement left the parse %q: the test no longer pins the partial reading", plain.ParseStatus)
				}
				if slices.Contains(plain.RuleIDs, rule) {
					t.Fatalf("without the readings the partial call already has %s: %v", rule, plain.RuleIDs)
				}
				got := evaluateDeterministicAction(context.Background(), input, command, "benchmark-"+pack, pack, true)
				if !slices.Contains(got.RuleIDs, rule) || got.Action != whole.Action {
					t.Fatalf("action=%q rules=%v, want %s with %s", got.Action, got.RuleIDs, whole.Action, rule)
				}
			})
		}
	}
}

// TestWindowsReadingTwinRequests pins which calls get the other readings: only
// a Windows hook's call, only when its chosen reading is not complete, never a
// reading itself.
func TestWindowsReadingTwinRequests(t *testing.T) {
	partial := actionfacts.Facts{Parse: actionfacts.ParseResult{
		Status: actionfacts.StatusPartial, Dialect: actionfacts.DialectPowerShell,
	}}
	complete := actionfacts.Facts{Parse: actionfacts.ParseResult{
		Status: actionfacts.StatusComplete, Dialect: actionfacts.DialectPowerShell,
	}}
	hook := trustedActionRequest{windowsDialectReadings: true}
	hints := func(twins []trustedActionRequest) []actionfacts.Dialect {
		var out []actionfacts.Dialect
		for _, twin := range twins {
			if !twin.readingTwin || twin.windowsDialectReadings || twin.record != nil {
				t.Fatalf("a twin must be a recording-free reading that makes no readings: %+v", twin)
			}
			out = append(out, twin.Input.DialectHint)
		}
		return out
	}
	if got := hints(windowsReadingTwinRequests(hook, partial)); !slices.Equal(got, []actionfacts.Dialect{actionfacts.DialectPOSIX}) {
		t.Fatalf("partial PowerShell reading: twin hints %v, want [posix]", got)
	}
	posixPartial := partial
	posixPartial.Parse.Dialect = actionfacts.DialectPOSIX
	if got := hints(windowsReadingTwinRequests(hook, posixPartial)); !slices.Equal(got, []actionfacts.Dialect{actionfacts.DialectPowerShell}) {
		t.Fatalf("partial POSIX reading: twin hints %v, want [powershell]", got)
	}
	for name, request := range map[string]trustedActionRequest{
		"not a Windows hook call": {},
		"already a reading":       {windowsDialectReadings: true, readingTwin: true},
		"a simple-command pass":   {windowsDialectReadings: true, simpleCommandPass: true},
	} {
		if twins := windowsReadingTwinRequests(request, partial); len(twins) != 0 {
			t.Fatalf("%s got %d twins", name, len(twins))
		}
	}
	if twins := windowsReadingTwinRequests(hook, complete); len(twins) != 0 {
		t.Fatalf("a complete reading got %d twins", len(twins))
	}
}
