// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// windowsUnreadableStatement is a PowerShell statement the reader does not
// model (a subexpression), so a call that holds it is a partial PowerShell
// reading.
const windowsUnreadableStatement = "Write-Output $(Get-Date)"

// windowsHookShellCall is command as a Windows hook places it: a generic shell
// tool call whose dialect is chosen by the hook's own selection
// (selectWindowsShellDialect), never forced by the test.
func windowsHookShellCall(command, cwd string) actionfacts.Input {
	input := actionfacts.Input{Tool: "shell", Command: command, CWD: cwd}
	input.DialectHint = selectWindowsShellDialect(input.Tool, command, input)
	return input
}

// TestWindowsHookJudgesTheReadableStatementsOfAPartialPowerShellCall keeps the
// finding of statements the PowerShell reading can read when another statement
// of the call cannot be read (rel-1-0-10:GAP-0367), with the dialect the
// Windows hook selects for the call (rel-1-0-10:GAP-0405). The attacks are two
// existing fixtures, loaded by id: the UAC auto-elevation handler chain of the
// tool-call security corpus (two statements that make the finding together)
// and the full NTDS IFM export of the Active Directory conformance pack. The
// unreadable statement is placed before the first and after the second, joined
// by a newline: the hook's selection used to place both calls in no dialect,
// and the readable-statements reading only runs for a call placed in
// PowerShell, so strict went from block to allow.
func TestWindowsHookJudgesTheReadableStatementsOfAPartialPowerShellCall(t *testing.T) {
	type pinned struct {
		id, rule, command, cwd, layout string
	}
	var cases []pinned
	for _, test := range readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl") {
		if test.ID == "windows-uac-eventvwr-autoelevation-hijack" {
			cases = append(cases, pinned{"toolcall/" + test.ID, test.RuleID, test.Command, test.CWD, "before"})
		}
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "benchmarks", "fixtures", "active-directory-conformance-v1.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		var fixture struct {
			ID      string `json:"id"`
			Payload struct {
				Command string `json:"command"`
				CWD     string `json:"cwd"`
			} `json:"payload"`
			Truth struct {
				RuleIDs []string `json:"rule_ids"`
			} `json:"truth"`
		}
		if strings.TrimSpace(line) == "" || json.Unmarshal([]byte(line), &fixture) != nil {
			continue
		}
		if fixture.ID == "ad-v1/ntds-ifm-full" && len(fixture.Truth.RuleIDs) == 1 {
			cases = append(cases, pinned{"ad/" + fixture.ID, fixture.Truth.RuleIDs[0], fixture.Payload.Command, fixture.Payload.CWD, "after"})
		}
	}
	if len(cases) != 2 {
		t.Fatalf("found %d of the 2 pinned fixtures", len(cases))
	}
	for _, test := range cases {
		command := windowsUnreadableStatement + "\n" + test.command
		if test.layout == "after" {
			command = test.command + "\n" + windowsUnreadableStatement
		}
		input := windowsHookShellCall(command, test.cwd)
		t.Run(test.id+"/"+test.layout, func(t *testing.T) {
			for _, pack := range []string{"default", "strict"} {
				alone := windowsHookShellCall(test.command, test.cwd)
				whole := evaluateDeterministicAction(context.Background(), alone, test.command, "benchmark-"+pack, pack, true)
				if !slices.Contains(whole.RuleIDs, test.rule) {
					t.Fatalf("%s: the fixture alone has no %s: %v", pack, test.rule, whole.RuleIDs)
				}
				got := evaluateDeterministicAction(context.Background(), input, command, "benchmark-"+pack, pack, true)
				if !slices.Contains(got.RuleIDs, test.rule) || got.Action != whole.Action {
					t.Fatalf("%s: action=%q rules=%v, want %s with %s", pack, got.Action, got.RuleIDs, whole.Action, test.rule)
				}
			}
			if input.DialectHint != actionfacts.DialectPowerShell {
				t.Fatalf("the hook placed the call in %q, want powershell: its unhinted reading is PowerShell", input.DialectHint)
			}
			if facts := actionfacts.Analyze(input); facts.Authoritative() || facts.Parse.Status != actionfacts.StatusPartial {
				t.Fatalf("the unreadable statement left the parse %q: the test no longer pins a partial reading", facts.Parse.Status)
			}
		})
	}
}

// TestWindowsReadingTwinRequests pins which calls get the readable-statements
// reading: only a Windows hook's call, only when its reading is partial, never
// a reading itself, and never the other shell (a Git Bash call read as
// PowerShell blocked benign copies, TestR105GAP2304WindowsGitBashHomeDrivePaths).
func TestWindowsReadingTwinRequests(t *testing.T) {
	const unreadable = windowsUnreadableStatement
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
