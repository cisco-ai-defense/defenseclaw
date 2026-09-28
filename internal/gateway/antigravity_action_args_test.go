// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// liveAntigravityRunCommandArgs is the argument shape the Antigravity CLI
// sends on Windows, with a harmless marker command.
const liveAntigravityRunCommandArgs = `{"CommandLine":"echo dc-marker","Cwd":"C:\\Users\\alice\\proj\\app","WaitMsBeforeAsync":5000,"toolAction":"Running echo command","toolSummary":"Echo marker"}`

func antigravityCommandFactsStatus(t *testing.T, args json.RawMessage) actionfacts.ParseStatus {
	t.Helper()
	facts := actionfacts.Analyze(actionfacts.Input{Tool: "run_command", Args: args, CWD: `C:\Users\alice\proj\app`})
	return facts.Parse.Status
}

func TestAgentHookTrustedActionArgsGivesLiveAntigravityCommandsCompleteFacts(t *testing.T) {
	raw := json.RawMessage(liveAntigravityRunCommandArgs)
	if status := antigravityCommandFactsStatus(t, raw); status == actionfacts.StatusComplete {
		t.Fatalf("fixture must reproduce the incomplete parse of the unprojected arguments, got %s", status)
	}
	projected := agentHookTrustedActionArgs("antigravity", "run_command", raw)
	if status := antigravityCommandFactsStatus(t, projected); status != actionfacts.StatusComplete {
		t.Fatalf("projected Antigravity arguments %s parse as %s, want complete command facts", projected, status)
	}
	facts := actionfacts.Analyze(actionfacts.Input{Tool: "run_command", Args: projected})
	if len(facts.Commands) != 1 || facts.Commands[0].Program != "echo" {
		t.Fatalf("projected command facts = %+v, want the one echo command", facts.Commands)
	}
}

func TestAgentHookTrustedActionArgsLeavesOtherShapesUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name, connector, tool, args string
	}{
		{"other connector", "codex", "run_command", liveAntigravityRunCommandArgs},
		{"unknown key", "antigravity", "run_command", `{"CommandLine":"echo dc-marker","toolAction":"a","Extra":"b"}`},
		{"metadata of the wrong type", "antigravity", "run_command", `{"CommandLine":"echo dc-marker","WaitMsBeforeAsync":"soon"}`},
	} {
		got := agentHookTrustedActionArgs(tc.connector, tc.tool, json.RawMessage(tc.args))
		if string(got) != tc.args {
			t.Errorf("%s: arguments changed to %s", tc.name, got)
		}
	}
	// An unknown key keeps the conservative partial parse.
	unknown := agentHookTrustedActionArgs("antigravity", "run_command",
		json.RawMessage(`{"CommandLine":"echo dc-marker","toolAction":"a","Extra":"b"}`))
	if status := antigravityCommandFactsStatus(t, unknown); status == actionfacts.StatusComplete {
		t.Fatal("an unreviewed argument must not acquire complete command facts")
	}
}
