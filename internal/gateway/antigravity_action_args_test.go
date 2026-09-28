// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// liveAntigravityRunCommandCwd is an absolute working directory on the host
// OS, where the live Antigravity CLI reports one (C:\ paths on Windows).
func liveAntigravityRunCommandCwd() string {
	if runtime.GOOS == "windows" {
		return `C:\Users\alice\proj\app`
	}
	return "/home/alice/proj/app"
}

// liveAntigravityRunCommandArgs is the argument shape the Antigravity CLI
// sends, with a harmless marker command.
func liveAntigravityRunCommandArgs(t *testing.T) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"CommandLine":       "echo dc-marker",
		"Cwd":               liveAntigravityRunCommandCwd(),
		"WaitMsBeforeAsync": 5000,
		"toolAction":        "Running echo command",
		"toolSummary":       "Echo marker",
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func antigravityCommandFactsStatus(args json.RawMessage, cwd string) actionfacts.ParseStatus {
	return actionfacts.Analyze(actionfacts.Input{Tool: "run_command", Args: args, CWD: cwd}).Parse.Status
}

func TestAgentHookTrustedActionArgsGivesLiveAntigravityCommandsCompleteFacts(t *testing.T) {
	raw := liveAntigravityRunCommandArgs(t)
	cwd := liveAntigravityRunCommandCwd()
	if status := antigravityCommandFactsStatus(raw, cwd); status == actionfacts.StatusComplete {
		t.Fatalf("fixture must reproduce the incomplete parse of the unprojected arguments, got %s", status)
	}
	projected, dir := agentHookTrustedActionArgs("antigravity", "run_command", raw)
	if dir != cwd {
		t.Fatalf("projected working directory = %q, want the call's Cwd %q", dir, cwd)
	}
	if status := antigravityCommandFactsStatus(projected, dir); status != actionfacts.StatusComplete {
		t.Fatalf("projected Antigravity arguments %s parse as %s, want complete command facts", projected, status)
	}
	facts := actionfacts.Analyze(actionfacts.Input{Tool: "run_command", Args: projected, CWD: dir})
	if len(facts.Commands) != 1 || facts.Commands[0].Program != "echo" {
		t.Fatalf("projected command facts = %+v, want the one echo command", facts.Commands)
	}
}

func TestAgentHookTrustedActionArgsLeavesOtherShapesUnchanged(t *testing.T) {
	live := string(liveAntigravityRunCommandArgs(t))
	for _, tc := range []struct {
		name, connector, tool, args string
	}{
		{"other connector", "codex", "run_command", live},
		{"unknown key", "antigravity", "run_command", `{"CommandLine":"echo dc-marker","toolAction":"a","Extra":"b"}`},
		{"metadata of the wrong type", "antigravity", "run_command", `{"CommandLine":"echo dc-marker","WaitMsBeforeAsync":"soon"}`},
	} {
		got, dir := agentHookTrustedActionArgs(tc.connector, tc.tool, json.RawMessage(tc.args))
		if string(got) != tc.args || dir != "" {
			t.Errorf("%s: arguments changed to %s (working directory %q)", tc.name, got, dir)
		}
	}
	// An unknown key keeps the conservative partial parse.
	unknown, _ := agentHookTrustedActionArgs("antigravity", "run_command",
		json.RawMessage(`{"CommandLine":"echo dc-marker","toolAction":"a","Extra":"b"}`))
	if status := antigravityCommandFactsStatus(unknown, ""); status == actionfacts.StatusComplete {
		t.Fatal("an unreviewed argument must not acquire complete command facts")
	}
}

// Kiro's shell tools as kiro-cli 2.24.1 sends them, with harmless marker
// commands.
func TestAgentHookTrustedActionArgsGivesLiveKiroCommandsCompleteFacts(t *testing.T) {
	for _, tc := range []struct{ name, tool, args string }{
		{"cli 2.x shell", "shell", `{"command":"echo dc-marker","__tool_use_purpose":"Running the exact command as requested"}`},
		{"v3 execute_bash", "execute_bash", `{"command":"echo dc-marker","description":null,"cwd":null,"run_in_background":false,"timeout":null}`},
	} {
		raw := json.RawMessage(tc.args)
		status := func(args json.RawMessage) actionfacts.ParseStatus {
			return actionfacts.Analyze(actionfacts.Input{Tool: "shell", Args: args, CWD: "/Users/dev"}).Parse.Status
		}
		if got := status(raw); got == actionfacts.StatusComplete {
			t.Fatalf("%s: fixture must reproduce the incomplete parse of the arguments as sent, got %s", tc.name, got)
		}
		projected, _ := agentHookTrustedActionArgs("kiro", tc.tool, raw)
		if got := status(projected); got != actionfacts.StatusComplete {
			t.Fatalf("%s: projected arguments %s parse as %s, want complete command facts", tc.name, projected, got)
		}
		// A duplicate key keeps the conservative parse.
		duplicate := json.RawMessage(`{"command":"echo a","command":"echo b","__tool_use_purpose":"x"}`)
		if got, _ := agentHookTrustedActionArgs("kiro", tc.tool, duplicate); string(got) != string(duplicate) {
			t.Fatalf("%s: duplicate-key arguments changed to %s", tc.name, got)
		}
	}
}
