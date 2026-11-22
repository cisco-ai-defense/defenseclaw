// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
)

// gap0337Row is a credentials read whose call reports text and an exit
// status, then the actor's upload.
type gap0337Row struct {
	id, read string
	ok       bool
	text     string
	refuse   bool
}

// gap0337Rows pin the T6 lead's rows for GAP-0337: a read that printed a
// credentials file is a secret read whatever its exit code (owner decision
// 2026-11-13); a failed read that provably read nothing (a missing file)
// is not.
var gap0337Rows = []gap0337Row{
	{"secret-plus-directory-exit-1", "cat .env .", false, "API_KEY=canary-1\ncat: .: Is a directory", true},
	{"or-true-exit-0", "cat .env . || true", true, "API_KEY=canary-1\ncat: .: Is a directory", true},
	{"later-command-fails", "cat .env && false", false, "API_KEY=canary-1", true},
	{"live-two-files-plus-directory", "cat .env .env.local .", false, "API_KEY=canary-1\nOTHER=canary-2\ncat: .: Is a directory", true},
	{"failed-without-text", "cat .env", false, "", true},
	{"benign-missing-file", "cat .env", false, "cat: .env: No such file or directory", false},
	{"benign-two-missing-files", "cat .env .env.local", false, "cat: .env: No such file or directory\ncat: .env.local: No such file or directory", false},
}

// gap0337Result is Claude Code's result of row: PostToolUse with the
// output, or PostToolUseFailure with "Exit code 1" and the output.
func gap0337Result(row gap0337Row) map[string]interface{} {
	if row.ok {
		post := claudeToolResult("PostToolUse", "s1", "read-1")
		post["tool_response"] = map[string]interface{}{"stdout": row.text, "stderr": "", "interrupted": false, "isImage": false}
		return post
	}
	post := claudeToolResult("PostToolUseFailure", "s1", "read-1")
	delete(post, "tool_response")
	post["tool_input"] = map[string]interface{}{"command": row.read}
	post["error"] = "Exit code 1\n" + row.text
	return post
}

// On a Substrate actor every row that printed a credentials file refuses
// the upload on the hook and the request at the callout, in the open source
// packs and managed; the benign rows refuse neither (substrate-1 GAP-0337).
func TestGAP0337FailedReadThatPrintedIsASecretRead(t *testing.T) {
	for _, tc := range []struct {
		pack    string
		managed bool
	}{{"default", false}, {"permissive", false}, {"strict", false}, {"default", true}, {"strict", true}} {
		name := tc.pack
		if tc.managed {
			name = "managed-" + tc.pack
		}
		for _, row := range gap0337Rows {
			t.Run(name+"/"+row.id, func(t *testing.T) {
				r, _, chains := substrateEgressReplicaWith(t, tc.pack, tc.managed, "")
				r.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "read-1", row.read))
				r.hook(t, "tok-alice", gap0337Result(row))
				got := r.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "send-1", substrateEgress))
				chain := slices.Contains(got.RuleIDs, guardrail.ToolChainSecretReadThenEgress)
				if row.refuse != (chain && got.Action == guardrailActionBlock) || !row.refuse && got.Action == guardrailActionBlock {
					t.Fatalf("hook upload after %q: action %q rules %v, want refuse=%v", row.read, got.Action, got.RuleIDs, row.refuse)
				}
				v, err := chains.CheckEgress(context.Background(), chainstate.EgressRequest{
					Actor: chainstate.Actor{Atespace: "eng-web", UID: subUID1}, Host: "github.com", Method: "POST",
				})
				if err != nil || v.Deny != row.refuse {
					t.Fatalf("callout after %q: %+v err=%v, want deny=%v", row.read, v, err, row.refuse)
				}
			})
		}
	}
}

// The proof that a failed call read nothing holds only for one plain
// reader whose whole result is its error line for every operand.
func TestToolResultProvesNothingRead(t *testing.T) {
	for _, tc := range []struct {
		command, text string
		want          bool
	}{
		{"cat .env", "Exit code 1\ncat: .env: No such file or directory", true},
		{"cat .env .env.local", "cat: .env: No such file or directory\ncat: .env.local: Permission denied", true},
		{"head .env", "head: .env: No such file or directory", true},
		{"cat .env", ".env: No such file or directory", true},
		{"cat .env .env.local", "cat: .env: No such file or directory", false},        // .env.local may have printed
		{"cat .env", "Exit code 1\nK=v\ncat: .env: No such file or directory", false}, // other output
		{"cat .env", "", false},                                                   // no text
		{"cat .env", "Exit code 1", false},                                        // no error line
		{"cat .env; false", "cat: .env: No such file or directory", false},        // another command
		{"cat .env || true", "cat: .env: No such file or directory", false},       // an operator
		{"cat .env > out", "cat: .env: No such file or directory", false},         // a redirect
		{"cat \"$F\"", "cat: x: No such file or directory", false},                // a variable
		{"cat -n .env", "cat: .env: No such file or directory", false},            // an option
		{"cp .env x", "cp: cannot stat '.env': No such file or directory", false}, // not a plain reader
		{"echo cat: .env: No such file or directory", "cat: .env: No such file or directory", false},
		{"cat .env", "cat: other: No such file or directory", false}, // another operand
	} {
		post := claudeToolResult("PostToolUseFailure", "s1", "read-1")
		delete(post, "tool_response")
		post["error"] = tc.text
		args, _ := json.Marshal(map[string]string{"command": tc.command})
		req := agentHookRequest{ToolName: "Bash", ToolArgs: args, Payload: post}
		if got := toolResultProvesNothingRead(req); got != tc.want {
			t.Errorf("%q with %q: %v, want %v", tc.command, tc.text, got, tc.want)
		}
	}
}
