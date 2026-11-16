// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// rel-1-0-2 GAP-0486: a per-user Claude Code hook that fails closed because
// this account's gateway is down answers with the structured block of a
// policy verdict (or a session-start systemMessage), so Claude Code shows
// only DefenseClaw's text and not the hook's command line, whose Windows
// launcher guard holds a "launcher is missing" sentence.
func TestPerUserClaudeCodeGatewayDownShowsOnlyTheText(t *testing.T) {
	shortRestartBudget(t)
	refused := &stubRT{err: fmt.Errorf("dial: %w", syscall.ECONNREFUSED)}
	for _, tc := range []struct {
		name, event, want string
		stopped           bool
		recovery          bool
	}{
		{name: "prompt, gateway down", event: "UserPromptSubmit", want: "this account's DefenseClaw gateway is restarting or not running"},
		{name: "tool call, gateway down", event: "PreToolUse", want: "this account's DefenseClaw gateway is restarting or not running"},
		{name: "session start, gateway down", event: "SessionStart", want: "this account's DefenseClaw gateway is restarting or not running"},
		{name: "prompt, gateway stopped", event: "UserPromptSubmit", recovery: true, stopped: true,
			want: "the DefenseClaw gateway was stopped with `defenseclaw-gateway stop`"},
		{name: "prompt, start failed", event: "UserPromptSubmit", recovery: true,
			want: "the DefenseClaw gateway is not running and could not be started"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := run(t, "claudecode", refused, func(o *Options) {
				o.Event = tc.event
				o.FailMode = "closed"
				o.Stdin = strings.NewReader(`{"hook_event_name":"` + tc.event + `"}`)
				if tc.stopped {
					if err := os.WriteFile(filepath.Join(o.Home, gatewayStoppedMarker), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if tc.recovery {
					o.GatewayRecovery = func(context.Context, error) error {
						return errors.New("hook cold start skipped")
					}
				}
			})
			var body struct {
				Decision      string `json:"decision"`
				Reason        string `json:"reason"`
				SystemMessage string `json:"systemMessage"`
				Hook          struct {
					Decision string `json:"permissionDecision"`
					Reason   string `json:"permissionDecisionReason"`
				} `json:"hookSpecificOutput"`
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(result.stdout)), &body); err != nil || result.code != 0 {
				t.Fatalf("code %d, stdout %q: want a structured answer with exit 0", result.code, result.stdout)
			}
			text := body.Reason
			switch tc.event {
			case "PreToolUse":
				if body.Hook.Decision != "deny" {
					t.Fatalf("stdout %q, want a PreToolUse deny", result.stdout)
				}
				text = body.Hook.Reason
			case "SessionStart":
				text = body.SystemMessage
			default:
				if body.Decision != "block" {
					t.Fatalf("stdout %q, want a prompt block", result.stdout)
				}
			}
			if !strings.HasPrefix(text, "DefenseClaw blocked this ") || !strings.Contains(text, tc.want) {
				t.Fatalf("text %q, want it to name %q", text, tc.want)
			}
		})
	}
}

// rel-1-0-3 GAP-0203: a per-user Claude Code session end (or subagent
// start) whose gateway is down cannot be blocked and has nothing to show:
// it exits 0 with no output, so Claude Code prints no hook command line
// (the Windows launcher guard) after the prompt's block. The failure is
// still logged.
func TestPerUserClaudeCodeGatewayDownQuietForUnblockableEvents(t *testing.T) {
	shortRestartBudget(t)
	refused := &stubRT{err: fmt.Errorf("dial: %w", syscall.ECONNREFUSED)}
	for _, event := range []string{"SessionEnd", "SubagentStart"} {
		for _, recovery := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s cold start=%v", event, recovery), func(t *testing.T) {
				var home string
				result := run(t, "claudecode", refused, func(o *Options) {
					o.Event = event
					o.FailMode = "closed"
					o.Stdin = strings.NewReader(`{"hook_event_name":"` + event + `"}`)
					if recovery {
						o.GatewayRecovery = func(context.Context, error) error {
							return errors.New("hook cold start skipped")
						}
					}
					home = o.Home
				})
				if result.code != 0 || strings.TrimSpace(result.stdout) != "" {
					t.Fatalf("code %d, stdout %q: want exit 0 and no output", result.code, result.stdout)
				}
				if _, err := os.Stat(filepath.Join(home, "logs", "hook-failures.jsonl")); err != nil {
					t.Fatalf("hook failure not logged: %v", err)
				}
			})
		}
	}
}
