// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	codexClosedDecision = `{"decision":"block","reason":"DefenseClaw hook failed closed"}` + "\n"
	codexClosedPreTool  = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"DefenseClaw hook failed closed"}}` + "\n"
	codexClosedPermit   = `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"DefenseClaw hook failed closed"}}}` + "\n"
)

// A managed Codex hook that fails closed must answer with Codex's own block:
// the Windows launcher turns a bare exit 2 into 0, which Codex reads as allow.
func TestManagedCodexFailClosedAnswersWithCodexBlock(t *testing.T) {
	events := []struct {
		event      string
		wantStdout string
		wantCode   int
	}{
		{"UserPromptSubmit", codexClosedDecision, 0},
		{"PostToolUse", codexClosedDecision, 0},
		{"Stop", codexClosedDecision, 0},
		{"PreToolUse", codexClosedPreTool, 0},
		{"PermissionRequest", codexClosedPermit, 0},
		// No block control: keep the bare exit code.
		{"SessionStart", "", blockExit},
		{"SubagentStart", "", blockExit},
		{"", "", blockExit},
	}
	paths := []struct {
		name   string
		rt     func() *stubRT
		mutate func(t *testing.T, o *Options)
		reason string
	}{
		{
			name: "disabled sentinel",
			rt:   func() *stubRT { return ok(`{"action":"allow"}`) },
			mutate: func(t *testing.T, o *Options) {
				if err := os.WriteFile(filepath.Join(o.Home, ".disabled"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			reason: managedRuntimeDisableSentinelReason,
		},
		{
			name: "runtime state invalid",
			rt:   func() *stubRT { return ok(`{"action":"allow"}`) },
			mutate: func(t *testing.T, o *Options) {
				o.ManagedRuntimeFailure = "enterprise_managed_runtime_state_invalid"
			},
			reason: "enterprise_managed_runtime_state_invalid",
		},
		{
			name:   "transport failure, closed mode",
			rt:     func() *stubRT { return &stubRT{err: errors.New("dial tcp: refused")} },
			mutate: func(t *testing.T, o *Options) { o.FailMode = "closed" },
			reason: "blocking codex tool",
		},
		{
			name:   "unusable gateway answer, closed mode",
			rt:     func() *stubRT { return ok(`not json`) },
			mutate: func(t *testing.T, o *Options) { o.FailMode = "closed" },
			reason: "invalid JSON response",
		},
	}
	for _, path := range paths {
		for _, tc := range events {
			t.Run(path.name+"/"+tc.event, func(t *testing.T) {
				payload := `{}`
				if tc.event != "" {
					payload = `{"hook_event_name":"` + tc.event + `","session_id":"s"}`
				}
				r := run(t, "codex", path.rt(), func(o *Options) {
					o.Event = ""
					o.ManagedEnterprise = true
					o.Token = "target-readable-token"
					o.Stdin = strings.NewReader(payload)
					path.mutate(t, o)
				})
				if r.code != tc.wantCode {
					t.Fatalf("code = %d, want %d; stdout=%q stderr=%q", r.code, tc.wantCode, r.stdout, r.stderr)
				}
				if r.stdout != tc.wantStdout {
					t.Fatalf("stdout = %q, want %q", r.stdout, tc.wantStdout)
				}
				// A managed hook shows the agent one fixed sentence; the
				// reason (path.reason) goes to the durable decision record.
				if strings.TrimSpace(r.stderr) != ManagedHookBlockMessage {
					t.Fatalf("stderr = %q, want only the managed block message", r.stderr)
				}
				if strings.Contains(r.stderr, path.reason) {
					t.Fatalf("stderr = %q carries the internal reason %q", r.stderr, path.reason)
				}
			})
		}
	}
}

func TestManagedCodexFailClosedPrefersExplicitEvent(t *testing.T) {
	r := run(t, "codex", ok(`{"action":"allow"}`), func(o *Options) {
		o.Event = "PreToolUse"
		o.ManagedEnterprise = true
		o.Token = "target-readable-token"
		o.ManagedRuntimeFailure = "enterprise_managed_runtime_state_invalid"
		o.Stdin = strings.NewReader(`{"hook_event_name":"UserPromptSubmit"}`)
	})
	if r.code != 0 || r.stdout != codexClosedPreTool {
		t.Fatalf("code=%d stdout=%q, want PreToolUse deny", r.code, r.stdout)
	}
}

// The open paths and the per-user hook keep their answers.
func TestCodexFailClosedReplyLeavesOtherPathsUnchanged(t *testing.T) {
	t.Run("managed open fail mode still allows", func(t *testing.T) {
		r := run(t, "codex", &stubRT{err: errors.New("dial tcp: refused")}, func(o *Options) {
			o.Event = ""
			o.ManagedEnterprise = true
			o.Token = "target-readable-token"
			o.Stdin = strings.NewReader(`{"hook_event_name":"UserPromptSubmit"}`)
		})
		if r.code != 0 || r.stdout != "" {
			t.Fatalf("code=%d stdout=%q, want a silent allow", r.code, r.stdout)
		}
	})
	t.Run("managed unregistered account follows the open mode", func(t *testing.T) {
		r := run(t, "codex", ok(`{"action":"allow"}`), func(o *Options) {
			o.Event = ""
			o.ManagedEnterprise = true
			o.Token = "target-readable-token"
			o.ManagedRuntimeFailure = ManagedSIDUnregisteredReason
			o.Stdin = strings.NewReader(`{"hook_event_name":"UserPromptSubmit"}`)
		})
		if r.code != 0 || r.stdout != "" {
			t.Fatalf("code=%d stdout=%q, want a silent allow", r.code, r.stdout)
		}
	})
	t.Run("per-user strict hook keeps the bare exit", func(t *testing.T) {
		r := run(t, "codex", &stubRT{err: errors.New("dial tcp: refused")}, func(o *Options) {
			o.Event = "UserPromptSubmit"
			o.StrictAvailability = true
		})
		if r.code != blockExit || r.stdout != "" {
			t.Fatalf("code=%d stdout=%q, want bare exit %d", r.code, r.stdout, blockExit)
		}
	})
	t.Run("claude code keeps the bare exit", func(t *testing.T) {
		r := run(t, "claudecode", ok(`{"action":"allow"}`), func(o *Options) {
			o.Event = ""
			o.ManagedEnterprise = true
			o.Token = "target-readable-token"
			o.ManagedRuntimeFailure = "enterprise_managed_runtime_state_invalid"
			o.Stdin = strings.NewReader(`{"hook_event_name":"UserPromptSubmit"}`)
		})
		if r.code != blockExit || r.stdout != "" {
			t.Fatalf("code=%d stdout=%q, want bare exit %d", r.code, r.stdout, blockExit)
		}
	})
}

// An oversized managed Codex payload is denied with the event's own block,
// recovered from the payload's prefix: a top-level decision does not deny a
// PermissionRequest or PreToolUse. With no event in the prefix it falls back
// to the structured decision.
func TestManagedCodexOversizedAnswersWithCodexBlockForEvent(t *testing.T) {
	big := strings.Repeat("x", 64)
	for _, tc := range []struct {
		name    string
		payload string
		want    string
	}{
		{
			name:    "PermissionRequest",
			payload: `{"hook_event_name":"PermissionRequest","tool_input":"` + big + `"}`,
			want:    `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"DefenseClaw hook payload too large"}}}` + "\n",
		},
		{
			name:    "PreToolUse",
			payload: `{"hook_event_name":"PreToolUse","tool_input":"` + big + `"}`,
			want:    `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"DefenseClaw hook payload too large"}}` + "\n",
		},
		{
			name:    "no event",
			payload: `{"tool_input":"` + big + `"}`,
			want:    `{"decision":"block","reason":"DefenseClaw hook payload too large"}` + "\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, "codex", ok(`{"action":"allow"}`), func(o *Options) {
				o.Event = ""
				o.ManagedEnterprise = true
				o.FailMode = "open"
				token := "authenticated-token"
				o.AuthenticatedManagedToken = &token
				o.MaxBody = 48
				o.Stdin = strings.NewReader(tc.payload)
			})
			if r.rt.requests != 0 {
				t.Fatal("oversized payload reached the gateway")
			}
			if r.code != 0 || r.stdout != tc.want {
				t.Fatalf("code = %d stdout = %q, want 0 and %q", r.code, r.stdout, tc.want)
			}
		})
	}
}

func TestOversizedHookEventReadsThePrefix(t *testing.T) {
	if got := oversizedHookEvent([]byte(`{"session_id":"s","hook_event_name" : "PermissionRequest","tool_input":"…`)); got != "PermissionRequest" {
		t.Fatalf("event = %q", got)
	}
	if got := oversizedHookEvent([]byte(`{"tool_input":"…`)); got != "" {
		t.Fatalf("event = %q, want none", got)
	}
}
