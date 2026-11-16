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
	codexClosedSession  = `{"continue":false,"stopReason":"DefenseClaw hook failed closed"}` + "\n"
)

// A Secure Client Codex hook that fails closed answers with Codex's own block
// for its bound event: Codex treats a non-zero exit as "hook failed" and runs
// the prompt or tool unchecked. Its stderr carries only the fixed sentence;
// the reason is in the durable record.
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
		{"SessionStart", codexClosedSession, 0},
		// No bound event: no control schema is guessed; the bare exit stays.
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
				o.ManagedRuntimeFailure = managedRuntimeStateInvalidReason
			},
			reason: managedRuntimeStateInvalidReason,
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
			reason: "invalid or ambiguous JSON response",
		},
	}
	for _, path := range paths {
		for _, tc := range events {
			if tc.event == "" && strings.Contains(path.name, "mode") {
				// Without a bound event the payload is refused before any
				// gateway contact (validateCodexInvocationBinding).
				continue
			}
			t.Run(path.name+"/"+tc.event, func(t *testing.T) {
				records := captureManagedHookDecisions(t)
				payload := `{}`
				if tc.event != "" {
					payload = `{"hook_event_name":"` + tc.event + `","session_id":"s"}`
				}
				r := run(t, "codex", path.rt(), func(o *Options) {
					o.Event = tc.event
					o.ManagedEnterprise = true
					o.SecureClient = true
					token := "authenticated-token"
					o.AuthenticatedManagedToken = &token
					o.Stdin = strings.NewReader(payload)
					path.mutate(t, o)
				})
				if r.code != tc.wantCode {
					t.Fatalf("code = %d, want %d; stdout=%q stderr=%q", r.code, tc.wantCode, r.stdout, r.stderr)
				}
				if r.stdout != tc.wantStdout {
					t.Fatalf("stdout = %q, want %q", r.stdout, tc.wantStdout)
				}
				requireManagedStderr(t, r.stderr, true)
				if len(*records) == 0 {
					t.Fatal("no durable decision record")
				}
			})
		}
	}
}

func TestManagedCodexFailClosedPrefersBoundEvent(t *testing.T) {
	r := run(t, "codex", ok(`{"action":"allow"}`), func(o *Options) {
		o.Event = "PreToolUse"
		o.ManagedEnterprise = true
		o.SecureClient = true
		token := "authenticated-token"
		o.AuthenticatedManagedToken = &token
		o.ManagedRuntimeFailure = managedRuntimeStateInvalidReason
		o.Stdin = strings.NewReader(`{"hook_event_name":"UserPromptSubmit"}`)
	})
	if r.code != 0 || r.stdout != codexClosedPreTool {
		t.Fatalf("code=%d stdout=%q, want PreToolUse deny", r.code, r.stdout)
	}
}

// The open paths keep their answers, and the standalone profile keeps its
// diagnostics.
func TestCodexFailClosedReplyLeavesOtherPathsUnchanged(t *testing.T) {
	t.Run("secure client open fail mode still allows", func(t *testing.T) {
		r := run(t, "codex", &stubRT{err: errors.New("dial tcp: refused")}, func(o *Options) {
			o.Event = "UserPromptSubmit"
			o.ManagedEnterprise = true
			o.SecureClient = true
			token := "authenticated-token"
			o.AuthenticatedManagedToken = &token
			o.Stdin = strings.NewReader(`{"hook_event_name":"UserPromptSubmit"}`)
		})
		if r.code != 0 || r.stdout != "" || r.stderr != "" {
			t.Fatalf("code=%d stdout=%q stderr=%q, want a silent allow", r.code, r.stdout, r.stderr)
		}
	})
	t.Run("secure client unregistered account follows the open mode", func(t *testing.T) {
		r := run(t, "codex", ok(`{"action":"allow"}`), func(o *Options) {
			o.Event = "UserPromptSubmit"
			o.ManagedEnterprise = true
			o.SecureClient = true
			o.ManagedRuntimeFailure = managedSIDUnregisteredReason
			o.Stdin = strings.NewReader(`{"hook_event_name":"UserPromptSubmit"}`)
		})
		if r.code != 0 || r.stdout != "" || r.stderr != "" {
			t.Fatalf("code=%d stdout=%q stderr=%q, want a silent allow", r.code, r.stdout, r.stderr)
		}
	})
	t.Run("standalone hook keeps its diagnostic", func(t *testing.T) {
		r := run(t, "codex", ok(`{"action":"allow"}`), func(o *Options) {
			o.ManagedEnterprise = true
			o.ManagedRuntimeFailure = managedRuntimeStateInvalidReason
		})
		if r.code != 0 || r.stdout != codexClosedPreTool {
			t.Fatalf("code=%d stdout=%q, want PreToolUse deny", r.code, r.stdout)
		}
		if !strings.Contains(r.stderr, managedRuntimeStateInvalidReason) {
			t.Fatalf("stderr = %q, want the standalone diagnostic", r.stderr)
		}
	})
	t.Run("claude code keeps the bare exit", func(t *testing.T) {
		r := run(t, "claudecode", ok(`{"action":"allow"}`), func(o *Options) {
			o.Event = ""
			o.ManagedEnterprise = true
			o.SecureClient = true
			o.ManagedRuntimeFailure = managedRuntimeStateInvalidReason
			o.Stdin = strings.NewReader(`{"hook_event_name":"UserPromptSubmit"}`)
		})
		if r.code != blockExit || r.stdout != "" {
			t.Fatalf("code=%d stdout=%q, want bare exit %d", r.code, r.stdout, blockExit)
		}
	})
}

// An oversized Secure Client Codex payload under a closed fail mode is denied
// with its bound event's own block: a top-level decision does not deny a
// PermissionRequest or PreToolUse. (Under the open fail mode it is allowed;
// see TestSecureClientAvailabilityGapsFollowFailMode.)
func TestManagedCodexOversizedAnswersWithCodexBlockForEvent(t *testing.T) {
	big := strings.Repeat("x", 64)
	for _, tc := range []struct {
		event string
		want  string
	}{
		{
			event: "PermissionRequest",
			want:  `{"hookSpecificOutput":{"hookEventName":"PermissionRequest","decision":{"behavior":"deny","message":"DefenseClaw hook payload too large"}}}` + "\n",
		},
		{
			event: "PreToolUse",
			want:  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"DefenseClaw hook payload too large"}}` + "\n",
		},
		{
			event: "UserPromptSubmit",
			want:  `{"decision":"block","reason":"DefenseClaw hook payload too large"}` + "\n",
		},
	} {
		t.Run(tc.event, func(t *testing.T) {
			r := run(t, "codex", ok(`{"action":"allow"}`), func(o *Options) {
				o.Event = tc.event
				o.ManagedEnterprise = true
				o.SecureClient = true
				o.FailMode = "closed"
				token := "authenticated-token"
				o.AuthenticatedManagedToken = &token
				o.MaxBody = 32
				o.Stdin = strings.NewReader(`{"hook_event_name":"` + tc.event + `","tool_input":"` + big + `"}`)
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
