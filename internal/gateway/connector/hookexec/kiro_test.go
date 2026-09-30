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
	"strings"
	"testing"
)

// Kiro runs the native hook binary on Windows. It must answer exactly like
// kiro-hook.sh: no stdout (Kiro adds hook stdout to the agent's context), a
// hook_output deny or block becomes exit 2 with the reason on stderr, and a
// closed failure is exit 2, the only status Kiro honors as a block. Before
// the binary knew Kiro it answered every event, allow included, with exit 2.
func TestKiroNativeHookAnswersLikeKiroHookScript(t *testing.T) {
	const v3Prompt = `{"hook_event_name":"UserPromptSubmit","session_id":"s","cwd":"/work","prompt":"hello"}`
	for _, tc := range []struct {
		name       string
		rt         *stubRT
		failMode   string
		strict     bool
		wantCode   int
		wantStderr string
		// unprefixed: the reason is printed as is, without "defenseclaw: ".
		unprefixed bool
	}{
		{name: "allow", rt: ok(`{"action":"allow"}`), wantCode: 0},
		{name: "allow with hook_output", rt: ok(`{"action":"allow","hook_output":{"decision":"allow"}}`), wantCode: 0},
		{name: "block", rt: ok(`{"action":"block","hook_output":{"decision":"block","reason":"marker rule matched"}}`), wantCode: 2, wantStderr: "defenseclaw: marker rule matched"},
		{name: "deny", rt: ok(`{"hook_output":{"decision":"deny","reason":"marker rule matched"}}`), wantCode: 2, wantStderr: "defenseclaw: marker rule matched"},
		// A reason that names DefenseClaw is not prefixed again (cert kiro:KR-F10).
		{name: "DefenseClaw's own reason", rt: ok(`{"action":"block","hook_output":{"decision":"block","reason":"Blocked by DefenseClaw rule R1: marker"}}`),
			wantCode: 2, wantStderr: "Blocked by DefenseClaw rule R1: marker", unprefixed: true},
		{name: "block without a hook_output is not a veto", rt: ok(`{"action":"block"}`), wantCode: 0},
		{name: "invalid response, fail open", rt: ok(`not json`), failMode: "open", wantCode: 0, wantStderr: "kiro hook error"},
		{name: "invalid response, fail closed", rt: ok(`not json`), failMode: "closed", wantCode: 2, wantStderr: "kiro hook error"},
		{name: "server error, fail open", rt: &stubRT{status: 503, body: "{}"}, failMode: "open", wantCode: 0},
		{name: "server error, fail closed", rt: &stubRT{status: 503, body: "{}"}, failMode: "closed", wantCode: 2},
		{name: "unreachable, strict", rt: &stubRT{err: errors.New("dial tcp: refused")}, strict: true, wantCode: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := run(t, "kiro", tc.rt, func(o *Options) {
				o.Event = ""
				o.Stdin = strings.NewReader(v3Prompt)
				if tc.failMode != "" {
					o.FailMode = tc.failMode
				}
				o.StrictAvailability = tc.strict
			})
			if r.code != tc.wantCode {
				t.Fatalf("exit = %d, want %d (stderr=%q)", r.code, tc.wantCode, r.stderr)
			}
			if r.stdout != "" {
				t.Fatalf("stdout = %q, want empty: Kiro adds hook stdout to the agent's context", r.stdout)
			}
			if tc.unprefixed && strings.Contains(r.stderr, "defenseclaw: ") {
				t.Fatalf("stderr = %q, want DefenseClaw's own reason without a second prefix", r.stderr)
			}
			if tc.wantStderr != "" && !strings.Contains(r.stderr, tc.wantStderr) {
				t.Fatalf("stderr = %q, want it to contain %q", r.stderr, tc.wantStderr)
			}
			if tc.rt.gotReq != nil {
				if got := tc.rt.gotReq.URL.Path; got != "/api/v1/kiro/hook" {
					t.Fatalf("endpoint = %q", got)
				}
				if got := tc.rt.gotReq.Header.Get("X-DefenseClaw-Client"); got != "kiro-hook/1.0" {
					t.Fatalf("client header = %q", got)
				}
				if got := string(tc.rt.gotBody); got != v3Prompt {
					t.Fatalf("body = %q, want the Kiro payload unchanged", got)
				}
			}
		})
	}
}

// An administrator-managed Kiro hook whose runtime cannot be resolved must
// block with exit 2 before contacting anything.
func TestKiroManagedRuntimeFailureBlocks(t *testing.T) {
	rt := ok(`{"action":"allow"}`)
	r := run(t, "kiro", rt, func(o *Options) {
		o.ManagedEnterprise = true
		o.ManagedRuntimeFailure = "enterprise_managed_runtime_state_invalid"
	})
	if r.code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr=%q)", r.code, r.stderr)
	}
	if rt.requests != 0 {
		t.Fatalf("gateway contacted %d times, want 0", rt.requests)
	}
}
