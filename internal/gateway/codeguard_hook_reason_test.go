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

package gateway

import (
	"strings"
	"testing"
)

// GAP-1954: a CodeGuard alert on a file Claude Code changed showed the
// user "<redacted len=60 sha=...>" instead of what was found.
func TestClaudeCodeCodeGuardNoticeNamesTheRule(t *testing.T) {
	reason := codeGuardHookReason(claudeCodeCodeGuardEventPlace("FileChanged"), []string{"CG-PATH-001"})
	want := "CodeGuard found 1 finding in a file Claude Code changed (rule CG-PATH-001: Potential path traversal)"
	if reason != want {
		t.Fatalf("reason = %q, want %q", reason, want)
	}
	resp := claudeCodeResponseFor(claudeCodeHookRequest{HookEventName: "FileChanged"},
		"alert", "alert", "MEDIUM", reason, []string{"CG-PATH-001"}, "action", false)
	if got := "DefenseClaw observed a MEDIUM Claude Code hook finding: " + want; resp.AdditionalContext != got {
		t.Fatalf("notice = %q, want %q", resp.AdditionalContext, got)
	}

	for _, ok := range []string{
		codeGuardHookReason(codeGuardPlaceClaudeChanged, []string{"CG-CRED-001", "CG-EXEC-001", "CG-CRED-001"}),
		codeGuardHookReason(codeGuardPlaceCodexChanged, []string{"CUSTOM-RULE-1"}),
	} {
		if !trustedCodeGuardHookReason(ok) {
			t.Errorf("trustedCodeGuardHookReason(%q) = false", ok)
		}
	}
	for _, bad := range []string{
		want + " extra",
		"CodeGuard found 1 finding in a file Claude Code changed (rule CG-PATH-001: something else)",
		"CodeGuard found 1 finding in /home/u/secret.txt",
		"CodeGuard found x finding in a file Claude Code changed",
	} {
		if trustedCodeGuardHookReason(bad) {
			t.Errorf("trustedCodeGuardHookReason(%q) = true", bad)
		}
		if strings.Contains(agentDisplayReason(bad, notificationSinkPolicy(nil)), "something else") {
			t.Errorf("untrusted reason %q passed through unredacted", bad)
		}
	}
}
