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
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

func TestTrustedBuiltInMatchReason(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		want   bool
	}{
		{
			name:   "single compiled-in finding",
			reason: "matched: TRUST-SAFETY-OVERRIDE:Safety override attempt",
			want:   true,
		},
		{
			name: "multiple compiled-in findings",
			reason: "matched: TRUST-SAFETY-OVERRIDE:Safety override attempt, " +
				"TRUST-JAILBREAK:Jailbreak attempt",
			want: true,
		},
		{
			name:   "normalized match suffix",
			reason: "matched: TRUST-SAFETY-OVERRIDE:Safety override attempt (obfuscated)",
			want:   true,
		},
		{
			name:   "same rule with scanner-authored title",
			reason: "matched: TRUST-SAFETY-OVERRIDE:not the catalog title",
			want:   false,
		},
		{
			name:   "unknown rule",
			reason: "matched: CUSTOM-RULE:Operator supplied title",
			want:   false,
		},
		{
			name:   "trailing content",
			reason: "matched: TRUST-SAFETY-OVERRIDE:Safety override attempt\nextra",
			want:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := trustedBuiltInMatchReason(test.reason); got != test.want {
				t.Fatalf("trustedBuiltInMatchReason(%q) = %t, want %t", test.reason, got, test.want)
			}
		})
	}
}

func TestNotificationDisplayReasonPreservesOnlyTrustedCatalogMetadata(t *testing.T) {
	trusted := "matched: TRUST-SAFETY-OVERRIDE:Safety override attempt"
	if got := notificationDisplayReason(trusted, redaction.SinkPolicyDefault); got != trusted {
		t.Fatalf("default notification reason = %q, want trusted metadata", got)
	}

	forced := notificationDisplayReason(trusted, redaction.SinkPolicyRedact)
	if forced == trusted || !strings.Contains(forced, "<redacted") {
		t.Fatalf("forced-redact notification reason = %q, want redacted title", forced)
	}

	untrusted := "matched: TRUST-SAFETY-OVERRIDE:scanner supplied value"
	got := notificationDisplayReason(untrusted, redaction.SinkPolicyDefault)
	if got == untrusted || !strings.Contains(got, "<redacted") {
		t.Fatalf("untrusted notification reason = %q, want redacted suffix", got)
	}
	if raw := notificationDisplayReason(untrusted, redaction.SinkPolicyRaw); raw != untrusted {
		t.Fatalf("raw managed notification reason = %q, want %q", raw, untrusted)
	}
}

func TestAgentAndDefaultSinkDisplayReasonUseTrustedMetadataCarveOut(t *testing.T) {
	redaction.SetAgentReasonRedactionDisabled(false)
	t.Cleanup(func() { redaction.SetAgentReasonRedactionDisabled(false) })

	trusted := "matched: TRUST-SAFETY-OVERRIDE:Safety override attempt"
	if got := agentDisplayReason(trusted, redaction.SinkPolicyDefault); got != trusted {
		t.Fatalf("agent display reason = %q, want trusted metadata", got)
	}
	if got := defaultSinkDisplayReason(trusted, redaction.SinkPolicyDefault); got != trusted {
		t.Fatalf("default sink display reason = %q, want trusted metadata", got)
	}
	for name, got := range map[string]string{
		"agent":   agentDisplayReason(trusted, redaction.SinkPolicyRedact),
		"default": defaultSinkDisplayReason(trusted, redaction.SinkPolicyRedact),
	} {
		if got == trusted || !strings.Contains(got, "<redacted") {
			t.Fatalf("forced-redact %s reason = %q, want trusted title redacted", name, got)
		}
	}

	untrusted := "matched: TRUST-SAFETY-OVERRIDE:scanner supplied value"
	if got := agentDisplayReason(untrusted, redaction.SinkPolicyDefault); got == untrusted || !strings.Contains(got, "<redacted") {
		t.Fatalf("agent display reason = %q, want scanner title redacted", got)
	}
	if got := defaultSinkDisplayReason(untrusted, redaction.SinkPolicyDefault); got == untrusted || !strings.Contains(got, "<redacted") {
		t.Fatalf("default sink display reason = %q, want scanner title redacted", got)
	}
	if got := agentDisplayReason(untrusted, redaction.SinkPolicyRaw); got != untrusted {
		t.Fatalf("raw agent display reason = %q, want %q", got, untrusted)
	}
	if got := defaultSinkDisplayReason(untrusted, redaction.SinkPolicyRaw); got != untrusted {
		t.Fatalf("raw default sink display reason = %q, want %q", got, untrusted)
	}
}

func TestHookResponseDisplayReasonHonorsManagedRedactionPolicy(t *testing.T) {
	trusted := "matched: TRUST-SAFETY-OVERRIDE:Safety override attempt"
	generic := agentHookResponseFor(
		agentHookRequest{ConnectorName: "cursor", HookEventName: "PreToolUse"},
		"block", "block", "HIGH", trusted, nil, "action", false,
		connector.HookCapability{}, redaction.SinkPolicyRedact,
	)
	codex := codexResponseFor(
		"PreToolUse", "block", "block", "HIGH", trusted, nil, "action", false,
		redaction.SinkPolicyRedact,
	)
	claude := claudeCodeResponseFor(
		claudeCodeHookRequest{HookEventName: "PreToolUse"},
		"block", "block", "HIGH", trusted, nil, "action", false,
		redaction.SinkPolicyRedact,
	)

	tests := []struct {
		name   string
		reason string
		wire   interface{}
	}{
		{name: "generic", reason: generic.Reason, wire: generic},
		{name: "codex", reason: codex.Reason, wire: codex},
		{name: "claude-code", reason: claude.Reason, wire: claude},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !strings.Contains(test.reason, "<redacted") {
				t.Fatalf("managed-redact response reason = %q, want redacted title", test.reason)
			}
			payload, err := json.Marshal(test.wire)
			if err != nil {
				t.Fatalf("marshal response: %v", err)
			}
			if strings.Contains(string(payload), "Safety override attempt") {
				t.Fatalf("managed-redact response leaked trusted title: %s", payload)
			}
		})
	}
}

func TestSanitizeForResponseHonorsManagedRedactionDirective(t *testing.T) {
	previous := ManagedEnterpriseActive()
	SetManagedEnterpriseActive(true)
	t.Cleanup(func() { SetManagedEnterpriseActive(previous) })

	trusted := "matched: TRUST-SAFETY-OVERRIDE:Safety override attempt"
	redact := true
	verdict := &ToolInspectVerdict{Reason: trusted, RedactionEnabled: &redact}
	for _, reveal := range []bool{false, true} {
		got := verdict.sanitizeForResponse(reveal)
		if got.Reason == trusted || !strings.Contains(got.Reason, "<redacted") {
			t.Fatalf("sanitizeForResponse(reveal=%t) reason = %q, want managed redaction", reveal, got.Reason)
		}
	}

	untrusted := "matched: TRUST-SAFETY-OVERRIDE:scanner supplied value"
	raw := false
	got := (&ToolInspectVerdict{Reason: untrusted, RedactionEnabled: &raw}).sanitizeForResponse(false)
	if got.Reason != untrusted {
		t.Fatalf("managed-raw response reason = %q, want %q", got.Reason, untrusted)
	}
}

// GAP-1099: a static block-list verdict reaches the agent as a DefenseClaw
// block naming the tool, not as a fully redacted reason.
func TestAgentVerdictReasonNamesBlockListEntry(t *testing.T) {
	for _, tc := range []struct{ source, want string }{
		{`tool "Write" is on the static block list`, "(tool Write is on the block list)"},
		{`mcp server "github" is blocked`, "(MCP server github is on the block list)"},
	} {
		display := agentDisplayReason(tc.source, redaction.SinkPolicyDefault)
		got := agentVerdictReason("block", tc.source, display, redaction.SinkPolicyDefault)
		if !strings.HasPrefix(got, "DefenseClaw policy blocked this action") || !strings.Contains(got, tc.want) {
			t.Errorf("agentVerdictReason(%q) = %q, want a DefenseClaw block naming %q", tc.source, got, tc.want)
		}
	}
	// Anything outside the exact shape keeps the existing redaction.
	odd := `tool "Write; echo x" is on the static block list`
	display := agentDisplayReason(odd, redaction.SinkPolicyDefault)
	if got := agentVerdictReason("block", odd, display, redaction.SinkPolicyDefault); got != display {
		t.Errorf("unexpected rewrite of a non-matching reason: %q", got)
	}
}

// TestAgentVerdictReasonNamesLLMJudgeKind pins GAP-1564: a judge block names
// DefenseClaw and the judge's kind instead of redaction tokens, and never
// echoes the judge's text or its PII category label.
func TestAgentVerdictReasonNamesLLMJudgeKind(t *testing.T) {
	source := "judge-pii: Password: 1 instance(s) detected; judge-exfil: the prompt writes AKIAIOSFODNN7EXAMPLE to a file"
	display := agentDisplayReason(source, redaction.SinkPolicyDefault)
	got := agentVerdictReason("block", source, display, redaction.SinkPolicyDefault)
	want := "DefenseClaw policy blocked this action (LLM judge: personal data or credentials, possible data exfiltration). " + agentBlockNoRetry
	if got != want {
		t.Fatalf("agentVerdictReason = %q, want %q", got, want)
	}
	if alert := agentVerdictReason("alert", source, display, redaction.SinkPolicyDefault); alert != display {
		t.Errorf("an alert was reworded: %q", alert)
	}
}
