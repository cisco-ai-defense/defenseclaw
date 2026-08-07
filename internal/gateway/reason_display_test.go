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
	if got := agentDisplayReason(trusted); got != trusted {
		t.Fatalf("agent display reason = %q, want trusted metadata", got)
	}
	if got := defaultSinkDisplayReason(trusted); got != trusted {
		t.Fatalf("default sink display reason = %q, want trusted metadata", got)
	}

	untrusted := "matched: TRUST-SAFETY-OVERRIDE:scanner supplied value"
	if got := agentDisplayReason(untrusted); got == untrusted || !strings.Contains(got, "<redacted") {
		t.Fatalf("agent display reason = %q, want scanner title redacted", got)
	}
	if got := defaultSinkDisplayReason(untrusted); got == untrusted || !strings.Contains(got, "<redacted") {
		t.Fatalf("default sink display reason = %q, want scanner title redacted", got)
	}
}
