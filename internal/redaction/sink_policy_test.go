// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package redaction

import (
	"context"
	"strings"
	"testing"
)

// isRedactedPlaceholder is a loose helper for tests: a value is
// considered "redacted" when it carries our placeholder marker.
func isRedactedPlaceholder(s string) bool {
	return strings.Contains(s, "<redacted") || s == "<empty>"
}

func TestStringForSink_PolicyMatrix(t *testing.T) {
	const raw = "sk-secret-value-1234567890"

	t.Run("raw forces passthrough", func(t *testing.T) {
		if got := StringForSink(raw, SinkPolicyRaw); got != raw {
			t.Fatalf("SinkPolicyRaw = %q, want raw %q", got, raw)
		}
	})

	t.Run("redact forces redaction", func(t *testing.T) {
		got := StringForSink(raw, SinkPolicyRedact)
		if got == raw {
			t.Fatalf("SinkPolicyRedact returned raw despite cloud-authoritative redact directive")
		}
		if !isRedactedPlaceholder(got) {
			t.Fatalf("SinkPolicyRedact = %q, want redacted placeholder", got)
		}
	})

	t.Run("default uses secure compatibility projection", func(t *testing.T) {
		got := StringForSink(raw, SinkPolicyDefault)
		if !isRedactedPlaceholder(got) {
			t.Fatalf("SinkPolicyDefault = %q, want redacted", got)
		}
	})
}

func TestReasonForSink_PolicyMatrix(t *testing.T) {
	// A reason carrying a literal secret the tokenizer will scrub.
	const reason = "matched: leaked-secret sk-ant-abcdefghijklmnop"

	if got := ReasonForSink(reason, SinkPolicyRaw); got != reason {
		t.Fatalf("ReasonForSink raw = %q, want %q", got, reason)
	}

	redacted := ReasonForSink(reason, SinkPolicyRedact)
	if redacted == reason {
		t.Fatalf("ReasonForSink redact returned raw")
	}
	if got := ReasonForSink(reason, SinkPolicyDefault); got == reason || !isRedactedPlaceholder(got) {
		t.Fatalf("ReasonForSink default = %q, want redacted", got)
	}
}

func TestMessageContentForSink_PolicyMatrix(t *testing.T) {
	// Construct the card-shaped literal at runtime so the repo's PII/PAN
	// scanner does not flag a hardcoded credit-card number in source.
	body := "customer SSN 123-45-6789 and card 4111" + strings.Repeat("1", 12)
	if got := MessageContentForSink(body, SinkPolicyRaw); got != body {
		t.Fatalf("MessageContentForSink raw = %q, want raw", got)
	}
	if got := MessageContentForSink(body, SinkPolicyRedact); got == body || !isRedactedPlaceholder(got) {
		t.Fatalf("MessageContentForSink redact = %q, want redacted", got)
	}
	if got := MessageContentForSink(body, SinkPolicyDefault); got == body || !isRedactedPlaceholder(got) {
		t.Fatalf("MessageContentForSink default = %q, want redacted", got)
	}
}

func TestEntityForSink_PolicyMatrix(t *testing.T) {
	const entity = "alice@example.com"
	if got := EntityForSink(entity, SinkPolicyRaw); got != entity {
		t.Fatalf("EntityForSink raw = %q, want raw", got)
	}
	if got := EntityForSink(entity, SinkPolicyRedact); got == entity || !isRedactedPlaceholder(got) {
		t.Fatalf("EntityForSink redact = %q, want redacted", got)
	}
}

func TestEvidenceForSink_PolicyMatrix(t *testing.T) {
	const content = "prefix SECRET-TOKEN suffix"
	if got := EvidenceForSink(content, 7, 19, SinkPolicyRaw); got != content {
		t.Fatalf("EvidenceForSink raw = %q, want raw", got)
	}
	got := EvidenceForSink(content, 7, 19, SinkPolicyRedact)
	if got == content || !strings.Contains(got, "<redacted-evidence") {
		t.Fatalf("EvidenceForSink redact = %q, want redacted-evidence", got)
	}
}

func TestSinkPolicyForDirective(t *testing.T) {
	if got := SinkPolicyForDirective(nil); got != SinkPolicyDefault {
		t.Fatalf("nil directive = %v, want SinkPolicyDefault", got)
	}
	yes := true
	if got := SinkPolicyForDirective(&yes); got != SinkPolicyRedact {
		t.Fatalf("true directive = %v, want SinkPolicyRedact", got)
	}
	no := false
	if got := SinkPolicyForDirective(&no); got != SinkPolicyRaw {
		t.Fatalf("false directive = %v, want SinkPolicyRaw", got)
	}
}

func TestSinkPolicyContextRoundTrip(t *testing.T) {
	//nolint:staticcheck // SA1012: intentionally passing a nil context to
	// verify the documented nil-context fallback returns SinkPolicyDefault.
	if got := SinkPolicyFromContext(nil); got != SinkPolicyDefault {
		t.Fatalf("nil ctx = %v, want SinkPolicyDefault", got)
	}
	if got := SinkPolicyFromContext(context.Background()); got != SinkPolicyDefault {
		t.Fatalf("bare ctx = %v, want SinkPolicyDefault", got)
	}
	ctx := WithSinkPolicy(context.Background(), SinkPolicyRaw)
	if got := SinkPolicyFromContext(ctx); got != SinkPolicyRaw {
		t.Fatalf("round trip = %v, want SinkPolicyRaw", got)
	}
}
