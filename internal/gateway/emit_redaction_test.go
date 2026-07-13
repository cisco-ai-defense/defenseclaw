// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// rawReason is a verdict reason whose free-form literal the tokenizer scrubs
// by default (the "found:" rule-id prefix is preserved while the trailing
// secret-shaped literal is redacted).
const rawReason = "found: leakedpassword1234567890"

func projectReasonFromContext(ctx context.Context) string {
	return redaction.ReasonForSink(rawReason, redaction.SinkPolicyFromContext(ctx))
}

func TestManagedRedactionDecision_PropagatesCanonicalSinkPolicy(t *testing.T) {
	t.Cleanup(func() {
		SetManagedEnterpriseActive(false)
	})

	baselineRedacted := redaction.ForSinkReason(rawReason)
	if baselineRedacted == rawReason {
		t.Fatalf("test fixture rawReason did not redact by default: %q", rawReason)
	}

	t.Run("managed directive false selects raw", func(t *testing.T) {
		SetManagedEnterpriseActive(true)
		no := false
		ctx := withRedactionDecision(context.Background(), &no)
		if policy := redaction.SinkPolicyFromContext(ctx); policy != redaction.SinkPolicyRaw {
			t.Fatalf("policy = %v, want raw", policy)
		}
		if got := projectReasonFromContext(ctx); got != rawReason {
			t.Fatalf("projected reason = %q, want raw %q", got, rawReason)
		}
	})

	t.Run("managed directive true forces redaction", func(t *testing.T) {
		SetManagedEnterpriseActive(true)
		yes := true
		ctx := withRedactionDecision(context.Background(), &yes)
		if policy := redaction.SinkPolicyFromContext(ctx); policy != redaction.SinkPolicyRedact {
			t.Fatalf("policy = %v, want redact", policy)
		}
		got := projectReasonFromContext(ctx)
		if got == rawReason || !strings.Contains(got, "<redacted") {
			t.Fatalf("projected reason = %q, want forced redaction", got)
		}
	})

	t.Run("non-managed ignores cloud directive", func(t *testing.T) {
		SetManagedEnterpriseActive(false)
		no := false
		ctx := withRedactionDecision(context.Background(), &no)
		if policy := redaction.SinkPolicyFromContext(ctx); policy != redaction.SinkPolicyDefault {
			t.Fatalf("policy = %v, want default", policy)
		}
		if got := projectReasonFromContext(ctx); got != baselineRedacted {
			t.Fatalf("projected reason = %q, want %q", got, baselineRedacted)
		}
	})

	t.Run("managed missing directive fails closed", func(t *testing.T) {
		SetManagedEnterpriseActive(true)
		ctx := withRedactionDecision(context.Background(), nil)
		if policy := redaction.SinkPolicyFromContext(ctx); policy != redaction.SinkPolicyRedact {
			t.Fatalf("policy = %v, want redact", policy)
		}
		got := projectReasonFromContext(ctx)
		if got == rawReason || !strings.Contains(got, "<redacted") {
			t.Fatalf("projected reason = %q, want fail-closed redaction", got)
		}
	})
}

func TestManagedEnterpriseRedactionPosture_AgentReasonCarveOut(t *testing.T) {
	t.Cleanup(func() {
		setManagedEnterpriseRedactionPosture(false)
	})

	const reason = "matched: PII-EMAIL:alice@example.com"
	setManagedEnterpriseRedactionPosture(true)
	if !ManagedEnterpriseActive() {
		t.Fatal("managed directive gate was not enabled")
	}
	if got := redaction.ReasonForAgent(reason); got != reason {
		t.Fatalf("managed agent reason = %q, want raw %q", got, reason)
	}
	if got := redaction.ForSinkReason(reason); !strings.Contains(got, "<redacted") {
		t.Fatalf("managed posture changed persistent compatibility redaction: %q", got)
	}

	setManagedEnterpriseRedactionPosture(false)
	if ManagedEnterpriseActive() {
		t.Fatal("non-managed directive gate remained enabled")
	}
	if got := redaction.ReasonForAgent(reason); !strings.Contains(got, "<redacted") {
		t.Fatalf("non-managed agent reason = %q, want redacted", got)
	}
}
