// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// rawReason is a verdict reason whose free-form literal the tokenizer
// scrubs by default (the "found:" rule-id prefix is preserved, the
// trailing secret-shaped literal is redacted).
const rawReason = "found: leakedpassword1234567890"

func lastVerdictReason(events []gatewaylog.Event) (string, bool) {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].EventType == gatewaylog.EventVerdict && events[i].Verdict != nil {
			return events[i].Verdict.Reason, true
		}
	}
	return "", false
}

func emitTestVerdict(ctx context.Context, directive *bool) {
	emitEvent(ctx, gatewaylog.Event{
		EventType:        gatewaylog.EventVerdict,
		Severity:         gatewaylog.SeverityHigh,
		Direction:        gatewaylog.DirectionPrompt,
		RedactionEnabled: directive,
		Verdict: &gatewaylog.VerdictPayload{
			Stage:  gatewaylog.StageCiscoAID,
			Action: "block",
			Reason: rawReason,
		},
	})
}

func TestEmitEvent_CloudDirectiveControlsReason(t *testing.T) {
	// Baseline redacted form (managed off, DisableAll off) so the test
	// asserts against the real redactor output rather than a guess.
	// DisableAll() also honors the DEFENSECLAW_DISABLE_REDACTION env var,
	// so clear it too — otherwise a CI environment with it set would make
	// baselineRedacted raw and fail before the feature is exercised.
	t.Setenv("DEFENSECLAW_DISABLE_REDACTION", "")
	redaction.SetDisableAll(false)
	baselineRedacted := redaction.ForSinkReason(rawReason)
	if baselineRedacted == rawReason {
		t.Fatalf("test fixture rawReason did not redact by default: %q", rawReason)
	}

	t.Run("managed + directive=false emits raw", func(t *testing.T) {
		events := withCapturedEvents(t)
		SetManagedEnterpriseActive(true)
		t.Cleanup(func() { SetManagedEnterpriseActive(false) })
		redaction.SetDisableAll(false)
		t.Cleanup(func() { redaction.SetDisableAll(false) })

		no := false
		emitTestVerdict(withRedactionDecision(context.Background(), &no), &no)

		got, ok := lastVerdictReason(*events)
		if !ok {
			t.Fatal("no verdict event captured")
		}
		if got != rawReason {
			t.Fatalf("directive=false: got %q, want raw %q", got, rawReason)
		}
	})

	t.Run("managed + directive=true force-redacts even under DisableAll", func(t *testing.T) {
		events := withCapturedEvents(t)
		SetManagedEnterpriseActive(true)
		t.Cleanup(func() { SetManagedEnterpriseActive(false) })
		redaction.SetDisableAll(true)
		t.Cleanup(func() { redaction.SetDisableAll(false) })

		yes := true
		emitTestVerdict(withRedactionDecision(context.Background(), &yes), &yes)

		got, ok := lastVerdictReason(*events)
		if !ok {
			t.Fatal("no verdict event captured")
		}
		if got == rawReason || !strings.Contains(got, "<redacted") {
			t.Fatalf("directive=true under DisableAll: got %q, want redacted", got)
		}
	})

	t.Run("non-managed ignores directive and honors global config", func(t *testing.T) {
		events := withCapturedEvents(t)
		SetManagedEnterpriseActive(false)
		redaction.SetDisableAll(false)
		t.Cleanup(func() { redaction.SetDisableAll(false) })

		// Even with a directive=false, non-managed must NOT go raw.
		no := false
		emitTestVerdict(withRedactionDecision(context.Background(), &no), &no)

		got, ok := lastVerdictReason(*events)
		if !ok {
			t.Fatal("no verdict event captured")
		}
		if got != baselineRedacted {
			t.Fatalf("non-managed: got %q, want baseline redacted %q", got, baselineRedacted)
		}
	})

	t.Run("managed + no directive fails closed (redacts even under DisableAll)", func(t *testing.T) {
		events := withCapturedEvents(t)
		SetManagedEnterpriseActive(true)
		t.Cleanup(func() { SetManagedEnterpriseActive(false) })
		// DisableAll on: a missing/failed cloud directive must still
		// redact in managed mode (fail closed), NOT fall through to raw.
		redaction.SetDisableAll(true)
		t.Cleanup(func() { redaction.SetDisableAll(false) })

		emitTestVerdict(context.Background(), nil)

		got, ok := lastVerdictReason(*events)
		if !ok {
			t.Fatal("no verdict event captured")
		}
		if got == rawReason || !strings.Contains(got, "<redacted") {
			t.Fatalf("managed no-directive under DisableAll: got %q, want redacted (fail closed)", got)
		}
	})
}
