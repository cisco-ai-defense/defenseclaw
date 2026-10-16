// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

func TestSandboxRegistrationWithoutGuestRecord(t *testing.T) {
	harness := newSandboxHarness(t)
	runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
	identity := testManagedIdentity()
	identity.Phase = SandboxPhaseReady
	input := SandboxRegistrationWithoutGuestEvent{
		Sandbox: identity, Subject: testManagedSubject(), Reason: SandboxGuestRelayWithoutGuest,
	}
	if err := recorder.RecordSandboxRegistrationWithoutGuest(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	_, record := onlySandboxRecord(t, runtime)
	if record.EventName() != observability.EventName(observability.TelemetryEventSandboxRegistrationWithoutGuest) ||
		record.Bucket() != observability.BucketComplianceActivity || record.Mandatory() || record.Outcome() != "" {
		t.Fatalf("record identity/outcome: %s %s %v %s", record.EventName(), record.Bucket(), record.Mandatory(), record.Outcome())
	}
	assertSandboxFields(t, sandboxBody(t, record), map[string]any{
		"defenseclaw.sandbox.managed.reason":  "relay_without_guest",
		"defenseclaw.sandbox.managed.action":  "alert",
		"defenseclaw.sandbox.registration.id": identity.Managed.RegistrationID,
		"defenseclaw.sandbox.phase":           "ready",
		"user.id":                             "1001",
		"defenseclaw.user.name":               "alice",
	})
	input.Reason = "unknown_reason"
	if err := recorder.RecordSandboxRegistrationWithoutGuest(context.Background(), input); err == nil {
		t.Fatal("unknown reason accepted")
	}
	input.Reason = SandboxGuestRunningWithoutGuest
	input.Sandbox.Managed.RegistrationID = ""
	if err := recorder.RecordSandboxRegistrationWithoutGuest(context.Background(), input); err == nil {
		t.Fatal("missing registration id accepted")
	}
}
