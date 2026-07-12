// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

func TestLogCLIActionPreservesCLIOriginAndCanonicalRuntimeOwnership(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	ctx := ContextWithEnvelope(context.Background(), CorrelationEnvelope{RunID: "python-run"})
	if err := logger.LogCLIAction(
		ctx, string(ActionPolicyReload), "default", "owner=alice@example.com",
	); err != nil {
		t.Fatal(err)
	}
	metadata, records := runtime.snapshot()
	if len(metadata) != 1 || len(records) != 1 {
		t.Fatalf("metadata/records=%d/%d", len(metadata), len(records))
	}
	record := records[0]
	if metadata[0].Source() != observability.SourceCLI ||
		record.Source() != observability.SourceCLI ||
		record.Bucket() != observability.BucketComplianceActivity ||
		record.EventName() != observability.EventName(observability.TelemetryEventPolicyUpdated) ||
		record.Correlation().RunID != "python-run" {
		t.Fatalf("metadata=%+v record=%+v", metadata[0], record)
	}
	body := securityActionBody(t, record)
	if body["defenseclaw.admin.origin"] != "cli" ||
		body["defenseclaw.admin.actor_ref"] != "cli" {
		t.Fatalf("CLI body=%#v", body)
	}
	events, err := logger.store.ListEvents(10)
	if err != nil || len(events) != 1 || events[0].RunID != "python-run" {
		t.Fatalf("canonical event history=%#v err=%v", events, err)
	}
}
