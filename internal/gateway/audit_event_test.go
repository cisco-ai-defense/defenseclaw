// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// auditEventRecordCapture keeps every record the logger builds on its way
// through the sidecar-owned runtime.
type auditEventRecordCapture struct {
	*sidecarOwnedObservabilityV8Runtime
	mu      sync.Mutex
	records []observability.Record
}

func (capture *auditEventRecordCapture) EmitRuntimeV8(
	ctx context.Context,
	metadata router.Metadata,
	builder audit.RuntimeV8Builder,
) (audit.RuntimeV8EmitOutcome, error) {
	return capture.sidecarOwnedObservabilityV8Runtime.EmitRuntimeV8(ctx, metadata,
		func(snapshot audit.RuntimeV8BuildContext, admission router.Admission) (observability.Record, error) {
			record, err := builder(snapshot, admission)
			if err == nil {
				capture.mu.Lock()
				capture.records = append(capture.records, record)
				capture.mu.Unlock()
			}
			return record, err
		})
}

func (capture *auditEventRecordCapture) snapshot() []observability.Record {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]observability.Record(nil), capture.records...)
}

// TestAuditEventEndpointIgnoresBodySandboxAttribution pins the binding-only
// contract of sandbox attribution: POST /audit/event decodes a whole
// audit.Event, but a sandbox_id or sandbox_name in the body never reaches
// the record.
func TestAuditEventEndpointIgnoresBodySandboxAttribution(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	fingerprintEngine, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	capture := &auditEventRecordCapture{sidecarOwnedObservabilityV8Runtime: &sidecarOwnedObservabilityV8Runtime{
		runtime: fixture.runtime, redactionEngine: fingerprintEngine,
	}}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(capture)
	t.Cleanup(logger.Close)
	api := &APIServer{health: NewSidecarHealth(), store: fixture.store, logger: logger}

	body := `{"action":"gateway-tool-call","target":"shell","actor":"plugin-test","severity":"INFO",` +
		`"sandbox_id":"sbx-forged","sandbox_name":"dc-forged-app"}`
	w := httptest.NewRecorder()
	api.handleAuditEvent(w, httptest.NewRequest(http.MethodPost, "/audit/event", strings.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("audit status = %d, want %d: %s", w.Code, http.StatusOK, w.Body.String())
	}
	records := capture.snapshot()
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	encoded, err := records[0].MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte("plugin-test")) {
		t.Fatalf("record does not carry the posted event: %s", encoded)
	}
	for _, forged := range []string{"sbx-forged", "dc-forged-app", "sandbox_id", "sandbox_name"} {
		if bytes.Contains(encoded, []byte(forged)) {
			t.Fatalf("a request body set sandbox attribution %q: %s", forged, encoded)
		}
	}
}
