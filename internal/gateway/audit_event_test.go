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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAuditEventEndpointIgnoresBodySandboxAttribution pins the binding-only
// contract of sandbox attribution: POST /audit/event decodes a whole
// audit.Event, but a sandbox_id or sandbox_name in the body never reaches
// the record.
func TestAuditEventEndpointIgnoresBodySandboxAttribution(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	capture := &nativeSkillRuntimeAuditCapture{}
	logger.SetRuntimeV8Emitter(capture)
	api := &APIServer{health: NewSidecarHealth(), store: store, logger: logger}

	body := `{"action":"gateway-tool-call","target":"shell","actor":"plugin-test","severity":"INFO",` +
		`"sandbox_id":"sbx-forged","sandbox_name":"dc-forged-app"}`
	w := httptest.NewRecorder()
	api.handleAuditEvent(w, httptest.NewRequest(http.MethodPost, "/audit/event", strings.NewReader(body)))
	if w.Code != http.StatusOK || len(capture.records) != 1 {
		t.Fatalf("audit status = %d (%s), records = %d, want one", w.Code, w.Body.String(), len(capture.records))
	}
	encoded, err := capture.records[0].MarshalJSON()
	if err != nil || !bytes.Contains(encoded, []byte("plugin-test")) {
		t.Fatalf("record does not carry the posted event: %s (%v)", encoded, err)
	}
	for _, forged := range []string{"sbx-forged", "dc-forged-app", "sandbox_id", "sandbox_name"} {
		if bytes.Contains(encoded, []byte(forged)) {
			t.Fatalf("a request body set sandbox attribution %q: %s", forged, encoded)
		}
	}
}
