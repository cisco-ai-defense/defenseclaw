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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// rel-1-0-10 REVIEW-4 P1-1: /health names the OpenClaw plugin only after it
// called in, with the hook mode it reported; an unknown mode is dropped.
func TestOpenClawPluginSeenInHealth(t *testing.T) {
	h := NewSidecarHealth()
	if h.Snapshot().OpenClawPlugin != nil {
		t.Fatal("plugin reported before it called in")
	}
	h.RecordOpenClawPluginSeen("hybrid")
	got := h.Snapshot().OpenClawPlugin
	if got == nil || got.HookMode != "hybrid" || got.LastSeenAt == "" {
		t.Fatalf("OpenClawPlugin = %+v", got)
	}
	h.RecordOpenClawPluginSeen("<script>")
	if got := h.Snapshot().OpenClawPlugin; got == nil || got.HookMode != "" {
		t.Fatalf("unknown mode kept: %+v", got)
	}
	raw, _ := json.Marshal(h.Snapshot())
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	if _, ok := doc["openclaw_plugin"]; !ok {
		t.Fatalf("health JSON lacks openclaw_plugin: %s", raw)
	}
}

// rel-1-0-10 REVIEW-4 P2-2: the local operator_admin refusal is a 409 with
// a code, not a 502; allow treats it as done.
func TestOpenClawRemediationRefusalStatus(t *testing.T) {
	a := &APIServer{}
	rec := httptest.NewRecorder()
	a.writeOpenClawRPCError(rec, fmt.Errorf("gateway: skills.update: %w", ErrOpenClawRemediationUnavailable))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["code"] != openClawRemediationUnavailableAction {
		t.Fatalf("body = %v", body)
	}
	rec = httptest.NewRecorder()
	a.writeOpenClawRPCError(rec, errors.New("gateway: not connected"))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if !openClawRemediationSkipped("skill", "s", fmt.Errorf("x: %w", ErrOpenClawRemediationUnavailable)) {
		t.Fatal("allow does not treat the local refusal as done")
	}
	if openClawRemediationSkipped("skill", "s", errors.New("gateway: not connected")) {
		t.Fatal("allow treats an OpenClaw failure as done")
	}
}
