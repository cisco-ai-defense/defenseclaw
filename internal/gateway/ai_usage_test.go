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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

func TestHandleAIUsageDisabled(t *testing.T) {
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ai-usage", nil)
	w := httptest.NewRecorder()

	api.handleAIUsage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("disabled response missing: %s", w.Body.String())
	}
}

func TestHandleAIUsageDiscoveryRejectsRawPath(t *testing.T) {
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	api.SetAIDiscoveryService(inventory.NewContinuousDiscoveryServiceWithOptions(
		inventory.AIDiscoveryOptions{Enabled: true, DataDir: t.TempDir(), EmitOTel: false},
		nil,
		nil,
		nil,
	))
	body := `{
	  "summary": {"scan_id":"scan-1"},
	  "signals": [{"category":"ai_cli","state":"new","basenames":["/tmp/raw"]}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ai-usage/discovery", strings.NewReader(body))
	w := httptest.NewRecorder()

	api.handleAIUsageDiscovery(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}
