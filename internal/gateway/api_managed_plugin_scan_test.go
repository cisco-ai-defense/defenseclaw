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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestHandlePluginScanRejectsExactManagedOpenCodeBridge(t *testing.T) {
	configRoot := filepath.Join(t.TempDir(), "opencode")
	t.Setenv("OPENCODE_CONFIG_DIR", configRoot)
	cfg := &config.Config{}
	cfg.Guardrail.Connector = "opencode"
	api := &APIServer{scannerCfg: cfg}
	managed := filepath.Join(configRoot, "plugins", "defenseclaw.js")
	sibling := filepath.Join(configRoot, "plugins", "foreign.js")
	if !api.isManagedPluginScanTarget(managed) {
		t.Fatalf("exact managed bridge was not recognized: %s", managed)
	}
	if api.isManagedPluginScanTarget(sibling) {
		t.Fatalf("managed bridge exemption escaped to sibling: %s", sibling)
	}

	body, err := json.Marshal(skillScanRequest{Target: managed, Name: "defenseclaw"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/plugin/scan", bytes.NewReader(body))
	w := httptest.NewRecorder()
	api.handlePluginScan(w, req)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "lifecycle-owned") {
		t.Fatalf("managed bridge response = %d %q", w.Code, w.Body.String())
	}
}
