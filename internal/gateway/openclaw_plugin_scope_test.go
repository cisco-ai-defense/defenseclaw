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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The OpenClaw plugin credential authenticates exactly the calls the plugin
// makes and nothing that loosens policy, writes config.yaml or stops the
// gateway; the master gateway token still reaches every route.
func TestOpenClawPluginCredentialRouteTable(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	plugin, err := connector.EnsureHookAPIToken(dataDir, "openclaw")
	if err != nil || plugin == "" {
		t.Fatalf("mint the openclaw plugin token: %v", err)
	}
	api := instructionProtectionTestAPI(t, "openclaw", "action", "HIGH")
	api.scannerCfg.DataDir = dataDir
	api.scannerCfg.Gateway.Token = "master-token"
	api.connectorRegistry = sharedDefaultRegistry()
	reached := ""
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = r.Method + " " + r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	call := func(method, path, token, remote string) int {
		reached = ""
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		req.RemoteAddr = remote
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		api.tokenAuth(next).ServeHTTP(rec, req)
		return rec.Code
	}
	for path, method := range openClawPluginRoutes {
		if got := call(method, path, plugin, "127.0.0.1:40000"); got != http.StatusNoContent || reached == "" {
			t.Errorf("plugin credential refused on %s %s: %d", method, path, got)
		}
		if got := call(method, path, plugin, "192.0.2.10:40000"); got == http.StatusNoContent {
			t.Errorf("plugin credential accepted from a remote address on %s %s", method, path)
		}
	}
	refused := [][2]string{
		{http.MethodPost, "/enforce/allow"},
		{http.MethodPost, "/enforce/block"},
		{http.MethodDelete, "/enforce/block"},
		{http.MethodDelete, "/enforce/blocked"},
		{http.MethodGet, "/alerts"},
		{http.MethodPost, "/v1/shutdown"},
		{http.MethodPost, "/api/v1/connector/enable"},
		{http.MethodPost, "/v1/provider/reload"},
		{http.MethodPatch, "/v1/guardrail/config"},
	}
	for _, rc := range refused {
		if got := call(rc[0], rc[1], plugin, "127.0.0.1:40000"); got != http.StatusUnauthorized || reached != "" {
			t.Errorf("plugin credential reached %s %s: %d", rc[0], rc[1], got)
		}
		if got := call(rc[0], rc[1], "master-token", "127.0.0.1:40000"); reached == "" {
			t.Errorf("master token did not reach %s %s: %d", rc[0], rc[1], got)
		}
	}
}
