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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestHookRegister_HasBuiltinFactories confirms init() wired up the
// two known connectors without anyone editing the api.go switch
// statement they replace. Plan C1 / S2.4.
func TestHookRegister_HasBuiltinFactories(t *testing.T) {
	for _, name := range []string{"claudecode", "codex"} {
		if _, ok := connectorHookHandlerByName[name]; !ok {
			t.Errorf("expected hook factory for connector %q to be registered", name)
		}
	}
}

// TestRegisterConnectorHookRoutes_DataDriven simulates a registry
// containing a connector that implements HookEndpoint with a custom
// path and a registered factory. The route must end up on the mux
// at the path the connector requested, NOT the legacy hardcoded
// /api/v1/<name>/hook path.
func TestRegisterConnectorHookRoutes_DataDriven(t *testing.T) {
	called := false
	registerHookHandler("test-c1-fixture", func(_ *APIServer) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		}
	})
	t.Cleanup(func() { delete(connectorHookHandlerByName, "test-c1-fixture") })

	reg := connector.NewRegistry()
	reg.RegisterBuiltin(&fakeHookEndpointConnector{name: "test-c1-fixture", path: "/api/v1/test-c1-fixture/hook"})
	a := &APIServer{connectorRegistry: reg}
	mux := http.NewServeMux()
	a.registerConnectorHookRoutes(mux)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test-c1-fixture/hook", nil)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d (factory called=%v)", rec.Code, called)
	}
	if !called {
		t.Fatal("factory's HandlerFunc was never invoked")
	}
}

// fakeHookEndpointConnector is the smallest connector that satisfies
// the HookEndpoint contract for this test. Doesn't implement the
// rest of Connector; the test is allowed to skip those assertions
// because registerConnectorHookRoutes only consults HookEndpoint.
type fakeHookEndpointConnector struct {
	name string
	path string
}

func (f *fakeHookEndpointConnector) Name() string        { return f.name }
func (f *fakeHookEndpointConnector) Description() string { return "test fixture" }
func (f *fakeHookEndpointConnector) ToolInspectionMode() connector.ToolInspectionMode {
	return connector.ToolModeResponseScan
}
func (f *fakeHookEndpointConnector) SubprocessPolicy() connector.SubprocessPolicy {
	return connector.SubprocessNone
}
func (f *fakeHookEndpointConnector) Setup(context.Context, connector.SetupOpts) error    { return nil }
func (f *fakeHookEndpointConnector) Teardown(context.Context, connector.SetupOpts) error { return nil }
func (f *fakeHookEndpointConnector) Authenticate(*http.Request) bool                     { return true }
func (f *fakeHookEndpointConnector) Route(*http.Request, []byte) (*connector.ConnectorSignals, error) {
	return &connector.ConnectorSignals{ConnectorName: f.name}, nil
}
func (f *fakeHookEndpointConnector) SetCredentials(string, string)         {}
func (f *fakeHookEndpointConnector) VerifyClean(connector.SetupOpts) error { return nil }
func (f *fakeHookEndpointConnector) HookAPIPath() string                   { return f.path }
