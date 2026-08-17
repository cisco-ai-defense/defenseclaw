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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIBodyLimitMiddlewareUsesLargerBoundOnlyForExactOTLPRoutes(t *testing.T) {
	inner := bodyLimitTestHandler()
	handler := apiBodyLimitMiddleware(inner, apiRequestBodyMaxBytes, otlpRequestBodyMaxBytes)

	for _, path := range []string{
		"/v1/logs",
		"/v1/metrics",
		"/v1/traces",
		"/otlp/codex/path-token/v1/traces",
	} {
		t.Run("accepts above API limit "+path, func(t *testing.T) {
			response := serveBodyLimitRequest(
				handler,
				path,
				apiRequestBodyMaxBytes+1,
			)
			if response.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
			}
		})
	}

	for _, path := range []string{
		"/api/v1/config",
		"/api/x/v1/traces",
		"/v1/traces/not-an-ingest-route",
		"/otlp/codex/path-token/v1/traces/not-an-ingest-route",
	} {
		t.Run("retains API limit "+path, func(t *testing.T) {
			response := serveBodyLimitRequest(
				handler,
				path,
				apiRequestBodyMaxBytes+1,
			)
			if response.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
			}
		})
	}

	t.Run("rejects OTLP above configured bounded limit", func(t *testing.T) {
		const (
			testAPIMaxBytes  = 8
			testOTLPMaxBytes = 16
		)
		boundedHandler := apiBodyLimitMiddleware(inner, testAPIMaxBytes, testOTLPMaxBytes)
		response := serveBodyLimitRequest(
			boundedHandler,
			"/v1/traces",
			testOTLPMaxBytes+1,
		)
		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
		}
	})
}

func TestMaxBodyMiddlewareRemainsUniformForOTLPPaths(t *testing.T) {
	const maxBytes = 8
	handler := maxBodyMiddleware(bodyLimitTestHandler(), maxBytes)
	response := serveBodyLimitRequest(handler, "/v1/traces", maxBytes+1)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestOTLPIngestAcceptsValidBatchesAboveOrdinaryAPILimit(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/logs", api.handleOTLPLogs)
	mux.HandleFunc("/v1/metrics", api.handleOTLPMetrics)
	mux.HandleFunc("/v1/traces", api.handleOTLPTraces)
	handler := apiBodyLimitMiddleware(mux, apiRequestBodyMaxBytes, otlpRequestBodyMaxBytes)

	for _, test := range []struct {
		path     string
		envelope string
	}{
		{path: "/v1/logs", envelope: `{"resourceLogs":[]}`},
		{path: "/v1/metrics", envelope: `{"resourceMetrics":[]}`},
		{path: "/v1/traces", envelope: `{"resourceSpans":[]}`},
	} {
		t.Run(test.path, func(t *testing.T) {
			body := strings.Repeat(" ", int(apiRequestBodyMaxBytes+1)) + test.envelope
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set(otelSourceHeader, "codex")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK || response.Body.String() != "{}" {
				t.Fatalf("response = %d %q, want 200 %q", response.Code, response.Body.String(), "{}")
			}
		})
	}
}

func bodyLimitTestHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			var maxBytesError *http.MaxBytesError
			if errors.As(err, &maxBytesError) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "read request body", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func serveBodyLimitRequest(handler http.Handler, path string, bodyBytes int64) *httptest.ResponseRecorder {
	body := strings.NewReader(strings.Repeat("x", int(bodyBytes)))
	request := httptest.NewRequest(http.MethodPost, path, body)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
