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

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// The 429 a sandbox ingress request gets states the limit that refused that
// binding and bucket: the limiter's configured numbers, the binding's own
// override, the telemetry bucket for telemetry, never the default tool-call
// numbers or a number the limiter did not apply (rel-1-0-6 GAP-0490).
func TestSandboxIngressRefusalStatesTheLimitInForce(t *testing.T) {
	message := func(t *testing.T, rec *httptest.ResponseRecorder) string {
		t.Helper()
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429: %s", rec.Code, rec.Body.String())
		}
		var got struct{ Reason, Message string }
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got.Message
	}
	const hookPath = "/api/v1/claude-code/hook"
	t.Run("configured hook rate", func(t *testing.T) {
		f := newSandboxIngressFixture(t, func(cfg *SandboxIngressConfig) {
			cfg.Limiter = sandboxauth.NewLimiter(sandboxauth.LimiterConfig{HookRPS: 0.001, HookBurst: 1})
		})
		f.do(t, http.MethodPost, hookPath, f.claudeTok, `{}`)
		got := message(t, f.do(t, http.MethodPost, hookPath, f.claudeTok, `{}`))
		if !strings.Contains(got, "tool calls (0.001 a second, a burst of 1)") {
			t.Fatalf("message = %q", got)
		}
	})
	t.Run("binding override rate", func(t *testing.T) {
		f := newSandboxIngressFixture(t)
		if _, err := f.store.Update(f.claude.ID, func(spec *sandboxauth.Spec) error {
			spec.RateLimit = sandboxauth.RateLimit{RequestsPerSecond: 0.001, Burst: 1}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		f.do(t, http.MethodPost, hookPath, f.claudeTok, `{}`)
		got := message(t, f.do(t, http.MethodPost, hookPath, f.claudeTok, `{}`))
		if !strings.Contains(got, "tool calls (0.001 a second, a burst of 1)") || strings.Contains(got, "25 a second") {
			t.Fatalf("message = %q", got)
		}
	})
	t.Run("telemetry rate", func(t *testing.T) {
		f := newSandboxIngressFixture(t, func(cfg *SandboxIngressConfig) {
			cfg.Limiter = sandboxauth.NewLimiter(sandboxauth.LimiterConfig{OTLPRPS: 0.001, OTLPBurst: 1})
		})
		f.do(t, http.MethodPost, "/v1/logs", f.claudeTok, `{}`)
		got := message(t, f.do(t, http.MethodPost, "/v1/logs", f.claudeTok, `{}`))
		if !strings.Contains(got, "telemetry uploads (0.001 a second, a burst of 1)") || strings.Contains(got, "tool calls") {
			t.Fatalf("message = %q", got)
		}
	})
	t.Run("binding override concurrency", func(t *testing.T) {
		f := newSandboxIngressFixture(t)
		if _, err := f.store.Update(f.claude.ID, func(spec *sandboxauth.Spec) error {
			spec.RateLimit = sandboxauth.RateLimit{MaxInFlight: 1}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		st := f.api.sandboxIngressState()
		_, exact := f.api.sandboxIngressMux()
		entered := make(chan struct{}, 1)
		release := make(chan struct{})
		h := f.api.sandboxIngressAuthenticate(st, f.api.sandboxIngressAuthorize(st, exact,
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				entered <- struct{}{}
				<-release
				w.WriteHeader(http.StatusNoContent)
			})))
		send := func() *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, hookPath, strings.NewReader(`{}`))
			req.Header.Set("Authorization", "Bearer "+f.claudeTok)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			return rec
		}
		done := make(chan struct{})
		go func() { defer close(done); send() }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("the first request did not acquire the slot")
		}
		rec := send()
		close(release)
		<-done
		got := message(t, rec)
		if !strings.Contains(got, "waiting for DefenseClaw's answer as it may (1)") || strings.Contains(got, "(475)") {
			t.Fatalf("message = %q", got)
		}
	})
}
