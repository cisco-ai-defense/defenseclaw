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

package tui

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// fetchAIUsage targets http://127.0.0.1:<port> directly, so we can't
// just point it at the httptest.Server URL. spawnLoopbackServer
// binds a real listener on 127.0.0.1 and reports the chosen port so
// the helper sees a fully-qualified loopback target.
func spawnLoopbackServer(t *testing.T, handler http.Handler) (port int, shutdown func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go func() {
		_ = srv.Serve(ln)
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return addr.Port, func() {
		_ = srv.Close()
	}
}

func TestFetchAIUsage_AuthorizationHeaderAndParse(t *testing.T) {
	t.Parallel()
	const wantToken = "test-bearer-xyz"

	var seenAuth string
	port, shutdown := spawnLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/ai-usage" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		seenAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{
			"enabled": true,
			"summary": {
				"scan_id": "s1",
				"total_signals": 2,
				"active_signals": 2,
				"new_signals": 1,
				"privacy_mode": "enhanced",
				"result": "ok"
			},
			"signals": [
				{
					"signal_id": "fp1",
					"signature_id": "claude-code",
					"name": "Claude Code",
					"vendor": "Anthropic",
					"category": "agent_cli",
					"state": "new",
					"confidence": 0.91,
					"first_seen": "2026-01-01T00:00:00Z",
					"last_seen": "2026-01-01T00:00:30Z"
				},
				{
					"signal_id": "fp2",
					"signature_id": "codex-cli",
					"name": "Codex",
					"vendor": "OpenAI",
					"category": "agent_cli",
					"state": "active",
					"confidence": 0.95,
					"first_seen": "2026-01-01T00:00:00Z",
					"last_seen": "2026-01-01T00:00:20Z"
				}
			]
		}`)
	}))
	t.Cleanup(shutdown)

	snap, err := fetchAIUsage(context.Background(), port, wantToken)
	if err != nil {
		t.Fatalf("fetchAIUsage: %v", err)
	}
	if got, want := seenAuth, "Bearer "+wantToken; got != want {
		t.Fatalf("Authorization header = %q, want %q", got, want)
	}
	if !snap.Enabled {
		t.Fatalf("Enabled = false, want true")
	}
	if snap.Summary.ActiveSignals != 2 || snap.Summary.NewSignals != 1 {
		t.Fatalf("summary counts = %+v, want active=2 new=1", snap.Summary)
	}
	if snap.Summary.PrivacyMode != "enhanced" {
		t.Fatalf("PrivacyMode = %q", snap.Summary.PrivacyMode)
	}
	if len(snap.Signals) != 2 {
		t.Fatalf("len(Signals) = %d, want 2", len(snap.Signals))
	}
	if snap.Signals[0].Name != "Claude Code" || snap.Signals[0].State != "new" {
		t.Fatalf("first signal = %+v", snap.Signals[0])
	}
	if snap.FetchedAt.IsZero() {
		t.Fatalf("FetchedAt should be set after a successful fetch")
	}
}

func TestFetchAIUsage_DisabledPayload(t *testing.T) {
	t.Parallel()
	port, shutdown := spawnLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"enabled": false, "summary": {"result": "disabled"}, "signals": []}`)
	}))
	t.Cleanup(shutdown)

	snap, err := fetchAIUsage(context.Background(), port, "anything")
	if err != nil {
		t.Fatalf("fetchAIUsage: %v", err)
	}
	if snap.Enabled {
		t.Fatalf("Enabled = true, want false")
	}
	if len(snap.Signals) != 0 {
		t.Fatalf("expected no signals when disabled, got %d", len(snap.Signals))
	}
}

func TestFetchAIUsage_Unauthorized(t *testing.T) {
	t.Parallel()
	port, shutdown := spawnLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "missing token", http.StatusUnauthorized)
	}))
	t.Cleanup(shutdown)

	_, err := fetchAIUsage(context.Background(), port, "")
	if err == nil {
		t.Fatalf("expected error on 401, got nil")
	}
	// The remediation hint must point at the env var name documented
	// in agent discovery + CLI bootstrap so operators don't have to
	// dig through tokenAuth comments to figure out what to set.
	if !strings.Contains(err.Error(), "DEFENSECLAW_GATEWAY_TOKEN") {
		t.Fatalf("expected DEFENSECLAW_GATEWAY_TOKEN hint, got: %v", err)
	}
}

func TestFetchAIUsage_BadStatus(t *testing.T) {
	t.Parallel()
	port, shutdown := spawnLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(shutdown)

	_, err := fetchAIUsage(context.Background(), port, "token")
	if err == nil {
		t.Fatalf("expected error on 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected 500 in error string, got: %v", err)
	}
}

func TestFetchAIUsage_InvalidPort(t *testing.T) {
	t.Parallel()
	_, err := fetchAIUsage(context.Background(), 0, "token")
	if err == nil {
		t.Fatalf("expected error for port=0, got nil")
	}
}

func TestFetchAIUsage_AcceptHeaderSet(t *testing.T) {
	t.Parallel()
	var seenAccept string
	port, shutdown := spawnLoopbackServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAccept = r.Header.Get("Accept")
		fmt.Fprintln(w, `{"enabled": true, "summary": {}, "signals": []}`)
	}))
	t.Cleanup(shutdown)

	if _, err := fetchAIUsage(context.Background(), port, "t"); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if seenAccept != "application/json" {
		t.Fatalf("Accept = %q, want application/json", seenAccept)
	}
}

// TestFetchAIUsage_UsesHTTPNotHTTPS makes sure the helper continues
// to target the local sidecar over plain HTTP — TLS is intentionally
// not enabled on the loopback API and changing this would silently
// break every existing install. We assert on the URL by spinning up
// an https-only server and confirming the helper *can't* reach it
// (i.e. nobody accidentally upgrades the scheme). Cheap insurance.
func TestFetchAIUsage_UsesHTTPNotHTTPS(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, `{"enabled": true, "summary": {}, "signals": []}`)
	}))
	t.Cleanup(srv.Close)

	// Extract the TLS server port; the helper will hit
	// http://127.0.0.1:<port>/api/v1/ai-usage and the TLS handshake
	// will fail with a protocol mismatch — which is exactly what we
	// want.
	addr := strings.TrimPrefix(srv.URL, "https://")
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	if host != "127.0.0.1" {
		t.Skipf("httptest server bound to %s, expected 127.0.0.1", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	if _, err := fetchAIUsage(context.Background(), port, "t"); err == nil {
		t.Fatalf("expected http→https mismatch error, got success")
	}
}
