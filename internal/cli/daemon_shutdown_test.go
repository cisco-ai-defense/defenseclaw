// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestRequestGatewayShutdownSendsAuthenticatedRuntimeIdentity(t *testing.T) {
	const token = "shutdown-request-test-token"
	dataDir := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/admin/shutdown" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token ||
			r.Header.Get("X-DefenseClaw-Token") != token ||
			r.Header.Get("X-DefenseClaw-Client") != "daemon-stop" ||
			r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("shutdown headers = %#v", r.Header)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			PID     int    `json:"pid"`
			DataDir string `json:"data_dir"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if body.PID != os.Getpid() || body.DataDir != dataDir {
			t.Errorf("runtime identity = %+v", body)
			http.Error(w, "identity mismatch", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"accepted"}`))
	}))
	defer server.Close()

	host, port := splitHostPortForTest(t, strings.TrimPrefix(server.URL, "http://"))
	cfg := config.DefaultConfig()
	cfg.DataDir = dataDir
	cfg.Gateway.APIBind = host
	cfg.Gateway.APIPort = port
	if err := requestGatewayShutdown(server.Client(), cfg, token, os.Getpid()); err != nil {
		t.Fatal(err)
	}
}

func TestRequestGatewayShutdownRejectsMissingTokenAndFailureResponse(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	if err := requestGatewayShutdown(http.DefaultClient, cfg, "", 1); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("missing-token error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "identity mismatch", http.StatusConflict)
	}))
	defer server.Close()
	host, port := splitHostPortForTest(t, strings.TrimPrefix(server.URL, "http://"))
	cfg.Gateway.APIBind, cfg.Gateway.APIPort = host, port
	if err := requestGatewayShutdown(server.Client(), cfg, "token", os.Getpid()); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("failure response error = %v", err)
	}
}

func TestRequestGatewayShutdownNeverLeaksTokenToForeignListener(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	host, port := splitHostPortForTest(t, strings.TrimPrefix(server.URL, "http://"))
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Gateway.APIBind, cfg.Gateway.APIPort = host, port
	withStartupListenerInspector(t, func(string, int) (int, error) { return 99, nil })
	err := requestGatewayShutdown(server.Client(), cfg, "must-not-leak", 42)
	if err == nil || !strings.Contains(err.Error(), "refusing to send") {
		t.Fatalf("foreign-listener error = %v", err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("foreign listener received %d authenticated request(s)", got)
	}
}

func TestRequestGatewayShutdownNeverSendsTokenOffLoopback(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Gateway.APIBind = "198.51.100.8"
	err := requestGatewayShutdown(http.DefaultClient, cfg, "must-not-leak", os.Getpid())
	if err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("non-loopback shutdown error = %v", err)
	}
}

func TestRequestGatewayShutdownDoesNotFollowRedirects(t *testing.T) {
	var redirectedRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedRequests.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	host, port := splitHostPortForTest(t, strings.TrimPrefix(origin.URL, "http://"))
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Gateway.APIBind, cfg.Gateway.APIPort = host, port
	err := requestGatewayShutdown(origin.Client(), cfg, "must-not-leak", os.Getpid())
	if err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("redirect response error = %v, want 307 rejection", err)
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Fatalf("redirect target received %d authenticated request(s)", got)
	}
}
