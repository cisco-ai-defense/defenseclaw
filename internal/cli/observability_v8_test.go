// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability/destinationtest"
)

func TestRecordDestinationTestActivityUsesAuthenticatedLoopbackOnly(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	const token = "gateway-token-must-not-appear"
	want := destinationtest.Activity{
		Phase: "outcome", Destination: "soc", ProbeID: "probe-1",
		Mode: "handshake", Result: "failed", FailureClass: "timeout",
	}
	received := make(chan destinationtest.Activity, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != destinationtest.EndpointPath || request.Method != http.MethodPost {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
			http.NotFound(w, request)
			return
		}
		if request.Header.Get("Authorization") != "Bearer "+token ||
			request.Header.Get("X-DefenseClaw-Client") != "python-cli" ||
			request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected authenticated request headers")
			http.Error(w, "rejected", http.StatusForbidden)
			return
		}
		var activity destinationtest.Activity
		if err := json.NewDecoder(request.Body).Decode(&activity); err != nil {
			t.Errorf("decode activity: %v", err)
			http.Error(w, "rejected", http.StatusBadRequest)
			return
		}
		received <- activity
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	source := fmt.Sprintf("config_version: 8\ndata_dir: %s\ngateway:\n  api_port: %d\n  token: %s\nobservability: {}\n", directory, port, token)
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if err := recordDestinationTestActivity(t.Context(), bytes.NewReader(payload), path, directory); err != nil {
		t.Fatal(err)
	}
	if got := <-received; got != want {
		t.Fatalf("activity = %+v, want %+v", got, want)
	}
}

func TestRecordDestinationTestActivityBoundsRemoteFailure(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	const secret = "server-response-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, secret, http.StatusInternalServerError)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	source := fmt.Sprintf("config_version: 8\ndata_dir: %s\ngateway:\n  api_port: %s\n  token: local-token\nobservability: {}\n", directory, parsed.Port())
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	activity := `{"phase":"attempt","destination":"soc","probe_id":"probe-1","mode":"handshake","result":"attempted"}`
	err = recordDestinationTestActivity(t.Context(), strings.NewReader(activity), path, directory)
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "local-token") {
		t.Fatalf("bounded error = %v", err)
	}
}

func TestDecodeDestinationTestActivityFailsClosed(t *testing.T) {
	valid := `{"phase":"attempt","destination":"soc","probe_id":"probe-1","mode":"handshake","result":"attempted"}`
	if _, err := decodeDestinationTestActivity(strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	invalid := []string{
		``,
		`{}`,
		valid + valid,
		`{"phase":"attempt","destination":"soc","probe_id":"probe-1","mode":"handshake","result":"attempted","secret":"x"}`,
		strings.Repeat(" ", destinationtest.MaxEncodedBytes+1),
	}
	for _, payload := range invalid {
		if _, err := decodeDestinationTestActivity(strings.NewReader(payload)); err == nil {
			t.Fatalf("invalid activity accepted (bytes=%d)", len(payload))
		}
	}
}

func TestRequestTraceCanaryUsesAuthenticatedLoopbackAndReturnsBoundedResult(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	const token = "trace-canary-token-must-not-appear"
	const traceID = "0123456789abcdef0123456789abcdef"
	received := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/telemetry/canary" || request.Method != http.MethodPost {
			t.Errorf("request = %s %s", request.Method, request.URL.Path)
			http.NotFound(w, request)
			return
		}
		if request.Header.Get("Authorization") != "Bearer "+token ||
			request.Header.Get("X-DefenseClaw-Client") != "python-cli" ||
			request.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected authenticated canary request headers")
			http.Error(w, "rejected", http.StatusForbidden)
			return
		}
		var payload struct {
			Destination string `json:"destination"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			t.Errorf("decode canary request: %v", err)
			http.Error(w, "rejected", http.StatusBadRequest)
			return
		}
		received <- payload.Destination
		_ = json.NewEncoder(w).Encode(traceCanaryHelperResult{
			Destination: "galileo", TraceID: traceID, Generation: 7, Acknowledged: true,
		})
	}))
	defer server.Close()

	configPath, dataDir := traceCanaryHelperConfig(t, server.URL, token)
	result, err := requestTraceCanary(
		t.Context(), "galileo", configPath, dataDir, 2*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := <-received; got != "galileo" {
		t.Fatalf("destination = %q", got)
	}
	if result.Destination != "galileo" || result.TraceID != traceID ||
		result.Generation != 7 || !result.Acknowledged || result.FailureClass != "" {
		t.Fatalf("result = %+v", result)
	}
	if strings.Contains(fmt.Sprintf("%+v", result), token) {
		t.Fatal("bounded canary result exposed the gateway token")
	}
}

func TestRunTraceCanaryCommandBoundsRemoteFailureAndResponseBody(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	const token = "local-token-must-not-escape"
	const remoteSecret = "remote-canary-error-must-not-escape"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, remoteSecret, http.StatusBadGateway)
	}))
	defer server.Close()

	configPath, dataDir := traceCanaryHelperConfig(t, server.URL, token)
	var output bytes.Buffer
	err := runTraceCanaryCommand(
		t.Context(), &output, "galileo", configPath, dataDir, 2*time.Second,
	)
	if err == nil || strings.Contains(err.Error(), token) || strings.Contains(err.Error(), remoteSecret) {
		t.Fatalf("bounded helper error = %v", err)
	}
	var result traceCanaryHelperResult
	if decodeErr := json.Unmarshal(output.Bytes(), &result); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if result != (traceCanaryHelperResult{
		Destination: "galileo", FailureClass: "gateway_rejected",
	}) {
		t.Fatalf("failure result = %+v", result)
	}
	if strings.Contains(output.String(), token) || strings.Contains(output.String(), remoteSecret) {
		t.Fatalf("bounded helper output leaked sensitive text: %s", output.String())
	}
}

func TestRequestTraceCanaryRejectsMalformedAcknowledgement(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"destination":"galileo","trace_id":"not-a-trace","generation":1,"acknowledged":true,"unexpected":"private"}`)
	}))
	defer server.Close()
	configPath, dataDir := traceCanaryHelperConfig(t, server.URL, "local-token")

	result, err := requestTraceCanary(
		t.Context(), "galileo", configPath, dataDir, 2*time.Second,
	)
	if err == nil || result.FailureClass != "invalid_response" ||
		strings.Contains(err.Error(), "private") {
		t.Fatalf("result/error = %+v / %v", result, err)
	}
}

func TestRequestTraceCanaryRejectsUnstableDestinationBeforeNetwork(t *testing.T) {
	result, err := requestTraceCanary(
		t.Context(), "Galileo/../../private", "ignored", "ignored", 2*time.Second,
	)
	if err == nil || result.FailureClass != "invalid_request" || result.Destination != "" ||
		strings.Contains(err.Error(), "private") {
		t.Fatalf("result/error = %+v / %v", result, err)
	}
}

func TestRequestTraceCanaryEnforcesExactTimeoutBoundsBeforeConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		timeout      time.Duration
		failureClass string
	}{
		{
			name: "below minimum", timeout: traceCanaryMinimumTimeout - time.Nanosecond,
			failureClass: "invalid_request",
		},
		{
			name: "exact minimum", timeout: traceCanaryMinimumTimeout,
			failureClass: "configuration_unavailable",
		},
		{
			name: "exact maximum", timeout: traceCanaryMaximumTimeout,
			failureClass: "configuration_unavailable",
		},
		{
			name: "above maximum", timeout: traceCanaryMaximumTimeout + time.Nanosecond,
			failureClass: "invalid_request",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := requestTraceCanary(
				t.Context(), "galileo", filepath.Join(t.TempDir(), "missing.yaml"), "", test.timeout,
			)
			if err == nil || result.FailureClass != test.failureClass {
				t.Fatalf("timeout %s result/error = %+v / %v", test.timeout, result, err)
			}
		})
	}
}

func TestObservabilityV8LoopbackDialHostNormalizesSupportedBinds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		bind string
		host string
		ok   bool
	}{
		{name: "default IPv4", bind: "", host: "127.0.0.1", ok: true},
		{name: "IPv4 loopback", bind: "127.0.0.1", host: "127.0.0.1", ok: true},
		{name: "IPv4 loopback range", bind: "127.7.8.9", host: "127.7.8.9", ok: true},
		{name: "localhost", bind: "localhost", host: "127.0.0.1", ok: true},
		{name: "IPv4 wildcard", bind: "0.0.0.0", host: "127.0.0.1", ok: true},
		{name: "IPv6 loopback", bind: "::1", host: "::1", ok: true},
		{name: "bracketed IPv6 loopback", bind: "[::1]", host: "::1", ok: true},
		{name: "IPv6 wildcard", bind: "::", host: "::1", ok: true},
		{name: "bracketed IPv6 wildcard", bind: "[::]", host: "::1", ok: true},
		{name: "private network", bind: "10.0.0.7"},
		{name: "public network", bind: "203.0.113.7"},
		{name: "non-loopback hostname", bind: "gateway.example.test"},
		{name: "host with port", bind: "127.0.0.1:18970"},
		{name: "whitespace is not normalized", bind: " 127.0.0.1 "},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			host, ok := observabilityV8LoopbackDialHost(test.bind)
			if host != test.host || ok != test.ok {
				t.Fatalf("loopback dial host = %q/%t, want %q/%t", host, ok, test.host, test.ok)
			}
		})
	}
}

func TestRequestTraceCanaryNormalizesWildcardBindToIPv4Loopback(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	const token = "wildcard-loopback-token"
	const traceID = "0123456789abcdef0123456789abcdef"
	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			t.Error("wildcard-normalized request omitted gateway authentication")
			http.Error(w, "rejected", http.StatusForbidden)
			return
		}
		received <- struct{}{}
		_ = json.NewEncoder(w).Encode(traceCanaryHelperResult{
			Destination: "galileo", TraceID: traceID, Generation: 3, Acknowledged: true,
		})
	}))
	defer server.Close()

	configPath, dataDir := traceCanaryHelperConfigWithBind(t, server.URL, token, "0.0.0.0")
	result, err := requestTraceCanary(t.Context(), "galileo", configPath, dataDir, 2*time.Second)
	if err != nil || !result.Acknowledged {
		t.Fatalf("wildcard-normalized canary = %+v / %v", result, err)
	}
	select {
	case <-received:
	default:
		t.Fatal("wildcard-normalized canary did not reach IPv4 loopback")
	}
}

func TestRequestTraceCanaryRejectsNonLoopbackBindBeforeNetwork(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		received <- struct{}{}
	}))
	defer server.Close()

	configPath, dataDir := traceCanaryHelperConfigWithBind(t, server.URL, "must-not-send", "10.0.0.7")
	result, err := requestTraceCanary(t.Context(), "galileo", configPath, dataDir, 2*time.Second)
	if err == nil || result.FailureClass != "configuration_unavailable" {
		t.Fatalf("non-loopback canary = %+v / %v", result, err)
	}
	select {
	case <-received:
		t.Fatal("non-loopback configuration reached the network")
	default:
	}
}

func TestRequestTraceCanaryNeverFollowsRedirectOrForwardsBearer(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	const token = "redirect-token-must-stay-at-origin"
	targetRequests := make(chan string, 1)
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		targetRequests <- request.Header.Get("Authorization")
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+token {
			t.Error("origin request omitted gateway authentication")
		}
		http.Redirect(w, request, target.URL+"/capture", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	configPath, dataDir := traceCanaryHelperConfigWithBind(t, origin.URL, token, "127.0.0.1")
	result, err := requestTraceCanary(t.Context(), "galileo", configPath, dataDir, 2*time.Second)
	if err == nil || result.FailureClass != "gateway_rejected" {
		t.Fatalf("redirected canary = %+v / %v", result, err)
	}
	select {
	case authorization := <-targetRequests:
		t.Fatalf("redirect target was contacted with authorization %q", authorization)
	default:
	}
}

func traceCanaryHelperConfig(t *testing.T, serverURL, token string) (string, string) {
	t.Helper()
	return traceCanaryHelperConfigWithBind(t, serverURL, token, "")
}

func traceCanaryHelperConfigWithBind(
	t *testing.T,
	serverURL string,
	token string,
	apiBind string,
) (string, string) {
	t.Helper()
	parsed, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	bindLine := ""
	if apiBind != "" {
		bindLine = fmt.Sprintf("  api_bind: %q\n", apiBind)
	}
	source := fmt.Sprintf(
		"config_version: 8\ndata_dir: %s\ngateway:\n  api_port: %s\n%s  token: %s\nobservability: {}\n",
		directory, parsed.Port(), bindLine, token,
	)
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, directory
}
