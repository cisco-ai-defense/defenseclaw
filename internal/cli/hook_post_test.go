// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

func TestHookPostCommandUsesConnectedSameAccountSocket(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"hook-post"})
	if err != nil || cmd == rootCmd || cmd.RunE == nil {
		t.Fatalf("hidden native plugin post command is unavailable: %v", err)
	}
	var seen int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/api/v1/amp/hook" || r.Header.Get("Authorization") != "Bearer secret" || string(body) != `{"tool_name":"Bash"}` {
			t.Errorf("unexpected native plugin post: path=%q auth=%q body=%q", r.URL.Path, r.Header.Get("Authorization"), body)
		}
		w.Header().Set("Retry-After", "2")
		_, _ = io.WriteString(w, `{"action":"allow"}`)
	}))
	addr := strings.TrimPrefix(server.URL, "http://")
	input := `{"path":"/api/v1/amp/hook","headers":{"Authorization":"Bearer secret","Content-Type":"application/json"},"body":"{\"tool_name\":\"Bash\"}"}`
	var output bytes.Buffer
	if err := postPerUserHookInput(context.Background(), addr, strings.NewReader(input), &output, false, false); err != nil {
		t.Fatalf("same-account listener rejected: %v", err)
	}
	var reply struct {
		Status     int    `json:"status"`
		Body       string `json:"body"`
		RetryAfter string `json:"retry_after"`
	}
	if err := json.Unmarshal(output.Bytes(), &reply); err != nil || reply.Status != 200 || reply.Body != `{"action":"allow"}` || reply.RetryAfter != "2" || seen != 1 {
		t.Fatalf("native plugin response = %+v, requests=%d, parse error=%v", reply, seen, err)
	}
	output.Reset()
	if err := postPerUserHookInput(context.Background(), addr, strings.NewReader(input), &output, true, false); err != nil ||
		output.String() != "{\"action\":\"allow\"}\n200" || seen != 2 {
		t.Fatalf("native shell response = %q, requests=%d, error=%v", output.String(), seen, err)
	}
	server.Close()
	output.Reset()
	if err := postPerUserHookInput(context.Background(), addr, strings.NewReader(input), &output, false, false); err == nil || seen != 2 || output.Len() != 0 {
		t.Fatalf("stopped gateway was trusted: requests=%d output=%q error=%v", seen, output.String(), err)
	}
	if err := postPerUserHookInput(context.Background(), addr, strings.NewReader(`{"path":"/status"}`), &output, false, false); err == nil {
		t.Fatal("non-hook endpoint was accepted")
	}
}

func TestFramedShellHookInputIsBoundedAndExact(t *testing.T) {
	frame := func(fields ...string) string { return strings.Join(fields, "\x00") }
	for _, tc := range []struct {
		name, input string
		valid       bool
	}{
		{"valid with quoted content", frame("/api/v1/codex/hook", "2", "Authorization", "Bearer example", "X-Trace", `a"b\c`, `{"command":"echo ok"}`), true},
		{"missing body", frame("/api/v1/codex/hook", "1", "Authorization", "Bearer example"), false},
		{"extra field", frame("/api/v1/codex/hook", "0", "{}", "extra"), false},
		{"bad count", frame("/api/v1/codex/hook", "65", "{}"), false},
		{"header injection", frame("/api/v1/codex/hook", "1", "X-Test", "one\r\nEvil: true", "{}"), false},
		{"body with NUL", frame("/api/v1/codex/hook", "0", "{", "}"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, err := readFramedHookInput(strings.NewReader(tc.input))
			if tc.valid != (err == nil) {
				t.Fatalf("read frame: valid=%v error=%v", tc.valid, err)
			}
			if tc.valid && (request.Path != "/api/v1/codex/hook" || request.Headers["Authorization"] != "Bearer example" ||
				request.Headers["X-Trace"] != `a"b\c` || request.Body != `{"command":"echo ok"}`) {
				t.Fatalf("frame changed hook fields: %+v", request)
			}
		})
	}
	_, err := readFramedHookInput(strings.NewReader(strings.Repeat("x", maxPerUserHookInput+1)))
	if err == nil {
		t.Fatal("oversized frame accepted")
	}
	nulFlood := strings.Repeat("\x00", 200_000)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := readFramedHookInput(strings.NewReader(nulFlood)); err == nil {
		t.Fatal("separator flood accepted")
	}
	runtime.ReadMemStats(&after)
	if used := after.TotalAlloc - before.TotalAlloc; used > 2<<20 {
		t.Fatalf("separator flood allocated %d bytes", used)
	}
}

func TestFramedShellPostUsesConnectedPeer(t *testing.T) {
	seen := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen++
		data, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/api/v1/codex/hook" || r.Header.Get("Authorization") != "Bearer example" ||
			string(data) != `{"command":"echo ok"}` {
			t.Errorf("framed request changed: path=%q auth=%q body=%q", r.URL.Path, r.Header.Get("Authorization"), data)
		}
		_, _ = io.WriteString(w, `{"action":"allow"}`)
	}))
	defer server.Close()
	frame := strings.Join([]string{"/api/v1/codex/hook", "1", "Authorization", "Bearer example", `{"command":"echo ok"}`}, "\x00")
	var output bytes.Buffer
	if err := postPerUserHookInput(context.Background(), strings.TrimPrefix(server.URL, "http://"),
		strings.NewReader(frame), &output, true, true); err != nil ||
		output.String() != "{\"action\":\"allow\"}\n200" || seen != 1 {
		t.Fatalf("framed post: output=%q requests=%d error=%v", output.String(), seen, err)
	}
}

func TestSecureClientNativePluginPostRefusesAnUnverifiedListener(t *testing.T) {
	previous := secureClientHost
	secureClientHost = func() bool { return true }
	t.Cleanup(func() { secureClientHost = previous })
	seen := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		seen++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	input := `{"path":"/api/v1/amp/hook","headers":{"Authorization":"Bearer shared-secret"},"body":"private tool event"}`
	var output bytes.Buffer
	err := postSecureClientPluginHook(context.Background(), strings.TrimPrefix(server.URL, "http://"), strings.NewReader(input), &output)
	if err == nil || seen != 0 || output.Len() != 0 {
		t.Fatalf("Secure Client sent a hook to an unverified listener: requests=%d output=%q error=%v", seen, output.String(), err)
	}
}

func TestHookVerifyConnectedCommandProvesTheOpenSocket(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"hook-verify-connected"})
	if err != nil || cmd == rootCmd || cmd.RunE == nil {
		t.Fatalf("hidden connected-socket verifier is unavailable: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer server.Close()
	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	local, remote := conn.LocalAddr().String(), conn.RemoteAddr().String()
	if err := cmd.Flags().Set("local", local); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("remote", remote); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Flags().Set("local", "")
		_ = cmd.Flags().Set("remote", "")
	})
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("same-account connected socket was rejected: %v", err)
	}
	_ = conn.Close()
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("closed client tuple was accepted as a live connected gateway")
	}
}
