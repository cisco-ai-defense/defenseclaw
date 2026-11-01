//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// shortSocketDir returns a directory whose paths fit the 104-byte macOS
// sun_path limit, mode 0700, removed after the test.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "dch")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

type recordingServer struct {
	mu       sync.Mutex
	requests []*http.Request
	server   *http.Server
}

func startStandaloneHookServer(t *testing.T, path string, body string, status ...int) *recordingServer {
	t.Helper()
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &recordingServer{}
	recorder.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.mu.Lock()
		recorder.requests = append(recorder.requests, r.Clone(r.Context()))
		recorder.mu.Unlock()
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		if len(status) != 0 {
			w.WriteHeader(status[0])
		}
		_, _ = io.WriteString(w, body)
	})}
	go func() { _ = recorder.server.Serve(listener) }()
	t.Cleanup(func() { _ = recorder.server.Close() })
	return recorder
}

// rawRecordingListener accepts connections and counts every byte a client
// sends, so a test can prove the hook wrote nothing to an impostor.
func rawRecordingListener(t *testing.T, network, address string) (net.Listener, func() int) {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		total int
	)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, _ := io.Copy(io.Discard, conn)
				mu.Lock()
				total += int(n)
				mu.Unlock()
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return listener, func() int {
		time.Sleep(200 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		return total
	}
}

func standaloneRun(t *testing.T, socket string, serviceUID int, payload ...string) runResult {
	t.Helper()
	home := t.TempDir()
	stdin := `{"hook_event_name":"PreToolUse","tool_name":"Bash"}`
	if len(payload) != 0 {
		stdin = payload[0]
	}
	var out, errb bytes.Buffer
	opts := Options{
		Connector:          "claudecode",
		Event:              "PreToolUse",
		APIAddr:            "127.0.0.1:18970",
		FailMode:           "closed",
		Home:               home,
		HookDir:            filepath.Join(home, "hooks"),
		Stdin:              strings.NewReader(stdin),
		Stdout:             &out,
		Stderr:             &errb,
		ManagedEnterprise:  true,
		StrictAvailability: true,
		ManagedStandalone:  true,
		ManagedUnixSocket:  socket,
		ManagedServiceUID:  serviceUID,
		Token:              "must-not-be-sent",
		Now:                func() time.Time { return time.Unix(0, 0).UTC() },
	}
	code := Run(t.Context(), opts)
	return runResult{stdout: out.String(), stderr: errb.String(), code: code}
}

func TestR103B07ManagedNativeRedirectOnlyDoesNotPanic(t *testing.T) {
	socket := filepath.Join(shortSocketDir(t), "hook.sock")
	server := startStandaloneHookServer(t, socket, `{"action":"allow"}`)
	cwd := t.TempDir()
	payload, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": cwd,
		"tool_input": map[string]string{"command": "> out/build.log"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := standaloneRun(t, socket, os.Getuid(), string(payload))
	if result.code != 0 {
		t.Fatalf("native redirect-only hook exit %d: %s", result.code, result.stderr)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.requests) != 1 {
		t.Fatalf("native hook sent %d requests, want 1", len(server.requests))
	}
	targets, ok := hookpaths.Decode(server.requests[0].Header.Get(hookpaths.Header))
	if !ok {
		t.Fatal("native hook sent no decodable write proof")
	}
	if _, ok := targets[filepath.Join(cwd, "out", "build.log")]; !ok {
		t.Fatalf("redirect-only write missing from native proof: %v", targets)
	}
}

func TestStandaloneUnenrolledAccountGetsEnrollmentDecision(t *testing.T) {
	socket := filepath.Join(shortSocketDir(t), "hook.sock")
	startStandaloneHookServer(t, socket, `{"error":"forbidden","reason":"enterprise_managed_uid_unregistered"}`, http.StatusForbidden)
	result := standaloneRun(t, socket, os.Getuid())
	// GAP-0636, GAP-0738: a structured deny that says the account is not
	// enrolled yet, not "HTTP 403" or the reason code.
	if result.code != 0 || !strings.Contains(result.stdout, "not enrolled in DefenseClaw on this computer yet") ||
		!strings.Contains(result.stdout, `"permissionDecision":"deny"`) ||
		strings.Contains(result.stdout+result.stderr, "HTTP 403") ||
		strings.Contains(result.stdout+result.stderr, "enterprise_managed_uid_unregistered") {
		t.Fatalf("enrollment refusal: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}

// identity-round GAP-1181: an account the policy excludes is not told to
// wait for its enrollment and try again; it is told the policy excludes it.
func TestStandaloneExcludedAccountIsToldThePolicyExcludesIt(t *testing.T) {
	socket := filepath.Join(shortSocketDir(t), "hook.sock")
	startStandaloneHookServer(t, socket, `{"enrollment":"excluded","error":"forbidden","reason":"enterprise_managed_uid_unregistered"}`, http.StatusForbidden)
	result := standaloneRun(t, socket, os.Getuid())
	if result.code != 0 || !strings.Contains(result.stdout, "policy excludes this account on this computer") ||
		!strings.Contains(result.stdout, `"permissionDecision":"deny"`) ||
		strings.Contains(result.stdout, "within about five minutes") || strings.Contains(result.stdout, "try again then") ||
		strings.Contains(result.stdout+result.stderr, "HTTP 403") {
		t.Fatalf("excluded refusal: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}

// GAP-0556: root's call under enrollment.root: deny said "the DefenseClaw
// gateway returned an answer DefenseClaw could not use". It names the policy
// and the code.
func TestStandaloneRootDeniedSaysRootIsNotAllowed(t *testing.T) {
	socket := filepath.Join(shortSocketDir(t), "hook.sock")
	startStandaloneHookServer(t, socket, `{"error":"forbidden","reason":"enterprise_managed_root_denied"}`, http.StatusForbidden)
	result := standaloneRun(t, socket, os.Getuid())
	if result.code != 0 || !strings.Contains(result.stdout, `"permissionDecision":"deny"`) ||
		!strings.Contains(result.stdout, "does not allow agents to run as root") ||
		!strings.Contains(result.stdout, managedRootDeniedReason) ||
		strings.Contains(result.stdout+result.stderr, "could not use") {
		t.Fatalf("root refusal: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}

func TestStandaloneHookSocketTrustedListenerGetsRequestWithoutToken(t *testing.T) {
	dir := shortSocketDir(t)
	socket := filepath.Join(dir, "hook.sock")
	server := startStandaloneHookServer(t, socket, `{"action":"allow"}`)
	result := standaloneRun(t, socket, os.Getuid())
	if result.code != 0 {
		t.Fatalf("trusted gateway: exit %d stderr=%q", result.code, result.stderr)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(server.requests))
	}
	request := server.requests[0]
	if request.Header.Get("Authorization") != "" {
		t.Fatal("standalone socket request must not carry a bearer token")
	}
	if request.URL.Path != "/api/v1/claude-code/hook" {
		t.Fatalf("path = %s", request.URL.Path)
	}
}

func TestStandaloneHookSocketImpostorGetsZeroBytes(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always a trusted listener uid")
	}
	dir := shortSocketDir(t)
	socket := filepath.Join(dir, "hook.sock")
	_, sentBytes := rawRecordingListener(t, "unix", socket)
	// The listener runs as this test's uid; claim the gateway is another account.
	result := standaloneRun(t, socket, os.Getuid()+1)
	if result.code != 0 || !strings.Contains(result.stdout, `"permissionDecision":"deny"`) {
		t.Fatalf("impostor listener must deny through the Claude Code hook: stdout=%q stderr=%q", result.stdout, result.stderr)
	}
	if strings.Contains(result.stderr+result.stdout, managedGatewayPeerUnverifiedReason) {
		t.Fatalf("internal peer reason reached the user: stdout=%q stderr=%q", result.stdout, result.stderr)
	}
	if n := sentBytes(); n != 0 {
		t.Fatalf("hook wrote %d bytes to an unverified listener", n)
	}
}

// GAP-0581: with the gateway service and its socket unit stopped the hook
// socket is gone. The hook fails closed and says the service is stopped,
// instead of sending the user to socket ownership checks. Claude Code gets
// a structured deny, one plain sentence that ends with the documented
// refusal code (GAP-0554, GAP-1179).
func TestStandaloneHookSocketMissingSaysGatewayStopped(t *testing.T) {
	result := standaloneRun(t, filepath.Join(shortSocketDir(t), "hook.sock"), os.Getuid())
	out := result.stdout + result.stderr
	if result.code != 0 || !strings.Contains(result.stdout, `"permissionDecision":"deny"`) ||
		!strings.Contains(out, "gateway service is not running") ||
		strings.Count(out, managedGatewayNotRunningReason) != 1 || strings.Contains(out, "not owned") {
		t.Fatalf("stopped gateway: exit %d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}

func TestStandaloneOpenDistinguishesVerifiedAbsenceFromUntrustedSocket(t *testing.T) {
	dir := shortSocketDir(t)
	socket := filepath.Join(dir, "hook.sock")
	assertClass := func(wantStopped bool) {
		t.Helper()
		_, err := managedStandaloneHTTPClient(time.Second, socket, os.Getuid())
		if err == nil || errors.Is(err, errManagedGatewayNotRunning) != wantStopped {
			t.Fatalf("socket error = %v, want stopped=%t", err, wantStopped)
		}
		wantMode := "closed"
		if wantStopped {
			wantMode = "open"
		}
		if got := managedPeerFailMode(Options{ManagedEnterprise: true, ManagedStandalone: true}, "open", err); got != wantMode {
			t.Fatalf("socket error %v selected %s, want %s", err, got, wantMode)
		}
	}
	assertClass(true)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	assertClass(false)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	client, err := managedStandaloneHTTPClient(time.Second, socket, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Get("http://unix/api/v1/claude-code/hook")
	if err == nil || errors.Is(err, errManagedGatewayNotRunning) {
		t.Fatalf("stale socket error = %v, want unverified peer", err)
	}
}

func TestValidateStandaloneHookSocketPath(t *testing.T) {
	dir := shortSocketDir(t)
	regular := filepath.Join(dir, "file")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateStandaloneHookSocketPath(regular, os.Getuid()); err == nil {
		t.Fatal("a regular file must not be accepted as the hook socket")
	}
	if err := validateStandaloneHookSocketPath("relative.sock", os.Getuid()); err == nil {
		t.Fatal("relative path must be rejected")
	}
	socket := filepath.Join(dir, "hook.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := validateStandaloneHookSocketPath(socket, os.Getuid()); err != nil {
		t.Fatalf("trusted socket rejected: %v", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateStandaloneHookSocketPath(socket, os.Getuid()); err == nil {
		t.Fatal("a world-writable socket directory must be rejected")
	}
	if os.Getuid() != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := validateStandaloneHookSocketPath(socket, os.Getuid()+1); err == nil {
			t.Fatal("a directory owned by neither root nor the service account must be rejected")
		}
	}
}

// A standalone runtime without a hook socket must fail closed. It must not
// fall back to loopback TCP, where another user can hold the port during a
// gateway restart, and it must not read or send a bearer token.
func TestStandaloneWithoutHookSocketNeverUsesTCP(t *testing.T) {
	listener, sentBytes := rawRecordingListener(t, "tcp4", "127.0.0.1:0")
	home := t.TempDir()
	hookDir := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hookDir, ".hook-claudecode.token"), []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	injectedCalls := 0
	for _, injected := range []bool{false, true} {
		var out, errb bytes.Buffer
		opts := Options{
			Connector:          "claudecode",
			Event:              "PreToolUse",
			APIAddr:            listener.Addr().String(),
			FailMode:           "closed",
			Home:               home,
			HookDir:            hookDir,
			Stdin:              strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`),
			Stdout:             &out,
			Stderr:             &errb,
			ManagedEnterprise:  true,
			StrictAvailability: true,
			ManagedStandalone:  true,
			ManagedServiceUID:  os.Getuid(),
			Token:              "must-not-be-sent",
			Now:                func() time.Time { return time.Unix(0, 0).UTC() },
		}
		if injected {
			opts.HTTPClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				injectedCalls++
				return nil, errors.New("unexpected request")
			})}
		}
		if code := Run(t.Context(), opts); code != 0 || !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
			t.Fatalf("injected=%v: a standalone hook without a socket must deny; stdout=%q stderr=%q", injected, out.String(), errb.String())
		}
		if strings.Contains(out.String()+errb.String(), managedGatewayPeerUnverifiedReason) {
			t.Fatalf("injected=%v: internal peer reason reached the user: stdout=%q stderr=%q", injected, out.String(), errb.String())
		}
	}
	if injectedCalls != 0 {
		t.Fatalf("hook sent %d requests through an injected client without a socket", injectedCalls)
	}
	if n := sentBytes(); n != 0 {
		t.Fatalf("hook wrote %d bytes to the loopback TCP port", n)
	}
	// A configured socket path that names no socket fails closed too.
	if result := standaloneRun(t, filepath.Join(shortSocketDir(t), "absent.sock"), os.Getuid()); result.code != 0 ||
		!strings.Contains(result.stdout, `"permissionDecision":"deny"`) {
		t.Fatalf("a missing socket must fail closed; stdout=%q stderr=%q", result.stdout, result.stderr)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestStandaloneTransportRequiresSocketAndServiceUID(t *testing.T) {
	if _, err := managedStandaloneHTTPClient(time.Second, "", 995); !errors.Is(err, errManagedGatewayPeerUnverified) {
		t.Fatalf("empty socket error = %v", err)
	}
	dir := shortSocketDir(t)
	socket := filepath.Join(dir, "hook.sock")
	startStandaloneHookServer(t, socket, `{"action":"allow"}`)
	if _, err := managedStandaloneHTTPClient(time.Second, socket, -1); err == nil {
		t.Fatal("negative service uid must be refused")
	}
	if _, err := managedStandaloneHTTPClient(time.Second, socket, os.Getuid()); err != nil {
		t.Fatalf("trusted socket refused: %v", err)
	}
}

// GAP-2405: a hook socket directory that is not owned by root or the gateway
// account is a peer failure the hook names: the guard's session exchange and
// the native hook both say the directory is the cause, in the words of the
// managed shell hooks.
func TestUntrustedHookSocketDirectoryIsNamed(t *testing.T) {
	dir := shortSocketDir(t)
	socket := filepath.Join(dir, "hook.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	gatewayUID := os.Getuid() + 1 // the directory belongs to this test's account, not the gateway's
	if os.Getuid() == 0 {
		t.Skip("root owns a directory every hook trusts")
	}
	_, err = managedStandaloneHTTPClient(time.Second, socket, gatewayUID)
	if !errors.Is(err, errManagedGatewayPeerUnverified) || !ManagedHookSocketDirectoryUntrusted(err) {
		t.Fatalf("foreign-owned socket directory: %v; want a peer failure that names the directory", err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := managedStandaloneHTTPClient(time.Second, socket, os.Getuid()); !ManagedHookSocketDirectoryUntrusted(err) {
		t.Fatalf("world-writable socket directory: %v; want it named", err)
	}
	if reason := managedPeerFailureReason(Options{ManagedEnterprise: true, ManagedStandalone: true}, err); reason != managedHookSocketDirectoryUntrustedReason {
		t.Fatalf("peer failure reason = %q", reason)
	}
	text, ok := ManagedTransportFailureText("PreToolUse", managedHookSocketDirectoryUntrustedReason)
	if !ok || !strings.Contains(text, "hook socket directory is not owned by root or the gateway account") ||
		strings.Contains(text, managedGatewayPeerUnverifiedReason) || strings.Contains(text, "not available") {
		t.Fatalf("block text = %q", text)
	}
	// A socket that is missing in a trusted directory is still a stopped gateway.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	listener.Close()
	_ = os.Remove(socket)
	if _, err := managedStandaloneHTTPClient(time.Second, socket, os.Getuid()); ManagedHookSocketDirectoryUntrusted(err) || !errors.Is(err, errManagedGatewayNotRunning) {
		t.Fatalf("missing socket in a trusted directory: %v; want the stopped-gateway error", err)
	}
}
