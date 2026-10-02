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

func startStandaloneHookServer(t *testing.T, path string, body string) *recordingServer {
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

func standaloneRun(t *testing.T, socket string, serviceUID int) runResult {
	t.Helper()
	home := t.TempDir()
	var out, errb bytes.Buffer
	opts := Options{
		Connector:          "claudecode",
		Event:              "PreToolUse",
		APIAddr:            "127.0.0.1:18970",
		FailMode:           "closed",
		Home:               home,
		HookDir:            filepath.Join(home, "hooks"),
		Stdin:              strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`),
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
	if result.code == 0 {
		t.Fatalf("impostor listener must fail closed; stdout=%q stderr=%q", result.stdout, result.stderr)
	}
	if !strings.Contains(result.stderr+result.stdout, managedGatewayPeerUnverifiedReason) {
		t.Fatalf("missing peer-unverified reason: stdout=%q stderr=%q", result.stdout, result.stderr)
	}
	if n := sentBytes(); n != 0 {
		t.Fatalf("hook wrote %d bytes to an unverified listener", n)
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
		if code := Run(t.Context(), opts); code == 0 {
			t.Fatalf("injected=%v: a standalone hook without a socket must fail closed; stdout=%q stderr=%q", injected, out.String(), errb.String())
		}
		if !strings.Contains(out.String()+errb.String(), managedGatewayPeerUnverifiedReason) {
			t.Fatalf("injected=%v: missing peer-unverified reason: stdout=%q stderr=%q", injected, out.String(), errb.String())
		}
	}
	if injectedCalls != 0 {
		t.Fatalf("hook sent %d requests through an injected client without a socket", injectedCalls)
	}
	if n := sentBytes(); n != 0 {
		t.Fatalf("hook wrote %d bytes to the loopback TCP port", n)
	}
	// A configured socket path that names no socket fails closed too.
	if result := standaloneRun(t, filepath.Join(shortSocketDir(t), "absent.sock"), os.Getuid()); result.code == 0 {
		t.Fatalf("a missing socket must fail closed; stderr=%q", result.stderr)
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
