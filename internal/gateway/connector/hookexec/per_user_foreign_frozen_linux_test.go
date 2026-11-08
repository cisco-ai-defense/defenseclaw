// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestForeignFrozenListenerChild is the helper process of
// startForeignFrozenListener: a listener of another account that accepts
// nothing, until the parent closes its stdin.
func TestForeignFrozenListenerChild(t *testing.T) {
	if os.Getenv("DC_TEST_FOREIGN_FROZEN") != "1" {
		t.Skip("helper process of the foreign frozen listener tests")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	fmt.Printf("FOREIGN_ADDR=%s\n", listener.Addr())
	go func() {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}()
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// startForeignFrozenListener starts a listener of a second local account that
// never accepts, when passwordless sudo can run one, and returns its address.
func startForeignFrozenListener(t *testing.T) string {
	t.Helper()
	if err := exec.Command("sudo", "-n", "-u", "nobody", "true").Run(); err != nil {
		t.Skipf("passwordless second-account execution is unavailable: %v", err)
	}
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/tmp", "defenseclaw-foreign-frozen-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(root, "hookexec.test")
	input, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, input, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, "sudo", "-n", "-u", "nobody", "/usr/bin/env",
		"DC_TEST_FOREIGN_FROZEN=1", copyPath, "-test.run=^TestForeignFrozenListenerChild$")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	reader := bufio.NewScanner(stdout)
	if !reader.Scan() || !strings.HasPrefix(reader.Text(), "FOREIGN_ADDR=") {
		t.Fatalf("second-account listener did not start: %q", reader.Text())
	}
	return strings.TrimPrefix(reader.Text(), "FOREIGN_ADDR=")
}

// A listener of another account that accepts nothing is not this account
// gateway, frozen: the connection stays refused as an unproven peer, in every
// fail mode, and nothing is sent to it.
func TestForeignListenerThatAcceptsNothingStaysUnverified(t *testing.T) {
	shortConnectedWait(t, 300*time.Millisecond)
	addr := startForeignFrozenListener(t)
	_, err := PostPerUserHook(context.Background(), addr, "/api/v1/claude-code/hook",
		map[string]string{"Authorization": "Bearer account-private-token"}, []byte("{}"))
	if err == nil {
		t.Fatal("a listener of another account was accepted")
	}
	if !PerUserPostPeerUnverified(err) || PerUserPostListenerUnanswered(err) || PerUserPostOutage(err) {
		t.Fatalf("a listener of another account that accepts nothing was not refused as unverified: %v", err)
	}
	result := run(t, "claudecode", nil, func(opts *Options) {
		client, cerr := NewPerUserGatewayHTTPClient(2*time.Second, addr)
		if cerr != nil {
			t.Fatal(cerr)
		}
		opts.APIAddr = addr
		opts.HTTPClient = client
		opts.Event = "PostToolBatch"
		opts.FailMode = "open"
		opts.OutageFailModeNow = func() string { return "open" }
		opts.Stdin = strings.NewReader(`{"hook_event_name":"PostToolBatch"}`)
	})
	if !nativeOutageBlocked(result) || !strings.Contains(result.stdout+result.stderr, unprovenListenerReasonPrefix) {
		t.Fatalf("the open tier let a call run past a listener of another account: code=%d stdout=%.300q stderr=%.300q", result.code, result.stdout, result.stderr)
	}
}
