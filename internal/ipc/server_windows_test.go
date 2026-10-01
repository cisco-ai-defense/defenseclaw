// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ipc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

type serverLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *serverLog) logf(format string, args ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
	l.mu.Unlock()
}

func (l *serverLog) find(fragments ...string) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range l.lines {
		matched := true
		for _, fragment := range fragments {
			if !strings.Contains(line, fragment) {
				matched = false
				break
			}
		}
		if matched {
			return line, true
		}
	}
	return "", false
}

// TestServerRunAuthenticatesWindowsPeers drives the production wiring
// on a managed_enterprise config: Server.Run binds the socket with its
// DACL, wraps it through wrapPeerAuthListener and
// newWindowsSecureClientListener with the host's trusted Program Files
// roots and real drive devices, and serves gRPC on the result. This
// test binary is an ordinary same-user process, so it must receive no
// health snapshot and the refusal must be logged. The test fails if Run
// ever serves the socket without the peer check.
func TestServerRunAuthenticatesWindowsPeers(t *testing.T) {
	previous := allowUnsafeSocketOverrideForTest
	allowUnsafeSocketOverrideForTest = true
	t.Cleanup(func() { allowUnsafeSocketOverrideForTest = previous })
	// The socket DACL names the gateway service identity. A test host
	// need not have the DefenseClaw service registered, so use a
	// virtual service account every Windows installation has.
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\TrustedInstaller`)

	socketPath := filepath.Join(shortSocketDir(t), "ipc", SocketFileName)
	serverLines := &serverLog{}
	srv, err := NewServer(ServerOptions{
		Config: &config.Config{
			DataDir:        t.TempDir(),
			DeploymentMode: "managed_enterprise",
			Managed:        config.ManagedIPCConfig{SocketPath: socketPath},
		},
		Health: gateway.NewSidecarHealth(),
		// Only the stats RPC reads the store, and it is never reached.
		Store: &audit.Store{},
		Logf:  serverLines.logf,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	stopped := false
	stop := func() error {
		if stopped {
			return nil
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(15 * time.Second):
			return fmt.Errorf("Run did not return after cancel")
		}
	}
	t.Cleanup(func() { _ = stop() })

	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, ok := serverLines.find("listening on", "codesign_peer_auth=enabled"); ok {
			break
		}
		select {
		case err := <-done:
			stopped = true
			t.Fatalf("Run returned before listening: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("Run did not start listening")
		}
	}

	if snapshot, err := fetchHealth(socketPath); err == nil {
		t.Fatalf("same-user test process received health snapshot %v from Server.Run", snapshot)
	}
	want := fmt.Sprintf("peer rejected: pid=%d ", os.Getpid())
	deadline = time.Now().Add(10 * time.Second)
	for {
		if _, ok := serverLines.find(want, "not an allowed Secure Client GUI executable"); ok {
			break
		}
		if time.Now().After(deadline) {
			line, _ := serverLines.find("peer rejected")
			t.Fatalf("no image-name rejection logged for this process (first rejection: %q)", line)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
}
