// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/ipc"
	"github.com/defenseclaw/defenseclaw/internal/notify"
	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

// shortTempDir returns a scratch dir with a path short enough to
// fit a UDS sun_path (104 bytes on darwin). t.TempDir defaults to
// /var/folders/… on macOS which regularly overshoots the limit, so
// we short-circuit to /tmp/dc-ipc-… when available.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "dc-ipc-")
	if err != nil {
		// Fall back to t.TempDir on platforms without /tmp write
		// access; the caller may still fail the path-length check
		// but the error will be explicit.
		return t.TempDir()
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// newIPCHarness spins up a real ipc.Server on a tempdir socket
// backed by a real *audit.Store + *gateway.SidecarHealth +
// *notifier.Dispatcher. Cleanup cancels the server and closes
// everything so the goroutine leak checker stays quiet.
func newIPCHarness(t *testing.T) (*grpc.ClientConn, *gateway.SidecarHealth, *audit.Store, *notifier.Dispatcher, string) {
	t.Helper()

	dataDir := shortTempDir(t)
	dbPath := filepath.Join(dataDir, "audit.db")
	store, err := audit.NewStore(dbPath)
	if err != nil {
		t.Fatalf("open audit store: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("init audit schema: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	health := gateway.NewSidecarHealth()
	health.SetGateway(gateway.StateRunning, "", nil)
	health.SetAPI(gateway.StateRunning, "", nil)

	// Give the dispatcher a permissive config so every category /
	// source flows through — matches how the sidecar wires it in
	// production for AVC's benefit. The sender is a silent no-op so
	// the e2e host never fires real desktop toasts.
	dispatcherCfg := config.NotificationsConfig{
		Enabled:         true,
		BlockEnforced:   true,
		BlockWouldBlock: true,
		HITLApproval:    true,
	}
	dispatcherCfg.Sources.Hook = true
	dispatcherCfg.Sources.Guardrail = true
	dispatcherCfg.Sources.AssetPolicy = true
	dispatcher := notifier.NewWithSender(dispatcherCfg, func(_ notify.Notification) error { return nil })

	sockPath := filepath.Join(dataDir, "ipc", ipc.SocketFileName)
	fullCfg := &config.Config{
		DataDir: dataDir,
		Managed: config.ManagedIPCConfig{
			SocketPath: sockPath,
			SocketMode: "0600",
		},
	}

	srv, err := ipc.NewServer(ipc.ServerOptions{
		Config:     fullCfg,
		Health:     health,
		Store:      store,
		Dispatcher: dispatcher,
		Version:    "e2e-test",
		Logf:       func(format string, args ...any) { t.Logf("[ipc] "+format, args...) },
	})
	if err != nil {
		t.Fatalf("ipc new server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()

	// Wait for the socket to be present so the client connect doesn't
	// race the bind.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(sockPath); err != nil {
		cancel()
		<-runErr
		t.Fatalf("socket did not appear at %s: %v", sockPath, err)
	}

	conn, err := grpc.NewClient(
		"unix://"+sockPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		cancel()
		<-runErr
		t.Fatalf("grpc dial: %v", err)
	}

	t.Cleanup(func() {
		_ = conn.Close()
		cancel()
		select {
		case err := <-runErr:
			if err != nil {
				t.Logf("server shutdown returned: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("ipc server did not shut down within 3s")
		}
	})

	return conn, health, store, dispatcher, sockPath
}

// TestIPC_GetHealthSnapshotFirst asserts the AVC contract's snapshot-
// first semantics on GetHealth: connecting immediately returns the
// current availability, and toggling gateway state produces a new
// snapshot within the debounce window.
func TestIPC_GetHealthSnapshotFirst(t *testing.T) {
	conn, health, _, _, _ := newIPCHarness(t)
	client := pb.NewDefenseClawSecureClientServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.GetHealth(ctx, &pb.GetHealthRequest{ClientSchemaVersion: 1})
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	first, err := recvWithDeadline(stream, 1*time.Second)
	if err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	if first.Availability != pb.ServiceAvailability_SERVICE_AVAILABILITY_READY {
		t.Errorf("first availability = %v, want READY", first.Availability)
	}
	if first.SchemaVersion != 1 {
		t.Errorf("schema version = %d, want 1", first.SchemaVersion)
	}
	if first.DefenseClawVersion != "e2e-test" {
		t.Errorf("version = %q, want e2e-test", first.DefenseClawVersion)
	}

	// Trigger a state change; the second snapshot arrives after debounce.
	health.SetGateway(gateway.StateReconnecting, "flake", nil)
	second, err := recvWithDeadline(stream, 1*time.Second)
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if second.Availability != pb.ServiceAvailability_SERVICE_AVAILABILITY_DEGRADED {
		t.Errorf("second availability = %v, want DEGRADED", second.Availability)
	}
}

// TestIPC_GetStatsSnapshotFirst asserts the stats stream reflects
// live audit counter changes on the 2s tick.
func TestIPC_GetStatsSnapshotFirst(t *testing.T) {
	conn, _, store, _, _ := newIPCHarness(t)
	client := pb.NewDefenseClawSecureClientServiceClient(conn)

	// Seed one blocked-skill action so the initial snapshot is non-trivial.
	seedBlockedSkill(t, store, "seed-skill")

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	stream, err := client.GetStatsSnapshot(ctx, &pb.GetStatsSnapshotRequest{ClientSchemaVersion: 1})
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	first, err := recvWithDeadline(stream, 1*time.Second)
	if err != nil {
		t.Fatalf("first stats snapshot: %v", err)
	}
	if first.Availability != pb.StatsAvailability_STATS_AVAILABILITY_AVAILABLE {
		t.Errorf("availability = %v, want AVAILABLE", first.Availability)
	}
	if first.BlockedSkills < 1 {
		t.Errorf("blocked_skills = %d, want ≥1 after seeding", first.BlockedSkills)
	}

	// Mutate the store and expect a fresh snapshot on the next tick.
	seedBlockedSkill(t, store, "delta-skill")
	next, err := recvWithDeadline(stream, 4*time.Second)
	if err != nil {
		t.Fatalf("delta stats snapshot: %v", err)
	}
	if next.BlockedSkills <= first.BlockedSkills {
		t.Errorf("blocked_skills did not increase: first=%d next=%d",
			first.BlockedSkills, next.BlockedSkills)
	}
}

// TestIPC_WatchNotifications asserts that a block event routed
// through the dispatcher arrives on the WatchNotifications stream
// with the mapped severity/presentation.
func TestIPC_WatchNotifications(t *testing.T) {
	conn, _, _, dispatcher, _ := newIPCHarness(t)
	client := pb.NewDefenseClawSecureClientServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := client.WatchNotifications(ctx, &pb.WatchNotificationsRequest{ClientSchemaVersion: 1})
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	// The stream registers the subscriber asynchronously in the RPC
	// handler on the server side, so a single OnBlock right after Open
	// can race the subscribe. Rather than a fixed sleep (flaky on
	// slow CI), keep publishing distinct targets on a ticker until
	// the client receives one — the dispatcher's dedup window is on
	// target+reason, so distinct targets guarantee eventual delivery
	// once the subscription lands.
	publishStop := make(chan struct{})
	publishDone := make(chan struct{})
	go func() {
		defer close(publishDone)
		i := 0
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-publishStop:
				return
			case <-tick.C:
				i++
				dispatcher.OnBlock(notifier.BlockEvent{
					Source: notifier.SourceHook,
					Target: fmt.Sprintf("shell.rm-%d", i),
					Reason: "dangerous",
				})
			}
		}
	}()
	t.Cleanup(func() {
		close(publishStop)
		<-publishDone
	})

	rec, err := recvWithDeadline(stream, 2*time.Second)
	if err != nil {
		t.Fatalf("recv notification: %v", err)
	}
	if rec.Severity != pb.NotificationSeverity_NOTIFICATION_SEVERITY_ERROR {
		t.Errorf("severity = %v, want ERROR", rec.Severity)
	}
	if rec.Presentation != pb.NotificationPresentation_NOTIFICATION_PRESENTATION_TRANSIENT_AND_HISTORY {
		t.Errorf("presentation = %v, want TRANSIENT_AND_HISTORY", rec.Presentation)
	}
	if rec.SchemaVersion != 1 {
		t.Errorf("schema version = %d, want 1", rec.SchemaVersion)
	}
	if rec.NotificationId == "" {
		t.Errorf("notification_id is empty; every record must carry a stable id")
	}
	if rec.Sequence == 0 {
		t.Errorf("sequence is 0; per-process sequence must start at 1")
	}
}

// TestIPC_ShutdownRemovesSocket asserts clean shutdown removes the
// UDS file so a subsequent boot does not have to reap a stale
// socket.
func TestIPC_ShutdownRemovesSocket(t *testing.T) {
	dataDir := shortTempDir(t)
	store, err := audit.NewStore(filepath.Join(dataDir, "audit.db"))
	if err != nil {
		t.Fatalf("open audit store: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("init audit schema: %v", err)
	}
	defer store.Close()

	sockPath := filepath.Join(dataDir, "ipc", ipc.SocketFileName)
	cfg := &config.Config{
		DataDir: dataDir,
		Managed: config.ManagedIPCConfig{
			SocketPath: sockPath,
			SocketMode: "0600",
		},
	}
	srv, err := ipc.NewServer(ipc.ServerOptions{
		Config: cfg,
		Health: gateway.NewSidecarHealth(),
		Store:  store,
		Logf:   func(format string, args ...any) { t.Logf("[ipc] "+format, args...) },
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- srv.Run(ctx) }()

	// Wait for the socket to appear or run to error out early.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-runErr:
			t.Fatalf("server exited before socket appeared: %v", err)
		default:
		}
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(sockPath); err != nil {
		cancel()
		t.Fatalf("socket did not appear at %s: %v", sockPath, err)
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("server shutdown returned: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("server did not stop within 3s")
	}

	if _, err := os.Stat(sockPath); !errors.Is(err, syscall.ENOENT) && !os.IsNotExist(err) {
		t.Errorf("expected socket removed after shutdown; stat = %v", err)
	}
}

func recvWithDeadline[T any](stream grpc.ServerStreamingClient[T], d time.Duration) (*T, error) {
	type recvResult struct {
		msg *T
		err error
	}
	ch := make(chan recvResult, 1)
	go func() {
		msg, err := stream.Recv()
		ch <- recvResult{msg: msg, err: err}
	}()
	select {
	case r := <-ch:
		if r.err == io.EOF {
			return nil, errors.New("stream closed early")
		}
		return r.msg, r.err
	case <-time.After(d):
		return nil, errors.New("recv timed out")
	}
}

func seedBlockedSkill(t *testing.T, store *audit.Store, name string) {
	t.Helper()
	if err := store.SetActionField("skill", name, "install", "block", "e2e-test"); err != nil {
		t.Fatalf("seed block: %v", err)
	}
}
