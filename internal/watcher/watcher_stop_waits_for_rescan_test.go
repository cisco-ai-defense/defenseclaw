// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// stopLaggingScanner holds its scan until the scan's context ends, then
// takes a little longer to finish, as a scanner subprocess does.
type stopLaggingScanner struct {
	started chan struct{}
	once    sync.Once
	ended   atomic.Bool
}

func (s *stopLaggingScanner) Name() string               { return "mcp-scanner" }
func (s *stopLaggingScanner) Version() string            { return "fake-1" }
func (s *stopLaggingScanner) SupportedTargets() []string { return []string{"mcp"} }
func (s *stopLaggingScanner) Scan(ctx context.Context, target string) (*scanner.ScanResult, error) {
	s.once.Do(func() { close(s.started) })
	<-ctx.Done()
	time.Sleep(200 * time.Millisecond)
	s.ended.Store(true)
	return nil, ctx.Err()
}

// p0-round GAP-1423: Run returns only after the rescan cycle it started has
// stopped. A cycle still scanning after Run returned went on to read and
// write the audit store its caller closes next ("sql: database is closed"),
// and beside the cycle of a watcher started in its place.
func TestRunReturnsOnlyAfterItsRescanCycleStopped(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Watch.RescanEnabled = true
	servers := []config.MCPServerEntry{{Name: "held", URL: "https://held.example.test/mcp", Connector: "codex"}}
	held := &stopLaggingScanner{started: make(chan struct{})}
	w := New(cfg, nil, nil, store, logger, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return held }
	w.SetMCPServerSource(func() ([]config.MCPServerEntry, error) {
		return append([]config.MCPServerEntry(nil), servers...), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- w.Run(ctx) }()
	select {
	case <-held.started:
	case err := <-runErr:
		t.Fatalf("Run ended before the startup rescan scanned the server: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the startup rescan never scanned the server")
	}
	cancel()
	select {
	case <-runErr:
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
	if !held.ended.Load() {
		t.Fatal("Run returned while its rescan cycle was still scanning")
	}
}
