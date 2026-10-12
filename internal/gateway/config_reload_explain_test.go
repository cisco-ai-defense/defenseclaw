// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0307: from the first event of a configuration write until its reload
// is applied the profile oracle waits, so the first explain after a write
// already uses the new assignments instead of the previous ones.
func TestConfigReloadHoldsTheProfileOracleUntilApplied(t *testing.T) {
	previousGate := configReloadInFlight
	configReloadInFlight = &configReloadGate{}
	t.Cleanup(func() { configReloadInFlight = previousGate })
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	var armed atomic.Bool
	entered, release := make(chan struct{}, 1), make(chan struct{})
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "",
		func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
			if armed.Load() {
				entered <- struct{}{}
				<-release
			}
			return nil
		})
	mgr.setStartupSource(path, raw)
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan error, 1), make(chan error, 1)
	go func() { done <- mgr.runWithStartupReconcile(ctx, ready) }()
	t.Cleanup(func() { cancel(); <-done })
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	armed.Store(true)
	writeConfigForManagerTest(t, path, dir, "action")
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the configuration write was not reloaded")
	}
	answered := make(chan struct{})
	go awaitConfigReload(func(http.ResponseWriter, *http.Request) { close(answered) })(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?user=ent-hank", nil))
	select {
	case <-answered:
		t.Fatal("explain answered while the new configuration was still being applied")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	select {
	case <-answered:
	case <-time.After(5 * time.Second):
		t.Fatal("explain did not answer once the reload was applied")
	}
}
