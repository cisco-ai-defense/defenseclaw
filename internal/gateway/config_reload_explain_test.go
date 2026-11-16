// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
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
	// The profile oracle intentionally waits for the reload. A managed
	// PreToolUse decision must keep serving from its pinned generation.
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger}
	api.SetGenerationSource(func() *Generation {
		return &Generation{N: 1, Config: initial}
	})
	hookDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook",
			strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"date"}}`))
		api.handleAgentHook("claudecode").ServeHTTP(response, request)
		hookDone <- response
	}()
	select {
	case response := <-hookDone:
		if response.Code != http.StatusOK {
			t.Fatalf("hook status during reload = %d: %s", response.Code, response.Body.String())
		}
	// Leave room for a contended race runner while staying well below the
	// oracle's reload wait. A hook that waits on that gate still fails here.
	case <-time.After(configReloadExplainWait / 2):
		t.Fatal("hook decision waited for the hot reload")
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
