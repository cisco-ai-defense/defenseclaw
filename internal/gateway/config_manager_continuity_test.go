// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A slow generation build must leave the previous generation available to
// admitted hooks. The fake gateway uses the production caller limiter and
// pins one atomically published generation for each request.
func TestHotGenerationReloadKeepsHooksServing(t *testing.T) {
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
	first, err := buildGeneration(t.Context(), generationInputs{cfg: initial, raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	first.N = 1
	var published atomic.Pointer[Generation]
	published.Store(first)
	building := make(chan struct{})
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(ctx context.Context, _, next *config.Config, _ ConfigDiff, source configReloadSource) error {
		close(building)
		// Represent a slow rule-pack or digest build while hooks arrive.
		time.Sleep(300 * time.Millisecond)
		g, err := buildGeneration(ctx, generationInputs{cfg: next, raw: source.raw})
		if err != nil {
			return err
		}
		g.N = first.N + 1
		published.Store(g)
		return nil
	})
	api := &APIServer{}
	api.hookCallerLimits = hookCallerLimiter{rate: 1000, burst: 1000, inFlight: 4, running: 2}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r, release := api.admitHookCaller(w, r, "managed-user", "/hook")
		if release == nil {
			return
		}
		defer release()
		g := published.Load()
		_, _ = io.WriteString(w, requestGeneration(withPinnedGeneration(r.Context(), g)).Digest)
	}))
	defer server.Close()
	writeConfigForManagerTest(t, path, dir, "action")
	reloadDone := make(chan error, 1)
	go func() { reloadDone <- mgr.Reload(context.Background(), "hot_bundle") }()
	select {
	case <-building:
	case <-time.After(5 * time.Second):
		t.Fatal("generation build did not start")
	}
	client := &http.Client{Timeout: 200 * time.Millisecond}
	var sawNext atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 80; j++ {
				start := time.Now()
				response, err := client.Get(server.URL + "/hook")
				if err != nil {
					t.Errorf("hook timed out during reload: %v", err)
					return
				}
				body, readErr := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if readErr != nil || response.StatusCode != http.StatusOK ||
					(string(body) != first.Digest && string(body) != published.Load().Digest) {
					t.Errorf("hook during reload: status=%d body=%q err=%v", response.StatusCode, body, readErr)
					return
				}
				if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
					t.Errorf("hook stalled for %s during reload", elapsed)
					return
				}
				if string(body) != first.Digest {
					sawNext.Store(true)
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	if err := <-reloadDone; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if published.Load().Digest == first.Digest {
		t.Fatal("new generation was not published")
	}
	if !sawNext.Load() {
		t.Fatal("hook loop did not observe the generation swap")
	}
}
