// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// GAP-2354: the watcher must not create ~/.hermes/hermes-agent before Hermes
// is installed (its installer then refuses the folder); it watches the plugin
// folder once the installer has created it.
func TestWatcherDoesNotCreateHermesAgentCheckout(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Guardrail.Connector = "hermes"
	home := filepath.Join(t.TempDir(), ".hermes")
	userPlugins := filepath.Join(home, "plugins")
	agentPlugins := filepath.Join(home, "hermes-agent", "plugins")
	if err := store.SetActionField("plugin", "late-plugin", "install", "allow", "pre-approved"); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	seen := map[string]string{}
	w := New(cfg, []string{skillDir}, []string{userPlugins, agentPlugins}, store, logger, nil, func(r AdmissionResult) {
		mu.Lock()
		seen[r.Event.Name] = r.Event.Path
		mu.Unlock()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- w.Run(ctx) }()
	time.Sleep(300 * time.Millisecond)

	if _, err := os.Lstat(filepath.Join(home, "hermes-agent")); !os.IsNotExist(err) {
		t.Fatalf("watcher created the Hermes checkout folder (err=%v)", err)
	}
	if info, err := os.Stat(userPlugins); err != nil || !info.IsDir() {
		t.Fatalf("user plugin folder not created: %v", err)
	}

	// The Hermes installer creates its checkout; a plugin added later is admitted.
	if err := os.MkdirAll(agentPlugins, 0o700); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * w.debounce)
	plugin := filepath.Join(agentPlugins, "late-plugin")
	if err := os.MkdirAll(plugin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugin, "__init__.py"), []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Hermes loads a plugin folder only with its manifest (GAP-2471).
	if err := os.WriteFile(filepath.Join(plugin, "plugin.yaml"), []byte("name: late-plugin\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		got := seen["late-plugin"]
		mu.Unlock()
		if got == plugin {
			break
		}
		select {
		case <-deadline:
			cancel()
			<-errCh
			mu.Lock()
			defer mu.Unlock()
			t.Fatalf("admissions = %v, want late-plugin at %s", seen, plugin)
		case <-time.After(50 * time.Millisecond):
		}
	}
	cancel()
	<-errCh
}
