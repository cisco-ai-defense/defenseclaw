// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestGAP0553RepeatedPluginQuarantineKeepsOneCompleteStage(t *testing.T) {
	cfg, store, logger, skillDir := setupQuarantineProvenanceTestEnv(t)
	pluginDir := filepath.Join(cfg.DataDir, "plugins")
	cfg.PluginDir = pluginDir
	cfg.Guardrail.Connector = "claudecode"
	pluginPath := filepath.Join(pluginDir, "kit")
	if err := os.MkdirAll(pluginPath, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 96; i++ {
		if err := os.WriteFile(filepath.Join(pluginPath, fmt.Sprintf("file-%03d.txt", i)), []byte("ordinary\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w := New(cfg, []string{skillDir}, []string{pluginDir}, store, logger, nil, nil)
	evt := InstallEvent{Type: InstallPlugin, Name: "kit", Path: pluginPath, Connector: "claudecode"}
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- w.quarantineAssetWith(context.Background(), evt, false, "manual block via CLI")
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("quarantine: %v", err)
		}
	}
	if _, err := os.Lstat(pluginPath); !os.IsNotExist(err) {
		t.Fatalf("source remains: %v", err)
	}
	quarantinePath := filepath.Join(cfg.QuarantineDir, "plugins", "claudecode", "kit")
	entries, err := os.ReadDir(quarantinePath)
	if err != nil || len(entries) != 96 {
		t.Fatalf("quarantine entries=%d err=%v", len(entries), err)
	}
	parent, err := os.ReadDir(filepath.Dir(quarantinePath))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range parent {
		if strings.HasPrefix(entry.Name(), "kit.pending-") {
			t.Fatalf("stage remains: %s", entry.Name())
		}
	}
}

func TestGAP0556WatcherQuarantineUsesPluginIdentity(t *testing.T) {
	cfg, store, logger, skillDir := setupQuarantineProvenanceTestEnv(t)
	pluginDir := filepath.Join(cfg.DataDir, "plugins")
	cfg.PluginDir = pluginDir
	cfg.Guardrail.Connector = "claudecode"
	pluginPath := filepath.Join(pluginDir, "kit", "1.0.0")
	if err := os.MkdirAll(pluginPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginPath, "plugin.txt"), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, []string{skillDir}, []string{pluginDir}, store, logger, nil, nil)
	evt := InstallEvent{Type: InstallPlugin, Name: "kit", Path: pluginPath, Connector: "claudecode"}
	if err := w.quarantineAssetWith(context.Background(), evt, false, "manual block via CLI"); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(cfg.QuarantineDir, "plugins", "claudecode", "kit")
	if _, err := os.Stat(filepath.Join(want, "plugin.txt")); err != nil {
		t.Fatalf("plugin copy: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(cfg.QuarantineDir, "plugins", "claudecode", "1.0.0")); !os.IsNotExist(err) {
		t.Fatalf("unexpected version slot: %v", err)
	}
	records, err := store.ListQuarantineRecordsForConnector(context.Background(), "plugin", "kit", "claudecode")
	if err != nil || len(records) != 1 || records[0].QuarantinePath != want {
		t.Fatalf("quarantine records=%v err=%v", records, err)
	}
}
