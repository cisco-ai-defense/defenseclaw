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

func TestGAP0556ClaudeCacheCopiesKeepListedIdentity(t *testing.T) {
	cfg, store, logger, skillDir := setupQuarantineProvenanceTestEnv(t)
	pluginDir := filepath.Join(cfg.DataDir, "plugins")
	cfg.PluginDir = pluginDir
	cfg.Guardrail.Connector = "claudecode"
	w := New(cfg, []string{skillDir}, []string{pluginDir}, store, logger, nil, nil)
	for _, version := range []string{"1.0.0", "2.0.0"} {
		path := filepath.Join(pluginDir, "cache", "market", "kit", version)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "plugin.txt"), []byte(version), 0o600); err != nil {
			t.Fatal(err)
		}
		evt := InstallEvent{Type: InstallPlugin, Name: "kit@market", Path: path, Connector: "claudecode"}
		if err := w.quarantineAssetWith(context.Background(), evt, false, "manual block via CLI"); err != nil {
			t.Fatal(err)
		}
	}
	records, err := store.ListQuarantineRecordsForConnector(context.Background(), "plugin", "kit@market", "claudecode")
	if err != nil || len(records) != 2 {
		t.Fatalf("quarantine records=%v err=%v", records, err)
	}
	primary := filepath.Join(cfg.QuarantineDir, "plugins", "claudecode", "kit@market")
	if records[0].QuarantinePath != primary {
		t.Fatalf("primary path=%q, want %q", records[0].QuarantinePath, primary)
	}
	fallback := records[1].QuarantinePath
	wantFallbackRoot := filepath.Join(cfg.QuarantineDir, "per-source", "plugins", "claudecode") + string(filepath.Separator)
	if !strings.HasPrefix(fallback, wantFallbackRoot) || filepath.Base(fallback) != "kit@market" {
		t.Fatalf("fallback path=%q, want a separate listed-identity slot", fallback)
	}
	for _, path := range []string{primary, fallback} {
		if _, err := os.Stat(filepath.Join(path, "plugin.txt")); err != nil {
			t.Fatalf("quarantine copy %q: %v", path, err)
		}
	}
}
