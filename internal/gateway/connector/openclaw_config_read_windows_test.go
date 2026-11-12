// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// A holder that denies sharing on openclaw.json for a moment (OpenClaw saving
// the file, an indexer, or another patcher mid-replace) delays the patch; it
// does not fail it.
func TestPatchOpenClawConfigWaitsForTransientExclusiveHolder(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{"keep":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	release := holdConnectorStateFile(t, configPath, windows.GENERIC_READ|windows.GENERIC_WRITE, 0)
	timer := time.AfterFunc(300*time.Millisecond, release)
	defer timer.Stop()

	if err := patchOpenClawConfig(configPath, "/tmp/ext", false, false, false, ""); err != nil {
		t.Fatalf("patchOpenClawConfig() error = %v, want it to wait for the holder", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("config is not valid JSON: %v\n%s", err, data)
	}
	if cfg["keep"] != true || cfg["plugins"] == nil {
		t.Fatalf("patched config lost keys: %s", data)
	}
}

// Patchers racing a writer that replaces openclaw.json by rename never get an
// open error: they read the old or the new document.
func TestPatchOpenClawConfigDuringConcurrentReplacement(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "openclaw.json")
	if err := os.WriteFile(configPath, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = atomicWriteFile(configPath, []byte("{\"other\":true}\n"), 0o644)
		}
	}()
	defer func() { close(stop); writer.Wait() }()

	for i := 0; i < 50; i++ {
		if err := patchOpenClawConfig(configPath, "/tmp/ext", false, false, false, ""); err != nil {
			t.Fatalf("patch %d: %v", i, err)
		}
	}
}
