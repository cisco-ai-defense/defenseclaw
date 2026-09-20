//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestJSONLExactFIFOOutputAndOwnerOnlyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	adapter, err := NewJSONL(JSONLConfig{Path: path, MaxSizeMB: 1})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newTestDispatcher(t, "jsonl-exact", adapter, 8*1024*1024, 4)
	enqueue(t, dispatcher, "jsonl-a", `{"index":1}`)
	enqueue(t, dispatcher, "jsonl-b", `{"index":2}`)
	drainAndCloseDispatcher(t, dispatcher)
	if err := adapter.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(contents), "{\"index\":1}\n{\"index\":2}\n"; got != want {
		t.Fatalf("JSONL bytes = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("JSONL permissions = %o, want 600", got)
	}
}

func TestJSONLRejectsRawNewlineAndMalformedLaterRecordBeforeWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	adapter, err := NewJSONL(JSONLConfig{Path: path, MaxSizeMB: 1})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newTestDispatcher(t, "jsonl-validation", adapter, 8*1024*1024, 4)
	enqueue(t, dispatcher, "jsonl-valid-first", `{"index":1}`)
	enqueue(t, dispatcher, "jsonl-injected-second", "{\"index\":2}\n")
	drainAndCloseDispatcher(t, dispatcher)
	if got := dispatcher.Counters(); got.Rejected != 2 || got.Delivered != 0 {
		t.Fatalf("invalid batch counters = %+v", got)
	}
	if err := adapter.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) != 0 {
		t.Fatalf("invalid batch partially wrote %q", contents)
	}
}

func TestJSONLRefusesSymlinkHardlinkNonRegularAndUnsafeMode(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("symlink", func(t *testing.T) {
		path := filepath.Join(directory, "symlink.jsonl")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := NewJSONL(JSONLConfig{Path: path, MaxSizeMB: 1}); !IsError(err, ErrorUnsafePath) {
			t.Fatalf("NewJSONL error = %v, want unsafe_path", err)
		}
	})

	t.Run("symlink-parent", func(t *testing.T) {
		realParent := filepath.Join(directory, "real-parent")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		linkedParent := filepath.Join(directory, "linked-parent")
		if err := os.Symlink(realParent, linkedParent); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(linkedParent, "events.jsonl")
		if _, err := NewJSONL(JSONLConfig{Path: path, MaxSizeMB: 1}); !IsError(err, ErrorUnsafePath) {
			t.Fatalf("NewJSONL error = %v, want unsafe_path", err)
		}
	})

	t.Run("hardlink", func(t *testing.T) {
		path := filepath.Join(directory, "hardlink.jsonl")
		if err := os.Link(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := NewJSONL(JSONLConfig{Path: path, MaxSizeMB: 1}); !IsError(err, ErrorUnsafePath) {
			t.Fatalf("NewJSONL error = %v, want unsafe_path", err)
		}
	})

	t.Run("non-regular", func(t *testing.T) {
		path := filepath.Join(directory, "directory.jsonl")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := NewJSONL(JSONLConfig{Path: path, MaxSizeMB: 1}); !IsError(err, ErrorUnsafePath) {
			t.Fatalf("NewJSONL error = %v, want unsafe_path", err)
		}
	})

	t.Run("group-readable", func(t *testing.T) {
		path := filepath.Join(directory, "readable.jsonl")
		if err := os.WriteFile(path, nil, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := NewJSONL(JSONLConfig{Path: path, MaxSizeMB: 1}); !IsError(err, ErrorUnsafePath) {
			t.Fatalf("NewJSONL error = %v, want unsafe_path", err)
		}
	})
}

func TestJSONLReopenRefusesUnsafeReplacementAndAcceptsMissingPath(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "events.jsonl")
	adapter, err := NewJSONL(JSONLConfig{Path: path, MaxSizeMB: 1})
	if err != nil {
		t.Fatal(err)
	}
	moved := path + ".external"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Reopen(context.Background()); err != nil {
		t.Fatalf("Reopen missing active path: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("reopened active path: %v", err)
	}
	if err := adapter.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	adapter, err = NewJSONL(JSONLConfig{Path: filepath.Join(directory, "safe.jsonl"), MaxSizeMB: 1})
	if err != nil {
		t.Fatal(err)
	}
	unsafePath := adapter.config.Path
	if err := os.Remove(unsafePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, unsafePath); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Reopen(context.Background()); !IsError(err, ErrorUnsafePath) {
		t.Fatalf("Reopen error = %v, want unsafe_path", err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "sentinel" {
		t.Fatalf("replacement target changed: %q, %v", got, err)
	}

	hardlinkPath := filepath.Join(directory, "hardlink-reopen.jsonl")
	hardlinkAdapter, err := NewJSONL(JSONLConfig{Path: hardlinkPath, MaxSizeMB: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(hardlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, hardlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := hardlinkAdapter.Reopen(context.Background()); !IsError(err, ErrorUnsafePath) {
		t.Fatalf("hardlink Reopen error = %v, want unsafe_path", err)
	}
}

func TestJSONLRotationCompressionBackupLimitAndAge(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "events.jsonl")
	adapter, err := NewJSONL(JSONLConfig{
		Path: path, MaxSizeMB: 1, MaxBackups: 1, MaxAgeDays: 30, Compress: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newTestDispatcher(t, "jsonl-rotation", adapter, 8*1024*1024, 1)
	first := `{"value":"` + strings.Repeat("a", 700*1024) + `"}`
	second := `{"value":"` + strings.Repeat("b", 700*1024) + `"}`
	third := `{"value":"` + strings.Repeat("c", 700*1024) + `"}`
	enqueue(t, dispatcher, "rotate-a", first)
	enqueue(t, dispatcher, "rotate-b", second)
	enqueue(t, dispatcher, "rotate-c", third)
	drainAndCloseDispatcher(t, dispatcher)
	if err := adapter.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	backups, err := filepath.Glob(path + ".*.gz")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("compressed backups = %v, want exactly one", backups)
	}
	compressed, err := os.Open(backups[0])
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(compressed)
	if err != nil {
		t.Fatal(err)
	}
	backupBytes, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	_ = compressed.Close()
	if got, want := string(backupBytes), second+"\n"; got != want {
		t.Fatalf("decompressed latest backup length=%d, want=%d", len(got), len(want))
	}
	active, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(active), third+"\n"; got != want {
		t.Fatalf("active bytes length=%d, want=%d", len(got), len(want))
	}

	oldTime := time.Now().Add(-31 * 24 * time.Hour)
	ageAdapter, err := NewJSONL(JSONLConfig{Path: filepath.Join(directory, "age.jsonl"), MaxSizeMB: 1, MaxAgeDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	_ = ageAdapter.Close(context.Background())
	// Cleanup is scoped to the configured base name, so create an old backup
	// for that base and reopen once to trigger preparation cleanup.
	agePath := filepath.Join(directory, "age.jsonl")
	ageOld := agePath + "." + strconv.FormatInt(time.Now().Add(-time.Hour).UnixNano(), 10) + ".1"
	if err := os.WriteFile(ageOld, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(ageOld, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	ageAdapter, err = NewJSONL(JSONLConfig{Path: agePath, MaxSizeMB: 1, MaxAgeDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	_ = ageAdapter.Close(context.Background())
	if _, err := os.Stat(ageOld); !os.IsNotExist(err) {
		t.Fatalf("aged backup still exists: %v", err)
	}
}

func TestJSONLZeroPruningDimensionsPreserveBackups(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "events.jsonl")
	backup := path + "." + strconv.FormatInt(time.Now().Add(-time.Hour).UnixNano(), 10) + ".1"
	if err := os.WriteFile(backup, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-365 * 24 * time.Hour)
	if err := os.Chtimes(backup, old, old); err != nil {
		t.Fatal(err)
	}
	adapter, err := NewJSONL(JSONLConfig{Path: path, MaxSizeMB: 1, MaxBackups: 0, MaxAgeDays: 0})
	if err != nil {
		t.Fatal(err)
	}
	_ = adapter.Close(context.Background())
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("zero pruning dimensions removed backup: %v", err)
	}
}

func TestJSONLDefaultsAndCleanupIgnoreUnownedNameShapes(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "events.jsonl")
	config := DefaultJSONLConfig(path)
	if config.MaxSizeMB != 50 || config.MaxBackups != 5 || config.MaxAgeDays != 30 || !config.Compress {
		t.Fatalf("defaults = %+v", config)
	}
	unrelated := path + ".operator-note"
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-365 * 24 * time.Hour)
	if err := os.Chtimes(unrelated, old, old); err != nil {
		t.Fatal(err)
	}
	adapter, err := NewJSONL(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(unrelated); err != nil || string(got) != "keep" {
		t.Fatalf("unrelated same-prefix file changed: %q, %v", got, err)
	}
}

func TestJSONLUnsafeReplacementIsPermanentAndNeverWritesTarget(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "events.jsonl")
	adapter, err := NewJSONL(JSONLConfig{Path: path, MaxSizeMB: 1})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	dispatcher := newTestDispatcher(t, "jsonl-replacement", adapter, 8*1024*1024, 1)
	enqueue(t, dispatcher, "unsafe-replacement", `{"secret":"must-not-write"}`)
	drainAndCloseDispatcher(t, dispatcher)
	if got := dispatcher.Counters(); got.Rejected != 1 || got.Retried != 0 || got.Delivered != 0 {
		t.Fatalf("unsafe replacement counters = %+v", got)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "sentinel" {
		t.Fatalf("replacement target changed: %q, %v", got, err)
	}
}

func TestJSONLConstructionAndCloseStartNoGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()
	for index := 0; index < 50; index++ {
		path := filepath.Join(t.TempDir(), "events.jsonl")
		adapter, err := NewJSONL(JSONLConfig{Path: path, MaxSizeMB: 1})
		if err != nil {
			t.Fatal(err)
		}
		if err := adapter.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	// No adapter code starts a goroutine. A small tolerance avoids unrelated
	// testing/runtime housekeeping making this assertion flaky.
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutines before=%d after=%d", before, after)
	}
}

func TestJSONLEncodedSizeExactAndOverflowSafe(t *testing.T) {
	if size, ok := (*JSONL)(nil).EncodedSize([]int{2, 3}); !ok || size != 7 {
		t.Fatalf("EncodedSize = (%d,%t), want (7,true)", size, ok)
	}
	if _, ok := (*JSONL)(nil).EncodedSize([]int{-1}); ok {
		t.Fatal("negative size accepted")
	}
	if _, ok := (*JSONL)(nil).EncodedSize([]int{maxInt}); ok {
		t.Fatal("overflow size accepted")
	}
}

func TestJSONLConstructorErrorsAreBoundedAndContentFree(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "secret-customer-path.jsonl")
	if err := os.Symlink("missing-target", secretPath); err != nil {
		t.Fatal(err)
	}
	_, err := NewJSONL(JSONLConfig{Path: secretPath, MaxSizeMB: 1})
	if !IsError(err, ErrorUnsafePath) {
		t.Fatalf("error = %v, want unsafe_path", err)
	}
	if strings.Contains(err.Error(), secretPath) || strings.Contains(err.Error(), "customer") {
		t.Fatalf("error leaked path: %q", err)
	}
	if _, err := NewJSONL(JSONLConfig{Path: filepath.Join(t.TempDir(), "age.jsonl"), MaxSizeMB: 1, MaxAgeDays: maxRetentionDays + 1}); !IsError(err, ErrorInvalidConfig) {
		t.Fatalf("oversized age error = %v, want invalid_config", err)
	}
}

func TestSecureMoveNoReplaceNeverClobbersRacedBackup(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "active.jsonl")
	destination := filepath.Join(directory, "raced-backup")
	if err := os.WriteFile(source, []byte("active"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secureMoveNoReplace(source, destination); err == nil {
		t.Fatal("secureMoveNoReplace unexpectedly replaced destination")
	}
	if got, err := os.ReadFile(destination); err != nil || string(got) != "sentinel" {
		t.Fatalf("destination changed: %q, %v", got, err)
	}
	if got, err := os.ReadFile(source); err != nil || string(got) != "active" {
		t.Fatalf("source changed: %q, %v", got, err)
	}
}
