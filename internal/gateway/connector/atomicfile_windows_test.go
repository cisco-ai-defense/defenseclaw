// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestAtomicWriteAcceptsVerifiedStateAfterVisibleLateReplaceFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	data := []byte("managed\n")
	lateFailure := errors.New("simulated late write-through failure")
	calls := 0
	replace := func(source, destination string) error {
		calls++
		if err := safefile.ReplaceFile(source, destination); err != nil {
			return err
		}
		if calls == 1 {
			return lateFailure
		}
		return nil
	}

	if err := atomicWriteFileWithReplace(path, data, 0o600, replace); err == nil {
		t.Fatal("first write accepted an ambiguous late replacement failure")
	}
	visible, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(visible) != string(data) {
		t.Fatalf("visible bytes after late failure = %q", visible)
	}
	if err := atomicWriteFileWithReplace(path, data, 0o600, replace); err != nil {
		t.Fatalf("durability retry: %v", err)
	}
	if calls != 1 {
		t.Fatalf("replace calls = %d, want 1; verified identical Windows state was rewritten", calls)
	}
}

func TestAtomicWriteIdenticalWindowsConfigPreservesIdentityAndMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	data := []byte("managed\n")
	if err := atomicWriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	stream := path + ":operator-metadata"
	if err := os.WriteFile(stream, []byte("preserve"), 0o600); err != nil {
		if errors.Is(err, windows.ERROR_INVALID_NAME) || errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
			t.Skipf("test volume does not support NTFS alternate streams: %v", err)
		}
		t.Fatal(err)
	}
	wantModTime := time.Unix(1_700_000_000, 0)
	if err := os.Chtimes(path, wantModTime, wantModTime); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("identical Windows config was replaced instead of treated as a no-op")
	}
	if !after.ModTime().Equal(wantModTime) {
		t.Fatalf("modification time=%s, want preserved %s", after.ModTime(), wantModTime)
	}
	metadata, err := os.ReadFile(stream)
	if err != nil || string(metadata) != "preserve" {
		t.Fatalf("alternate stream=%q error=%v, want preserved", metadata, err)
	}
}
