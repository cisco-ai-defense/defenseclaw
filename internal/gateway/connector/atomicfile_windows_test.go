// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestAtomicWriteRetriesVisibleLateReplaceFailure(t *testing.T) {
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
	if calls != 2 {
		t.Fatalf("replace calls = %d, want 2; visible equality skipped the durability retry", calls)
	}
}
