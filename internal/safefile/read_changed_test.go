// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A file replaced by a rename while it was read is refused with an error
// that matches ErrFileChanged and keeps its message.
func TestReadReplacedDuringTheReadIsErrFileChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	next := filepath.Join(dir, ".state.json.next")
	if err := os.WriteFile(next, []byte(`{"v":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readRegularFileBounded(path, 1<<10, func() {
		if err := os.Rename(next, path); err != nil {
			t.Fatalf("replace: %v", err)
		}
	})
	if data != nil || !errors.Is(err, ErrFileChanged) || !strings.Contains(err.Error(), "safefile: file changed while reading: "+path) {
		t.Fatalf("read of a replaced file = %q, %v; want no bytes and ErrFileChanged", data, err)
	}
	again, err := ReadRegularFileBounded(path, 1<<10)
	if err != nil || string(again) != `{"v":2}` {
		t.Fatalf("read again = %q, %v", again, err)
	}
}

func TestOtherReadErrorsAreNotErrFileChanged(t *testing.T) {
	_, err := ReadRegularFileBounded(filepath.Join(t.TempDir(), "missing.json"), 1<<10)
	if err == nil || errors.Is(err, ErrFileChanged) {
		t.Fatalf("read of a missing file = %v", err)
	}
}
