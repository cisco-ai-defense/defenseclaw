// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cfgtxn

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCommitDoesNotReplaceConfigWhenPreviousReadFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	txn, err := Begin(context.Background(), path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer txn.Close()
	if _, _, _, err := txn.Read(); err != nil {
		t.Fatal(err)
	}

	// A non-cooperating process can change the path after Read. A symlink to
	// a directory makes the second read fail even when tests run as root.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(filepath.Dir(path), "unreadable")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Mkdir(GenerationPath(path), 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := txn.Commit([]byte("candidate"), 0o600, "test", "regression"); err == nil {
		t.Fatal("commit succeeded despite failed previous read")
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("commit removed config path: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("commit replaced unreadable config path with %s", info.Mode())
	}
}
