// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestReadManagedHookRuntimeFileRetriesChangedIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "runtime.txt")
	stage := filepath.Join(dir, "stage.txt")
	if err := os.WriteFile(path, []byte("old body"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stage, []byte("new body"), 0o600); err != nil {
		t.Fatal(err)
	}
	replaced := false
	restore := pathidentity.SetPinnedStatHookForTest(func(checked string) {
		if checked != path || replaced {
			return
		}
		replaced = true
		if err := safefile.ReplaceFileAtomically(stage, path); err != nil {
			t.Fatalf("replace between identity check and open: %v", err)
		}
	})
	t.Cleanup(restore)
	data, err := ReadManagedHookRuntimeFile(path, "managed hook runtime", 128)
	if err != nil || string(data) != "new body" || !replaced {
		t.Fatalf("read = %q, err = %v, replaced = %t", data, err, replaced)
	}
}

func TestReadManagedHookRuntimeFileReadsStableBody(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.txt")
	if err := os.WriteFile(path, []byte("stable body"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := ReadManagedHookRuntimeFile(path, "managed hook runtime", 128)
	if err != nil || string(data) != "stable body" {
		t.Fatalf("read = %q, err = %v", data, err)
	}
}
