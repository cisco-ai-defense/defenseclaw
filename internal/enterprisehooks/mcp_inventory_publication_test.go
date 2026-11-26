// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMCPInventoryPublicationRejectsUnwithdrawnRecord(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "claude-mcp")
	record := filepath.Join(dir, "S-1-5-21-1.json")
	publish := func() error {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		return os.WriteFile(record, []byte(`{"old":"servers"}`), 0o600)
	}
	if err := PublishMCPInventorySpool(dir, publish, nil); err != nil {
		t.Fatal(err)
	}
	if err := ReadMCPInventoryPublication(dir, nil); err != nil {
		t.Fatal(err)
	}
	failed := errors.New("cannot replace, remove, or truncate record")
	if err := PublishMCPInventorySpool(dir, func() error { return failed }, nil); !errors.Is(err, failed) {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Stat(record); err != nil {
		t.Fatalf("old record should remain for this regression: %v", err)
	}
	if err := ReadMCPInventoryPublication(dir, nil); err == nil {
		t.Fatal("failed publication accepted an older readable record")
	}
	if err := PublishMCPInventorySpool(dir, publish, nil); err != nil {
		t.Fatal(err)
	}
	if err := ReadMCPInventoryPublication(dir, nil); err != nil {
		t.Fatalf("recovery: %v", err)
	}
}

func TestMCPInventoryPublicationRequiresTrustedCompletion(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "codex-mcp")
	if err := ReadMCPInventoryPublication(dir, nil); err == nil {
		t.Fatal("missing receipt accepted")
	}
	called := false
	denied := errors.New("receipt protection failed")
	if err := PublishMCPInventorySpool(dir, func() error { called = true; return nil }, func(string) error { return denied }); !errors.Is(err, denied) {
		t.Fatalf("error=%v", err)
	}
	if called {
		t.Fatal("publisher ran without invalidating and protecting receipt")
	}
	if err := ReadMCPInventoryPublication(dir, nil); err == nil {
		t.Fatal("incomplete receipt accepted")
	}
	if err := PublishMCPInventorySpool(dir, func() error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	trusted := false
	if err := ReadMCPInventoryPublication(dir, func(path, root string) error {
		trusted = path == dir+".inventory-ready" && root == filepath.Dir(dir)
		return denied
	}); !errors.Is(err, denied) || !trusted {
		t.Fatalf("trust check skipped: %v", err)
	}
}

func TestMCPInventoryPublicationFailedCompletionStaysPending(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "codex-mcp")
	protections := 0
	denied := errors.New("final receipt protection failed")
	err := PublishMCPInventorySpool(dir, func() error { return nil }, func(string) error {
		protections++
		if protections == 2 {
			return denied
		}
		return nil
	})
	if !errors.Is(err, denied) {
		t.Fatalf("error=%v", err)
	}
	if err := ReadMCPInventoryPublication(dir, nil); err == nil {
		t.Fatal("failed completion became authoritative")
	}
}
