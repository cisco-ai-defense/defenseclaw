// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReclaimWrittenFileToDirectoryOwnerNoopWhenNotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("reclaim is a no-op only for an unprivileged writer")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.pid")
	if err := os.WriteFile(path, []byte(`{"pid":1}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat fixture: %v", err)
	}
	if err := ReclaimWrittenFileToDirectoryOwner(path); err != nil {
		t.Fatalf("unprivileged reclaim: %v", err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("re-stat fixture: %v", err)
	}
	if after.Mode() != before.Mode() {
		t.Fatalf("unprivileged reclaim changed mode: %v -> %v", before.Mode(), after.Mode())
	}
}

func TestWriteServiceRuntimeFileSelfManagedKeepsPrivateContract(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hook-token")
	if err := WriteServiceRuntimeFile("self_managed", path, "gateway token", []byte("first")); err != nil {
		t.Fatalf("write self-managed runtime file: %v", err)
	}
	if err := WriteServiceRuntimeFile("self_managed", path, "gateway token", []byte("second")); err != nil {
		t.Fatalf("replace self-managed runtime file: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read runtime file: %v", err)
	}
	if string(data) != "second" {
		t.Fatalf("runtime file was not replaced: %q", data)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("inspect runtime file: %v", err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("self-managed runtime file is group/other accessible: %v", info.Mode())
		}
	}
}

// The managed branch validates the shared directory rather than creating it.
func TestWriteServiceRuntimeFileManagedRejectsUnvouchedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	path := filepath.Join(dir, "hook-token")
	if err := WriteServiceRuntimeFile(
		DeploymentModeManagedEnterprise, path, "gateway token", []byte("payload"),
	); err == nil {
		t.Fatal("managed write accepted a directory outside the installer-provisioned tree")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("rejected managed write left a file behind: %v", err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("rejected managed write created the directory: %v", err)
	}
}

func TestPublishServiceRuntimeFileLeavesNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ai-discovery.json")
	for _, payload := range []string{"{}", "{\"a\":1}"} {
		if err := publishServiceRuntimeFile(path, []byte(payload), false); err != nil {
			t.Fatalf("publish %q: %v", payload, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read published file: %v", err)
		}
		if string(data) != payload {
			t.Fatalf("published file holds %q, want %q", data, payload)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("list runtime directory: %v", err)
		}
		if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
			t.Fatalf("publish left extra entries in the runtime directory: %v", entries)
		}
	}
}
