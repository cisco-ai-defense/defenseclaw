// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestMCPInventoryPublicationLockedReadyReceiptFailsClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "codex-mcp")
	publish := func() error {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, "S-1-5-21-1.json"), []byte(`{"servers":[]}`), 0o600)
	}
	if err := PublishMCPInventorySpool(dir, publish, nil); err != nil {
		t.Fatal(err)
	}

	ready := windows.StringToUTF16Ptr(dir + ".inventory-ready")
	handle, err := windows.CreateFile(ready, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := PublishMCPInventorySpool(dir, publish, nil); err == nil {
		windows.CloseHandle(handle)
		t.Fatal("publication replaced a receipt held without write or delete sharing")
	}
	if _, err := ReadMCPInventoryPublication(dir, nil); err == nil {
		windows.CloseHandle(handle)
		t.Fatal("locked stale receipt remained authoritative")
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}

	if err := PublishMCPInventorySpool(dir, publish, nil); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if _, err := ReadMCPInventoryPublication(dir, nil); err != nil {
		t.Fatalf("recovery receipt: %v", err)
	}
}
