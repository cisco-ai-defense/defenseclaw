// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0044: the scanner runtime executable is hashed once, through a handle
// that shares only reading. While it is held the file cannot be written,
// replaced or removed, and the installed check compares that digest with the
// admission record without reading the file again, only while the handle
// holds the very file the path names.
func TestWindowsScannerRuntimeIsHashedOnceUnderAPin(t *testing.T) {
	aclSeam := windowsScannerRuntimeACLCheck
	t.Cleanup(func() { windowsScannerRuntimeACLCheck = aclSeam })
	windowsScannerRuntimeACLCheck = func(string, string) error { return nil }

	root := t.TempDir()
	target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	body := []byte("scanner runtime bytes")
	if err := os.WriteFile(target, body, 0o644); err != nil {
		t.Fatal(err)
	}
	pin, got, err := windowsScannerRuntimePinned(target)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	sum := sha256.Sum256(body)
	if got != hex.EncodeToString(sum[:]) {
		t.Fatalf("pinned digest %s", got)
	}
	if err := os.WriteFile(target, []byte("other"), 0o644); err == nil {
		t.Fatal("the pinned executable was rewritten")
	}
	if err := os.Rename(target, target+".old"); err == nil {
		t.Fatal("the pinned executable was renamed")
	}
	if err := os.Remove(target); err == nil {
		t.Fatal("the pinned executable was removed")
	}
	if err := managed.WriteScannerRuntimeAdmission(root, got, managed.ScannerRuntimeTrustHashPinned); err != nil {
		t.Fatal(err)
	}
	if err := windowsInstalledScannerRuntimeCheckPinned(root, target, pin, got); err != nil {
		t.Fatalf("pinned check of the admitted executable: %v", err)
	}
	// The held digest is what is compared: another digest is refused.
	if err := windowsInstalledScannerRuntimeCheckPinned(root, target, pin, hex.EncodeToString(make([]byte, 32))); err == nil {
		t.Fatal("a digest that is not the admitted one passed")
	}
	// A handle on another file proves nothing about target.
	other := filepath.Join(root, "other.exe")
	if err := os.WriteFile(other, body, 0o644); err != nil {
		t.Fatal(err)
	}
	otherPin, _, err := windowsScannerRuntimePinned(other)
	if err != nil {
		t.Fatal(err)
	}
	defer otherPin.Close()
	if err := windowsInstalledScannerRuntimeCheckPinned(root, target, otherPin, got); err == nil {
		t.Fatal("a pin on another file was taken for the installed executable")
	}
}
