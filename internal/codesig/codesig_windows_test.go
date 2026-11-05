// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package codesig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestVerifyAuthenticodeRefusesAnUnsignedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claude.exe")
	if err := os.WriteFile(path, []byte("MZ not signed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := VerifyAuthenticode(path, AnthropicPublishers); got.Verified || !strings.Contains(got.Reason, "does not verify") {
		t.Fatalf("VerifyAuthenticode = %+v, want an unsigned refusal", got)
	}
}

func TestVerifyAuthenticodeMatchesThePublisher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claude.exe")
	if err := os.WriteFile(path, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := verifyAuthenticodeFile
	t.Cleanup(func() { verifyAuthenticodeFile = old })
	for signer, want := range map[string]bool{"Anthropic PBC": true, "Anthropic, PBC": true, "Mallory Inc": false} {
		verifyAuthenticodeFile = func(*uint16, windows.Handle) (string, error) { return signer, nil }
		if got := VerifyAuthenticode(path, AnthropicPublishers); got.Verified != want {
			t.Fatalf("signer %q: VerifyAuthenticode = %+v, want verified %v", signer, got, want)
		}
	}
	verifyAuthenticodeFile = func(*uint16, windows.Handle) (string, error) { return "", errors.New("TRUST_E_NOSIGNATURE") }
	if got := VerifyAuthenticode(path, AnthropicPublishers); got.Verified || !strings.Contains(got.Reason, "TRUST_E_NOSIGNATURE") {
		t.Fatalf("VerifyAuthenticode = %+v, want the WinVerifyTrust reason", got)
	}
	if got := VerifyAuthenticode(path, nil); got.Verified {
		t.Fatalf("VerifyAuthenticode without publishers = %+v, want refused", got)
	}
	if got := VerifyAuthenticode(`claude.exe`, AnthropicPublishers); got.Verified {
		t.Fatalf("VerifyAuthenticode of a relative path = %+v, want refused", got)
	}
}

func TestVerifyAuthenticodeReportsTheSignedFileVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claude.exe")
	if err := os.WriteFile(path, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldVerify, oldVersion := verifyAuthenticodeFile, readFileVersion
	t.Cleanup(func() { verifyAuthenticodeFile, readFileVersion = oldVerify, oldVersion })
	verifyAuthenticodeFile = func(*uint16, windows.Handle) (string, error) { return "Anthropic PBC", nil }
	readFileVersion = func(string) string { return "2.1.309.0" }
	if got := VerifyAuthenticode(path, AnthropicPublishers); !got.Verified || got.Version != "2.1.309.0" {
		t.Fatalf("VerifyAuthenticode = %+v", got)
	}
	// An unversioned file has no version resource.
	if got := fileProductVersion(path); got != "" {
		t.Fatalf("fileProductVersion = %q", got)
	}
}

// GAP-0039: the digest is of the bytes the signature check held. It is read
// through the verified handle from the start (the check moved the file
// pointer), and nothing can open the file for writing while it is checked.
func TestVerifyAuthenticodeWithSHA256HashesTheVerifiedHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claude.exe")
	content := []byte("MZ a signed engine image")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	oldVerify, oldVersion := verifyAuthenticodeFile, readFileVersion
	t.Cleanup(func() { verifyAuthenticodeFile, readFileVersion = oldVerify, oldVersion })
	readFileVersion = func(string) string { return "2.1.317.0" }
	var writeErr error
	verifyAuthenticodeFile = func(_ *uint16, handle windows.Handle) (string, error) {
		var read uint32
		if err := windows.ReadFile(handle, make([]byte, 4), &read, nil); err != nil || read != 4 {
			t.Fatalf("read the handle: %d %v", read, err)
		}
		if file, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			file.Close()
		} else {
			writeErr = err
		}
		return "Anthropic PBC", nil
	}
	sum := sha256.Sum256(content)
	got := VerifyAuthenticodeWithSHA256(path, AnthropicPublishers)
	if !got.Verified || got.SHA256 != hex.EncodeToString(sum[:]) || got.Version != "2.1.317.0" {
		t.Fatalf("VerifyAuthenticodeWithSHA256 = %+v, want sha256 %x", got, sum)
	}
	if writeErr == nil {
		t.Fatal("the file could be opened for writing while its signature was checked")
	}
	if got := VerifyAuthenticode(path, AnthropicPublishers); !got.Verified || got.SHA256 != "" {
		t.Fatalf("VerifyAuthenticode = %+v, want no digest", got)
	}
	verifyAuthenticodeFile = func(*uint16, windows.Handle) (string, error) { return "Mallory Inc", nil }
	if got := VerifyAuthenticodeWithSHA256(path, AnthropicPublishers); got.Verified || got.SHA256 != "" {
		t.Fatalf("another signer = %+v, want refused without a digest", got)
	}
}
