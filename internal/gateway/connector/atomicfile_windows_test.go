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

func TestAtomicWritePrivatePublicationDoesNotPreserveRacedDestinationDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := atomicWriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var attackerIdentity string
	streamCreated := false
	atomicFileBeforePrivatePublish = func(destination string) error {
		if err := os.WriteFile(destination, []byte("attacker\n"), 0o600); err != nil {
			return err
		}
		if err := setAtomicFileUnsafeReadDACL(destination); err != nil {
			return err
		}
		attacker, err := os.Open(destination)
		if err != nil {
			return err
		}
		attackerIdentity, err = atomicTransformOpenFileIdentity(attacker)
		closeErr := attacker.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err := os.WriteFile(destination+":attacker-metadata", []byte("unsafe"), 0o600); err == nil {
			streamCreated = true
		} else if !errors.Is(err, windows.ERROR_INVALID_NAME) && !errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
			return err
		}
		return nil
	}
	t.Cleanup(func() { atomicFileBeforePrivatePublish = nil })

	if err := atomicWriteFile(path, []byte("managed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if attackerIdentity == "" {
		t.Fatal("private-publication race hook was not invoked")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "managed\n" {
		t.Fatalf("published bytes=%q error=%v", got, err)
	}
	published, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	publishedIdentity, identityErr := atomicTransformOpenFileIdentity(published)
	closeErr := published.Close()
	if identityErr != nil || closeErr != nil {
		t.Fatalf("published identity error=%v close=%v", identityErr, closeErr)
	}
	if attackerIdentity == publishedIdentity {
		t.Fatal("private publication reused the raced destination inode")
	}
	if err := safefile.ValidatePrivateFile(path); err != nil {
		t.Fatalf("published private file retained raced unsafe DACL: %v", err)
	}
	if streamCreated {
		if metadata, err := os.ReadFile(path + ":attacker-metadata"); err == nil {
			t.Fatalf("published private file retained raced alternate stream %q", metadata)
		}
	}
}

func setAtomicFileUnsafeReadDACL(path string) error {
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return err
	}
	entry := func(sid *windows.SID, sidType windows.TRUSTEE_TYPE, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: mask,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  sidType,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		entry(currentUser.User.Sid, windows.TRUSTEE_IS_USER, windows.GENERIC_ALL),
		entry(everyone, windows.TRUSTEE_IS_WELL_KNOWN_GROUP, windows.GENERIC_READ),
	}, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil,
	)
}
