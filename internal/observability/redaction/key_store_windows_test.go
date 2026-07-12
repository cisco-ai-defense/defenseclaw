// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package redaction

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsCorrelationKeyCreateLoadAndProtectedDACL(t *testing.T) {
	dir := t.TempDir()
	created, err := LoadOrCreateCorrelationKey(dir)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	loaded, err := LoadOrCreateCorrelationKey(dir)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	createdMaterial, createdOK := created.Material()
	loadedMaterial, loadedOK := loaded.Material()
	if !createdOK || !loadedOK || created.ID() != loaded.ID() || createdMaterial != loadedMaterial {
		t.Fatal("created and loaded keys differ")
	}
	path := filepath.Join(dir, correlationKeyFilename)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != hashV1KeySize {
		t.Fatalf("key size = %d", info.Size())
	}
	assertNoWindowsCorrelationTemps(t, dir)
}

func TestWindowsCorrelationKeyConcurrentCreatorsConverge(t *testing.T) {
	dir := t.TempDir()
	const creators = 24
	start := make(chan struct{})
	results := make(chan CorrelationKey, creators)
	errorsCh := make(chan error, creators)
	var group sync.WaitGroup
	group.Add(creators)
	for range creators {
		go func() {
			defer group.Done()
			<-start
			key, err := LoadOrCreateCorrelationKey(dir)
			if err != nil {
				errorsCh <- err
				return
			}
			results <- key
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		t.Errorf("creator: %v", err)
	}
	var winner CorrelationKey
	first := true
	for key := range results {
		if first {
			winner, first = key, false
			continue
		}
		winnerMaterial, winnerOK := winner.Material()
		material, ok := key.Material()
		if !winnerOK || !ok || winner.ID() != key.ID() || winnerMaterial != material {
			t.Fatal("concurrent creators did not converge")
		}
	}
	if first {
		t.Fatal("no creator returned a key")
	}
	assertNoWindowsCorrelationTemps(t, dir)
}

func TestWindowsCorrelationKeyRejectsUntrustedReadACL(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateCorrelationKey(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, correlationKeyFilename)
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		windowsCorrelationAccess(current.User.Sid, windows.GENERIC_ALL),
		windowsCorrelationAccess(everyone, windows.GENERIC_READ),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCorrelationKey(dir); !IsKeyStoreError(err, KeyStoreErrorUnsafePermissions) {
		t.Fatalf("error = %v, want unsafe permissions", err)
	}
}

func TestWindowsCorrelationKeyRejectsInvalidLength(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateCorrelationKey(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, correlationKeyFilename)
	if err := os.WriteFile(path, bytes.Repeat([]byte{0x44}, hashV1KeySize-1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCorrelationKey(dir); !IsKeyStoreError(err, KeyStoreErrorInvalidLength) {
		t.Fatalf("error = %v, want invalid length", err)
	}
}

func TestWindowsCorrelationKeyPostMoveFailureLeavesLoadableKey(t *testing.T) {
	dir := t.TempDir()
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x4a}, hashV1KeySize+keyTempRandomBytes))
	hooks := keyStoreHooks{afterLink: func() error { return errors.New("injected post-move failure") }}
	if _, err := loadOrCreateCorrelationKeyPlatform(dir, entropy, hooks); !IsKeyStoreError(err, KeyStoreErrorSync) {
		t.Fatalf("error = %v, want sync failure", err)
	}
	key, err := LoadOrCreateCorrelationKey(dir)
	if err != nil {
		t.Fatalf("load installed key: %v", err)
	}
	material, ok := key.Material()
	var want [hashV1KeySize]byte
	for index := range want {
		want[index] = 0x4a
	}
	if !ok || material != want {
		t.Fatal("installed key changed after post-move failure")
	}
	assertNoWindowsCorrelationTemps(t, dir)
}

func TestWindowsCorrelationKeyRejectsReparsePoint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, bytes.Repeat([]byte{0x33}, hashV1KeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, correlationKeyFilename)); err != nil {
		t.Skipf("Windows symlink privilege unavailable: %v", err)
	}
	if _, err := LoadOrCreateCorrelationKey(dir); !IsKeyStoreError(err, KeyStoreErrorUnsafeType) {
		t.Fatalf("error = %v, want unsafe type", err)
	}
}

func TestWindowsCorrelationKeyRejectsReparseDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("Windows symlink privilege unavailable: %v", err)
	}
	if _, err := LoadOrCreateCorrelationKey(alias); !IsKeyStoreError(err, KeyStoreErrorInvalidDataDir) {
		t.Fatalf("error = %v, want invalid data directory", err)
	}
}

func TestWindowsCorrelationKeyInvalidDataDirectory(t *testing.T) {
	if _, err := LoadOrCreateCorrelationKey(""); !IsKeyStoreError(err, KeyStoreErrorInvalidDataDir) {
		t.Fatalf("empty directory error = %v", err)
	}
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateCorrelationKey(file); !IsKeyStoreError(err, KeyStoreErrorInvalidDataDir) {
		t.Fatalf("file directory error = %v", err)
	}
}

func windowsCorrelationAccess(sid *windows.SID, access windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: access,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func assertNoWindowsCorrelationTemps(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, correlationKeyTempPrefix+"*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary key files remain: %v", matches)
	}
}
