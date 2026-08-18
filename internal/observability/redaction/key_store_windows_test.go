// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package redaction

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

func TestWindowsCorrelationKeyRetriesTransientBusyHandle(t *testing.T) {
	// Repeat the timing-sensitive first reopen so a future removal of the
	// trusted-inheritance repair cannot disappear as a low-frequency flake.
	for attempt := 0; attempt < 8; attempt++ {
		dir := t.TempDir()
		created, err := LoadOrCreateCorrelationKey(dir)
		if err != nil {
			t.Fatalf("attempt %d create key: %v", attempt, err)
		}
		path, err := windows.UTF16PtrFromString(filepath.Join(dir, correlationKeyFilename))
		if err != nil {
			t.Fatal(err)
		}
		handle, err := openWindowsCorrelationHandle(func() (windows.Handle, error) {
			return windows.CreateFile(
				path,
				windows.GENERIC_READ,
				0,
				nil,
				windows.OPEN_EXISTING,
				windows.FILE_ATTRIBUTE_NORMAL,
				0,
			)
		}, false)
		if err != nil {
			t.Fatalf("attempt %d open incompatible handle: %v", attempt, err)
		}
		released := make(chan error, 1)
		go func() {
			time.Sleep(20 * time.Millisecond)
			released <- windows.CloseHandle(handle)
		}()

		loaded, loadErr := LoadOrCreateCorrelationKey(dir)
		closeErr := <-released
		if closeErr != nil {
			t.Fatalf("attempt %d close incompatible handle: %v", attempt, closeErr)
		}
		if loadErr != nil {
			t.Fatalf("attempt %d load after transient sharing violation: %v", attempt, loadErr)
		}
		createdMaterial, createdOK := created.Material()
		loadedMaterial, loadedOK := loaded.Material()
		if !createdOK || !loadedOK || created.ID() != loaded.ID() || createdMaterial != loadedMaterial {
			t.Fatalf("attempt %d key changed while retrying the transient sharing violation", attempt)
		}
		assertNoWindowsCorrelationTemps(t, dir)
	}
}

func TestWindowsCorrelationHandleRetryLoopIsExercised(t *testing.T) {
	const want = windows.Handle(0x1234)
	attempts := 0
	handle, err := openWindowsCorrelationHandle(func() (windows.Handle, error) {
		attempts++
		if attempts < 3 {
			return 0, windows.ERROR_SHARING_VIOLATION
		}
		return want, nil
	}, false)
	if err != nil {
		t.Fatalf("retry transient sharing violation: %v", err)
	}
	if handle != want || attempts != 3 {
		t.Fatalf("handle=%v attempts=%d, want handle=%v attempts=3", handle, attempts, want)
	}
}

func TestWindowsCorrelationKeyRetryableErrorClassification(t *testing.T) {
	tests := []struct {
		name              string
		err               error
		retryAccessDenied bool
		want              bool
	}{
		{name: "sharing violation", err: windows.ERROR_SHARING_VIOLATION, want: true},
		{name: "lock violation", err: windows.ERROR_LOCK_VIOLATION, want: true},
		{name: "delete pending", err: windows.ERROR_DELETE_PENDING, want: true},
		{name: "leaf access denied", err: windows.ERROR_ACCESS_DENIED, retryAccessDenied: true, want: true},
		{name: "directory access denied", err: windows.ERROR_ACCESS_DENIED, want: false},
		{name: "missing", err: windows.ERROR_FILE_NOT_FOUND, retryAccessDenied: true, want: false},
		{name: "other", err: errors.New("other"), retryAccessDenied: true, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := windowsCorrelationOpenRetryable(test.err, test.retryAccessDenied); got != test.want {
				t.Fatalf("retryable = %t, want %t", got, test.want)
			}
		})
	}
}

func TestWindowsCorrelationKeyRepairsTrustedUnprotectedDACL(t *testing.T) {
	dir := t.TempDir()
	created, err := LoadOrCreateCorrelationKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, correlationKeyFilename)
	initial, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || initial == nil {
		t.Fatalf("read initial descriptor: %v", err)
	}
	initialControl, _, err := initial.Control()
	if err != nil {
		t.Fatal(err)
	}
	if initialControl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("freshly installed key DACL is not protected")
	}
	setWindowsCorrelationTrustedUnprotectedDACL(t, path)

	loaded, err := LoadOrCreateCorrelationKey(dir)
	if err != nil {
		t.Fatalf("repair trusted inherited DACL: %v", err)
	}
	createdMaterial, createdOK := created.Material()
	loadedMaterial, loadedOK := loaded.Material()
	if !createdOK || !loadedOK || created.ID() != loaded.ID() || createdMaterial != loadedMaterial {
		t.Fatal("repair changed correlation key material")
	}
	repaired, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || repaired == nil {
		t.Fatalf("read repaired descriptor: %v", err)
	}
	control, _, err := repaired.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("trusted inherited DACL was not re-protected")
	}
}

func TestWindowsCorrelationKeyFreshProcessRestartRepairsTrustedDACL(t *testing.T) {
	const (
		dirEnv = "DEFENSECLAW_TEST_CORRELATION_RESTART_DIR"
		idEnv  = "DEFENSECLAW_TEST_CORRELATION_RESTART_ID"
	)
	if dir := os.Getenv(dirEnv); dir != "" {
		loaded, err := LoadOrCreateCorrelationKey(dir)
		if err != nil {
			t.Fatalf("fresh-process load: %v", err)
		}
		if loaded.ID() != os.Getenv(idEnv) {
			t.Fatalf("fresh-process key ID = %q, want %q", loaded.ID(), os.Getenv(idEnv))
		}
		return
	}

	dir := t.TempDir()
	created, err := LoadOrCreateCorrelationKey(dir)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	path := filepath.Join(dir, correlationKeyFilename)
	setWindowsCorrelationTrustedUnprotectedDACL(t, path)

	command := exec.Command(
		os.Args[0],
		"-test.run=^TestWindowsCorrelationKeyFreshProcessRestartRepairsTrustedDACL$",
		"-test.v",
	)
	command.Env = append(os.Environ(), dirEnv+"="+dir, idEnv+"="+created.ID())
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fresh-process restart failed: %v\n%s", err, output)
	}

	repaired, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || repaired == nil {
		t.Fatalf("read repaired descriptor: %v", err)
	}
	control, _, err := repaired.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("fresh-process restart did not protect the trusted DACL")
	}
	loaded, err := LoadOrCreateCorrelationKey(dir)
	if err != nil {
		t.Fatalf("load after fresh-process repair: %v", err)
	}
	createdMaterial, createdOK := created.Material()
	loadedMaterial, loadedOK := loaded.Material()
	if !createdOK || !loadedOK || created.ID() != loaded.ID() || createdMaterial != loadedMaterial {
		t.Fatal("fresh-process restart changed correlation key material")
	}
}

func setWindowsCorrelationTrustedUnprotectedDACL(t *testing.T, path string) {
	t.Helper()
	descriptor, err := windowsCorrelationProtectedSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("resolve canonical DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsCorrelationKeyDoesNotRepairUntrustedUnprotectedDACL(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateCorrelationKey(dir); err != nil {
		t.Fatal(err)
	}
	current, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	dacl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		windowsCorrelationAccess(current.User.Sid, windows.GENERIC_ALL),
		windowsCorrelationAccess(system, windows.GENERIC_ALL),
		windowsCorrelationAccess(administrators, windows.GENERIC_ALL),
		windowsCorrelationAccess(everyone, windows.GENERIC_READ),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, correlationKeyFilename)
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || before == nil {
		t.Fatalf("read untrusted descriptor: %v", err)
	}
	beforeSDDL := before.String()

	if _, err := LoadOrCreateCorrelationKey(dir); !IsKeyStoreError(err, KeyStoreErrorUnsafePermissions) {
		t.Fatalf("error = %v, want unsafe permissions", err)
	}
	after, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || after == nil {
		t.Fatalf("read rejected descriptor: %v", err)
	}
	if after.String() != beforeSDDL {
		t.Fatalf("untrusted descriptor was mutated\nbefore: %s\nafter:  %s", beforeSDDL, after.String())
	}
	control, _, err := after.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED != 0 {
		t.Fatal("untrusted inherited DACL was unexpectedly protected")
	}
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
