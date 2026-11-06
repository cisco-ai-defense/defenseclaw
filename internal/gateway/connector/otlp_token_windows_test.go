// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestLoadOTLPPathTokenWindowsRejectsUntrustedWriteDACL(t *testing.T) {
	writeMasks := []struct {
		name string
		mask windows.ACCESS_MASK
	}{
		{name: "generic_write", mask: windows.GENERIC_WRITE},
		{name: "write_data", mask: windows.FILE_WRITE_DATA},
		{name: "append_data", mask: windows.FILE_APPEND_DATA},
		{name: "write_ea", mask: windows.FILE_WRITE_EA},
		{name: "write_attributes", mask: windows.FILE_WRITE_ATTRIBUTES},
	}
	for _, tc := range writeMasks {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			if _, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex); err != nil {
				t.Fatalf("seed token: %v", err)
			}
			path, err := OTLPPathTokenFilePath(dataDir, OTLPScopeCodex)
			if err != nil {
				t.Fatal(err)
			}
			setOTLPTokenWindowsDACL(t, path, tc.mask, false)

			if token, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err == nil {
				t.Fatalf("LoadOTLPPathToken accepted untrusted %s access; token=%q", tc.name, token)
			}
		})
	}
}

// A write grant on a folder above the data directory is drift on a folder
// DefenseClaw doesn't own: the token keeps working (and can still be minted)
// and the drift is logged instead of turning off telemetry for that user.
func TestLoadOTLPPathTokenWindowsAcceptsWritableAncestor(t *testing.T) {
	for _, tc := range []struct {
		name string
		mask windows.ACCESS_MASK
	}{
		{name: "generic_write", mask: windows.GENERIC_WRITE},
		{name: "write_extended_attributes", mask: windows.FILE_WRITE_EA},
		{name: "write_attributes", mask: windows.FILE_WRITE_ATTRIBUTES},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			ancestor := filepath.Join(root, "ancestor")
			dataDir := filepath.Join(ancestor, "data")
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatalf("create token data path: %v", err)
			}
			seeded, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
			if err != nil {
				t.Fatalf("seed token: %v", err)
			}
			tokenPath, err := OTLPPathTokenFilePath(dataDir, OTLPScopeCodex)
			if err != nil {
				t.Fatalf("resolve token path: %v", err)
			}
			setOTLPTokenWindowsDACL(t, ancestor, tc.mask, true)

			if token, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex); err != nil || token != seeded {
				t.Fatalf("EnsureOTLPPathToken = %q, %v; want the seeded token", token, err)
			}
			if token, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err != nil || token != seeded {
				t.Fatalf("LoadOTLPPathToken = %q, %v; want the seeded token", token, err)
			}
			if err := os.Remove(tokenPath); err != nil {
				t.Fatalf("remove seeded token: %v", err)
			}
			if token, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex); err != nil || token == "" {
				t.Fatalf("EnsureOTLPPathToken after removal = %q, %v; want a new token", token, err)
			}
		})
	}
}

func TestLoadOTLPPathTokenWindowsAllowsCreateChildOnSharedAncestor(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	ancestor := filepath.Join(root, "ancestor")
	dataDir := filepath.Join(ancestor, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("create token data path: %v", err)
	}
	want, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
	if err != nil {
		t.Fatalf("seed token: %v", err)
	}
	setOTLPTokenWindowsDACL(t, ancestor, windows.FILE_WRITE_DATA, true)

	got, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex)
	if err != nil {
		t.Fatalf("LoadOTLPPathToken rejected shared ancestor create-child access: %v", err)
	}
	if got != want {
		t.Fatalf("token = %q, want %q", got, want)
	}
}

func TestOTLPPathTokenWindowsRejectsUnsupportedWriteAllowACETypes(t *testing.T) {
	aceTypes := []struct {
		name   string
		typeID byte
	}{
		{name: "compound", typeID: 0x4},
		{name: "object", typeID: 0x5},
		{name: "callback", typeID: 0x9},
		{name: "callback_object", typeID: 0xB},
	}
	for _, tc := range aceTypes {
		t.Run(tc.name, func(t *testing.T) {
			everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
			if err != nil {
				t.Fatalf("Everyone SID: %v", err)
			}
			acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
				AccessPermissions: windows.GENERIC_WRITE,
				AccessMode:        windows.GRANT_ACCESS,
				Trustee: windows.TRUSTEE{
					TrusteeForm:  windows.TRUSTEE_IS_SID,
					TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
					TrusteeValue: windows.TrusteeValueFromSID(everyone),
				},
			}}, nil)
			if err != nil {
				t.Fatalf("build DACL: %v", err)
			}
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(acl, 0, &ace); err != nil {
				t.Fatalf("get ACE: %v", err)
			}
			ace.Header.AceType = tc.typeID
			if err := hookAPIRejectUntrustedWindowsWriteACEs("token", acl, false, true, false); err == nil ||
				!strings.Contains(err.Error(), "unsupported Windows allow ACE type") {
				t.Fatalf("write-capable ACE type 0x%x error = %v", tc.typeID, err)
			}
		})
	}
}

func TestOTLPPathTokenWindowsSecureCreationAndRepairsBroadDACL(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	for _, test := range []struct {
		name       string
		permission windows.ACCESS_MASK
		// readDrift: an extra reader is permission drift. The token stays
		// usable (accepted and logged) for an unprivileged caller; a
		// privileged publish rotates it, because the reader may already
		// hold the value, and restores its protection.
		readDrift bool
		wantError string
	}{
		{name: "readable", permission: windows.GENERIC_READ, readDrift: true},
		{name: "writeable", permission: windows.GENERIC_WRITE, wantError: "write-like access"},
	} {
		t.Run(test.name, func(t *testing.T) {
			captureManagedResilienceEvents(t)
			dataDir := testenv.PrivateTempDir(t)
			first, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
			if err != nil {
				t.Fatalf("initial EnsureOTLPPathToken: %v", err)
			}
			path, err := OTLPPathTokenFilePath(dataDir, OTLPScopeCodex)
			if err != nil {
				t.Fatal(err)
			}
			if err := setOTLPWindowsBroadDACL(path, test.permission); err != nil {
				t.Fatalf("install broad DACL: %v", err)
			}
			if test.readDrift {
				// The fixture's extra reader is Everyone, which only a
				// verified Secure Client deployment accepts (GAP-0566);
				// TestOTLPPathTokenWindowsRefusesBroadReaderOutsideSecureClient
				// covers standalone and per-user installs.
				originalHost, originalPath := managed.SecureClientHostVerified, managed.SecureClientProcessPathVerified
				t.Cleanup(func() {
					managed.SecureClientHostVerified, managed.SecureClientProcessPathVerified = originalHost, originalPath
				})
				managed.SecureClientHostVerified = func() bool { return true }
				managed.SecureClientProcessPathVerified = func(candidate string) bool {
					return strings.HasPrefix(strings.ToLower(filepath.Clean(candidate)), strings.ToLower(dataDir)+string(filepath.Separator))
				}
				if token, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err != nil || token != first {
					t.Fatalf("LoadOTLPPathToken with an extra reader matched=%v err=%v, want the token", token == first, err)
				}
				originalCanRepair := windowsManagedCanRepair
				t.Cleanup(func() { windowsManagedCanRepair = originalCanRepair })
				windowsManagedCanRepair = func() bool { return false }
				second, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
				if err != nil || second != first {
					t.Fatalf("unprivileged EnsureOTLPPathToken with an extra reader matched=%v err=%v, want the same token", second == first, err)
				}
				windowsManagedCanRepair = func() bool { return true }
				rotated, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
				if err != nil || rotated == "" || rotated == first {
					t.Fatalf("privileged EnsureOTLPPathToken with an extra reader rotated=%v err=%v, want a new token", rotated != first, err)
				}
				if replace, err := otlpPathTokenNeedsSecureReplacement(path); err != nil || replace {
					t.Fatalf("privileged publish left the extra reader: replace=%v err=%v", replace, err)
				}
				if loaded, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err != nil || loaded != rotated {
					t.Fatalf("load rotated token: matched=%v err=%v", loaded == rotated, err)
				}
				return
			}
			if token, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err == nil ||
				token != "" || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("LoadOTLPPathToken token=%q err=%v, want %q rejection", token, err, test.wantError)
			}

			// A credential an untrusted principal could overwrite must be
			// rotated, not merely have its ACL tightened while retaining
			// bytes that principal may have planted.
			second, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
			if err != nil {
				t.Fatalf("repair EnsureOTLPPathToken: %v", err)
			}
			if second == "" || second == first {
				t.Fatal("repair did not rotate the exposed scoped credential")
			}
			loaded, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex)
			if err != nil || loaded != second {
				t.Fatalf("load repaired token: matched=%v err=%v", loaded == second, err)
			}
		})
	}
}

// GAP-0566: outside a verified Secure Client deployment a credential every
// local account can read is refused, and Ensure rotates it even without
// privilege; a narrow extra reader stays accepted.
func TestOTLPPathTokenWindowsRefusesBroadReaderOutsideSecureClient(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	captureManagedResilienceEvents(t)
	originalSecureClient := SecureClientDeploymentVerified
	t.Cleanup(func() { SecureClientDeploymentVerified = originalSecureClient })
	SecureClientDeploymentVerified = func() bool { return false }
	originalCanRepair := windowsManagedCanRepair
	t.Cleanup(func() { windowsManagedCanRepair = originalCanRepair })
	windowsManagedCanRepair = func() bool { return false }

	dataDir := testenv.PrivateTempDir(t)
	first, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
	if err != nil {
		t.Fatalf("initial EnsureOTLPPathToken: %v", err)
	}
	path, err := OTLPPathTokenFilePath(dataDir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	if err := setOTLPWindowsBroadDACL(path, windows.GENERIC_READ); err != nil {
		t.Fatalf("install broad DACL: %v", err)
	}
	if token, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err == nil || token != "" ||
		!strings.Contains(err.Error(), "every local account can read") {
		t.Fatalf("LoadOTLPPathToken with an Everyone reader token=%v err=%v, want the broad-reader refusal", token != "", err)
	}
	rotated, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
	if err != nil || rotated == "" || rotated == first {
		t.Fatalf("EnsureOTLPPathToken with an Everyone reader rotated=%v err=%v, want a new token", rotated != first, err)
	}
	if loaded, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err != nil || loaded != rotated {
		t.Fatalf("load rotated token: matched=%v err=%v", loaded == rotated, err)
	}

	// A narrow extra reader (one named account) is still drift that is
	// accepted and logged.
	narrow, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	if err := addOTLPWindowsReaderForTest(path, narrow); err != nil {
		t.Fatalf("add narrow reader: %v", err)
	}
	if loaded, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err != nil || loaded != rotated {
		t.Fatalf("LoadOTLPPathToken with a narrow extra reader matched=%v err=%v, want the token", loaded == rotated, err)
	}
}

func TestOTLPPathTokenWindowsRevokesPerUserTokenOnSecureClientHost(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	previousHost, previousPath := managed.SecureClientHostVerified, managed.SecureClientProcessPathVerified
	t.Cleanup(func() {
		managed.SecureClientHostVerified, managed.SecureClientProcessPathVerified = previousHost, previousPath
	})
	managed.SecureClientHostVerified = func() bool { return true }
	managed.SecureClientProcessPathVerified = func(string) bool { return false }
	previousCanRepair := windowsManagedCanRepair
	t.Cleanup(func() { windowsManagedCanRepair = previousCanRepair })
	windowsManagedCanRepair = func() bool { return false }

	dataDir := testenv.PrivateTempDir(t)
	first, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	path, err := OTLPPathTokenFilePath(dataDir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	if err := setOTLPWindowsBroadDACL(path, windows.GENERIC_READ); err != nil {
		t.Fatal(err)
	}
	if token, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err == nil || token != "" {
		t.Fatal("a per-user token remained readable after its credential was broadly readable")
	}
	rotated, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
	if err != nil || rotated == "" || rotated == first {
		t.Fatalf("per-user token rotation failed: rotated=%v err=%v", rotated != first, err)
	}
}

func TestWindowsCredentialsLocalAccountReadAndExecuteOnly(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	previousHost, previousPath := managed.SecureClientHostVerified, managed.SecureClientProcessPathVerified
	t.Cleanup(func() {
		managed.SecureClientHostVerified, managed.SecureClientProcessPathVerified = previousHost, previousPath
	})
	managed.SecureClientHostVerified, managed.SecureClientProcessPathVerified = nil, nil
	localAccount, err := windows.CreateWellKnownSid(windows.WinLocalAccountSid)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		ensure func(string) (string, error)
		load   func(string) (string, error)
		path   func(string) (string, error)
	}{
		{
			name:   "OTLP path token",
			ensure: func(dir string) (string, error) { return EnsureOTLPPathToken(dir, OTLPScopeCodex) },
			load:   func(dir string) (string, error) { return LoadOTLPPathToken(dir, OTLPScopeCodex) },
			path:   func(dir string) (string, error) { return OTLPPathTokenFilePath(dir, OTLPScopeCodex) },
		},
		{
			name:   "hook API token",
			ensure: func(dir string) (string, error) { return EnsureHookAPIToken(dir, "codex") },
			load:   func(dir string) (string, error) { return LoadHookAPIToken(dir, "codex") },
			path:   func(dir string) (string, error) { return HookAPITokenFilePath(dir, "codex") },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			first, err := tc.ensure(dataDir)
			if err != nil {
				t.Fatalf("create credential: %v", err)
			}
			path, err := tc.path(dataDir)
			if err != nil {
				t.Fatal(err)
			}
			if err := addOTLPWindowsReaderForTest(path, localAccount); err != nil {
				t.Fatalf("add local-account reader: %v", err)
			}
			if token, err := tc.load(dataDir); token != "" || !errors.Is(err, ErrCredentialDisclosed) {
				t.Fatalf("load readable credential: returned=%v err=%v", token != "", err)
			}
			rotated, err := tc.ensure(dataDir)
			if err != nil || rotated == "" || rotated == first {
				t.Fatalf("refresh readable credential: rotated=%v err=%v", rotated != first, err)
			}
			if err := setOTLPWindowsBroadDACL(path, windows.GENERIC_EXECUTE); err != nil {
				t.Fatalf("set execute-only DACL: %v", err)
			}
			if loaded, err := tc.load(dataDir); err != nil || loaded != rotated {
				t.Fatalf("load execute-only credential: matched=%v err=%v", loaded == rotated, err)
			}
			if kept, err := tc.ensure(dataDir); err != nil || kept != rotated {
				t.Fatalf("refresh execute-only credential: matched=%v err=%v", kept == rotated, err)
			}
		})
	}
}

func TestOTLPPathTokenWindowsPrivilegedRepairKeepsUndisclosedValue(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	for _, tc := range []struct {
		name string
		mask windows.ACCESS_MASK
	}{
		{name: "execute only", mask: windows.GENERIC_EXECUTE},
		{name: "attributes only", mask: windows.FILE_READ_ATTRIBUTES},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previousRepair := windowsManagedCanRepair
			windowsManagedCanRepair = func() bool { return true }
			t.Cleanup(func() { windowsManagedCanRepair = previousRepair })

			dataDir := testenv.PrivateTempDir(t)
			first, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
			if err != nil {
				t.Fatalf("create token: %v", err)
			}
			path, err := OTLPPathTokenFilePath(dataDir, OTLPScopeCodex)
			if err != nil {
				t.Fatal(err)
			}
			if err := setOTLPWindowsBroadDACL(path, tc.mask); err != nil {
				t.Fatalf("set token permissions: %v", err)
			}
			if loaded, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err != nil || loaded != first {
				t.Fatalf("load token with permission drift: same=%v err=%v", loaded == first, err)
			}
			after, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex)
			if err != nil || after != first {
				t.Fatalf("repair token: same=%v err=%v", after == first, err)
			}
			if replace, err := otlpPathTokenNeedsSecureReplacement(path); err != nil || replace {
				t.Fatalf("repair left permission drift: replace=%v err=%v", replace, err)
			}
			if loaded, err := LoadOTLPPathToken(dataDir, OTLPScopeCodex); err != nil || loaded != after {
				t.Fatalf("load repaired token: same=%v err=%v", loaded == after, err)
			}
		})
	}
}

func TestWindowsBroadCredentialReaderRequiresDataAccess(t *testing.T) {
	localAccount, err := windows.CreateWellKnownSid(windows.WinLocalAccountSid)
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		sid       *windows.SID
		mask      windows.ACCESS_MASK
		disclosed bool
	}{
		{name: "local account data read", sid: localAccount, mask: windows.GENERIC_READ, disclosed: true},
		{name: "everyone data read", sid: everyone, mask: windows.FILE_READ_DATA, disclosed: true},
		{name: "everyone execute only", sid: everyone, mask: windows.GENERIC_EXECUTE},
		{name: "everyone attributes only", sid: everyone, mask: windows.FILE_READ_ATTRIBUTES},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
				AccessPermissions: tc.mask,
				AccessMode:        windows.GRANT_ACCESS,
				Trustee: windows.TRUSTEE{
					TrusteeForm:  windows.TRUSTEE_IS_SID,
					TrusteeValue: windows.TrusteeValueFromSID(tc.sid),
				},
			}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(acl, 0, &ace); err != nil {
				t.Fatal(err)
			}
			ace.Mask = tc.mask
			if err := otlpWindowsBroadReader("credential", acl); errors.Is(err, ErrCredentialDisclosed) != tc.disclosed {
				t.Fatalf("disclosed=%v, err=%v; want disclosed=%v", errors.Is(err, ErrCredentialDisclosed), err, tc.disclosed)
			}
		})
	}
}

// addOTLPWindowsReaderForTest adds a read entry for sid to path's DACL.
func addOTLPWindowsReaderForTest(path string, sid *windows.SID) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	current, _, err := sd.DACL()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_READ,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, current)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// A data-free lock with an extra reader is drift, not a reason to stop the
// lifecycle: the callback runs and the drift is logged. A write grant still
// refuses, because another principal could replace the lock.
func TestOwnedFileLockWindowsAcceptsExtraReaderRejectsWriter(t *testing.T) {
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	captureManagedResilienceEvents(t)
	lockPath := filepath.Join(testenv.PrivateTempDir(t), ".codex-lifecycle.lock")
	if err := withOwnedFileLock(lockPath, func() error { return nil }); err != nil {
		t.Fatalf("create secure lock: %v", err)
	}
	if err := setOTLPWindowsBroadDACL(lockPath, windows.GENERIC_READ); err != nil {
		t.Fatalf("install broad lock DACL: %v", err)
	}
	ran := false
	if err := withOwnedFileLock(lockPath, func() error {
		ran = true
		return nil
	}); err != nil || !ran {
		t.Fatalf("withOwnedFileLock with an extra reader ran=%v err=%v, want accepted", ran, err)
	}

	if err := setOTLPWindowsBroadDACL(lockPath, windows.GENERIC_WRITE); err != nil {
		t.Fatalf("install writable lock DACL: %v", err)
	}
	if err := withOwnedFileLock(lockPath, func() error {
		t.Fatal("callback ran with a lock another principal can write")
		return nil
	}); err == nil || !strings.Contains(err.Error(), "write-like access") {
		t.Fatalf("withOwnedFileLock err=%v, want write-access rejection", err)
	}
}

func TestRemoveOTLPPathTokenWindowsRevokesBroadDACL(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	if _, err := EnsureOTLPPathToken(dataDir, OTLPScopeCodex); err != nil {
		t.Fatalf("seed token: %v", err)
	}
	path, err := OTLPPathTokenFilePath(dataDir, OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	if err := setOTLPWindowsBroadDACL(path, windows.GENERIC_READ|windows.GENERIC_WRITE); err != nil {
		t.Fatalf("install broad token DACL: %v", err)
	}
	if err := RemoveOTLPPathToken(dataDir, OTLPScopeCodex); err != nil {
		t.Fatalf("revoke exposed token: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("exposed token still exists after revoke: %v", err)
	}
}

func TestOwnedFileLockWindowsRejectsReparsePoint(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	target := filepath.Join(dir, "target.lock")
	if err := withOwnedFileLock(target, func() error { return nil }); err != nil {
		t.Fatalf("create target lock: %v", err)
	}
	link := filepath.Join(dir, ".codex-lifecycle.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("Windows symlink privilege unavailable: %v", err)
	}
	if err := withOwnedFileLock(link, func() error {
		t.Fatal("callback ran through a reparse-point lock")
		return nil
	}); err == nil || !strings.Contains(err.Error(), "reparse points are not allowed") {
		t.Fatalf("withOwnedFileLock err=%v, want reparse rejection", err)
	}
}

func setOTLPWindowsBroadDACL(path string, untrustedPermission windows.ACCESS_MASK) error {
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(currentUser.User.Sid),
			},
		},
		{
			AccessPermissions: untrustedPermission,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(everyone),
			},
		},
	}, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
}

func setOTLPTokenWindowsDACL(t *testing.T, path string, untrustedMask windows.ACCESS_MASK, inheritOwner bool) {
	t.Helper()
	inheritance := uint32(windows.NO_INHERITANCE)
	if inheritOwner {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("current token user: %v", err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("Everyone SID: %v", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(currentUser.User.Sid),
			},
		},
		{
			AccessPermissions: untrustedMask,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(everyone),
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("build DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatalf("set DACL: %v", err)
	}
}
