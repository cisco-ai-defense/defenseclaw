//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

func TestAuditDBWindowsAllowsOnlyExactPinnedGatewayServiceSID(t *testing.T) {
	serviceSID, err := windows.StringToSid("S-1-5-80-111-222-333-444-555")
	if err != nil {
		t.Fatal(err)
	}
	foreignSID, err := windows.StringToSid("S-1-5-80-555-444-333-222-111")
	if err != nil {
		t.Fatal(err)
	}
	const serviceName = "DefenseClawCertGateway_AuditFixture"
	t.Setenv(connector.WindowsGatewayServiceNameEnv, serviceName)
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\`+serviceName)
	previous := auditDBWindowsServiceAccountSID
	auditDBWindowsServiceAccountSID = func(account string) (*windows.SID, error) {
		if account != `NT SERVICE\`+serviceName {
			t.Fatalf("service account = %q", account)
		}
		return serviceSID, nil
	}
	t.Cleanup(func() { auditDBWindowsServiceAccountSID = previous })

	resolved, err := auditDBWindowsPinnedGatewayServiceSID()
	if err != nil || resolved == nil || !resolved.Equals(serviceSID) {
		t.Fatalf("pinned gateway SID = %v, %v", resolved, err)
	}
	if !auditDBWindowsTrustedPrincipal(serviceSID, resolved) {
		t.Fatal("exact pinned gateway service SID was not trusted")
	}
	if auditDBWindowsTrustedPrincipal(foreignSID, resolved) {
		t.Fatal("foreign NT SERVICE SID was broadly trusted")
	}

	dacl, err := auditDBWindowsProtectedDACL(true)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			t.Fatal(err)
		}
		if ace != nil && ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if sid.Equals(serviceSID) {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatal("protected audit DACL omitted exact pinned gateway service SID")
	}
}

func TestAuditDBWindowsRejectsIncompleteOrMismatchedGatewayPins(t *testing.T) {
	const serviceName = "DefenseClawCertGateway_AuditFixture"
	for _, test := range []struct {
		name    string
		account string
		service string
	}{
		{name: "missing account", service: serviceName},
		{name: "missing service", account: `NT SERVICE\` + serviceName},
		{name: "foreign account", account: `NT SERVICE\OtherGateway`, service: serviceName},
		{name: "malformed service", account: `NT SERVICE\Bad/Name`, service: "Bad/Name"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(managed.WindowsServiceAccountEnv, test.account)
			t.Setenv(connector.WindowsGatewayServiceNameEnv, test.service)
			if _, err := auditDBWindowsPinnedGatewayServiceSID(); err == nil {
				t.Fatal("invalid gateway identity pins were accepted")
			}
		})
	}

	t.Run("resolution failure", func(t *testing.T) {
		t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\`+serviceName)
		t.Setenv(connector.WindowsGatewayServiceNameEnv, serviceName)
		previous := auditDBWindowsServiceAccountSID
		auditDBWindowsServiceAccountSID = func(string) (*windows.SID, error) {
			return nil, errors.New("fixture SID unavailable")
		}
		t.Cleanup(func() { auditDBWindowsServiceAccountSID = previous })
		if _, err := auditDBWindowsPinnedGatewayServiceSID(); err == nil {
			t.Fatal("unresolvable exact gateway service SID was accepted")
		}
	})

	// Cover the both-unset branch: an ordinary (non-enterprise-managed)
	// Windows deployment leaves both env vars unset and expects
	// auditDBWindowsPinnedGatewayServiceSID to return (nil, nil) —
	// the "no pin" case. A regression here would convert every such
	// host into a hard audit failure.
	t.Run("both unset returns no pin", func(t *testing.T) {
		t.Setenv(managed.WindowsServiceAccountEnv, "")
		t.Setenv(connector.WindowsGatewayServiceNameEnv, "")
		sid, err := auditDBWindowsPinnedGatewayServiceSID()
		if err != nil {
			t.Fatalf("both-unset returned error: %v", err)
		}
		if sid != nil {
			t.Fatalf("both-unset returned SID %v, want nil", sid)
		}
	})
}

func TestAuditDBWindowsCreatesProtectedPath(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "protected")
	path := filepath.Join(parent, "audit.db")
	db, err := openHardenedAuditSQLite(path, auditDBPathHooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	for _, candidate := range []struct {
		path            string
		directory       bool
		protectChildren bool
	}{
		{path: parent, directory: true, protectChildren: true},
		{path: path, directory: false, protectChildren: true},
	} {
		info, err := os.Stat(candidate.path)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateAuditDBPlatformTrust(
			candidate.path, info, candidate.directory, candidate.protectChildren,
		); err != nil {
			t.Fatalf("protected path %s failed trust validation: %v", candidate.path, err)
		}
	}
}

func TestAuditDBWindowsRejectsUntrustedWriteACL(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "protected")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := secureAuditDBPlatformPath(directory, true); err != nil {
		t.Fatal(err)
	}
	grantEveryoneAuditDBWindowsAccess(t, directory, windows.GENERIC_WRITE, true)
	assertAuditDBPathError(t, filepath.Join(directory, "audit.db"), "untrusted Windows principal")
}

func TestAuditDBWindowsRejectsInheritedReadAccessForSQLiteSidecars(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "protected")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := secureAuditDBPlatformPath(directory, true); err != nil {
		t.Fatal(err)
	}
	grantEveryoneAuditDBWindowsAccess(t, directory, windows.GENERIC_READ, true)
	assertAuditDBPathError(t, filepath.Join(directory, "audit.db"), "untrusted Windows principal")
}

func TestAuditDBWindowsRejectsMutableAncestor(t *testing.T) {
	grandparent := filepath.Join(t.TempDir(), "shared")
	parent := filepath.Join(grandparent, "defenseclaw")
	if err := os.Mkdir(grandparent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := secureAuditDBPlatformPath(grandparent, true); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := secureAuditDBPlatformPath(parent, true); err != nil {
		t.Fatal(err)
	}
	const fileDeleteChild windows.ACCESS_MASK = 0x40
	grantEveryoneAuditDBWindowsAccess(t, grandparent, fileDeleteChild, true)
	assertAuditDBPathError(t, filepath.Join(parent, "audit.db"), "untrusted Windows principal")
}

func TestAuditDBWindowsRejectsPermissiveExistingLeaf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := openHardenedAuditSQLite(path, auditDBPathHooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	grantEveryoneAuditDBWindowsAccess(t, path, windows.GENERIC_READ|windows.GENERIC_WRITE, false)
	assertAuditDBPathError(t, path, "untrusted Windows principal")
}

func TestAuditDBWindowsRejectsStaleSidecarReadACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := openHardenedAuditSQLite(path, auditDBPathHooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	sidecar := path + "-journal"
	if err := os.WriteFile(sidecar, []byte("confidential pages"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secureAuditDBPlatformPath(sidecar, false); err != nil {
		t.Fatal(err)
	}
	grantEveryoneAuditDBWindowsAccess(t, sidecar, windows.GENERIC_READ, false)
	prepared, err := prepareAuditDatabasePath(path, auditDBPathHooks{})
	if prepared != nil {
		prepared.close()
	}
	if err == nil || !strings.Contains(err.Error(), "SQLite sidecar -journal") {
		t.Fatalf("stale sidecar ACL error = %v", err)
	}
}

func TestAuditDBWindowsSecuresTrustedSidecarThroughPinnedHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protected", "audit.db")
	db, err := openHardenedAuditSQLite(path, auditDBPathHooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	sidecar := path + "-wal"
	if err := os.WriteFile(sidecar, []byte("confidential pages"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := secureAuditDBSQLiteSidecars(path, auditDBPathHooks{}); err != nil {
		t.Fatalf("secure trusted SQLite sidecar through pinned handle: %v", err)
	}
	info, err := os.Stat(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAuditDBPlatformTrust(sidecar, info, false, true); err != nil {
		t.Fatalf("secured sidecar trust validation: %v", err)
	}
}

func TestAuditDBWindowsRejectsLeafReparsePoint(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.db")
	path := filepath.Join(directory, "audit.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("creating a Windows symlink requires unavailable privilege: %v", err)
	}
	assertAuditDBPathError(t, path, "symbolic link")
}

func TestAuditDBWindowsRejectsParentReparsePoint(t *testing.T) {
	directory := t.TempDir()
	realParent := filepath.Join(directory, "real")
	aliasParent := filepath.Join(directory, "alias")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realParent, aliasParent); err != nil {
		t.Skipf("creating a Windows directory symlink requires unavailable privilege: %v", err)
	}
	assertAuditDBPathError(t, filepath.Join(aliasParent, "audit.db"), "symbolic link")
}

func TestAuditDBWindowsRejectsWrongOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := openHardenedAuditSQLite(path, auditDBPathHooks{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		everyone,
		nil,
		nil,
		nil,
	); err != nil {
		t.Skipf("changing Windows owner requires unavailable privilege: %v", err)
	}
	defer windows.SetNamedSecurityInfo( //nolint:errcheck
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		currentUser.User.Sid,
		nil,
		nil,
		nil,
	)
	assertAuditDBPathError(t, path, "owner")
}

func TestAuditDBWindowsTrustRejectsWorldOwner(t *testing.T) {
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	if auditDBWindowsTrustedPrincipal(everyone) {
		t.Fatal("Everyone SID must never be a trusted audit DB owner")
	}
}

func grantEveryoneAuditDBWindowsAccess(
	t *testing.T,
	path string,
	access windows.ACCESS_MASK,
	directory bool,
) {
	t.Helper()
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = uint32(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
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
			AccessPermissions: access,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(everyone),
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
}
