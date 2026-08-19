// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ipc

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// defaultGatewayServiceAccount is the NT SERVICE virtual account the
// managed-enterprise gateway service registers under by convention
// ("NT SERVICE\DefenseClawGateway"). Callers can override this at
// runtime by setting managed.WindowsServiceAccountEnv, which the
// installer already pins per spec 002's SCM env plumbing. This
// constant is only the fallback when the env is unset — a
// certification-scoped install with a hashed service name (e.g.
// DefenseClawCertGateway_<10-hex>) sets the env explicitly and
// overrides this default.
const defaultGatewayServiceAccount = `NT SERVICE\DefenseClawGateway`

// aclObjectClass distinguishes the ACL rules applied to the socket's
// parent directory from those applied to the socket file itself.
// Windows' generic-access mapping differs for the two object types —
// GENERIC_READ|GENERIC_WRITE on a directory includes FILE_ADD_FILE
// and FILE_ADD_SUBDIRECTORY, which would let Authenticated Users
// pre-create files inside the IPC directory (including at the socket
// path while the daemon is stopped). See CR
// spec-004:PRRT_kwDORuAK-s6ankzk.
type aclObjectClass int

const (
	aclObjectDirectory aclObjectClass = iota
	aclObjectSocketFile
)

// applyBaselineIPCACL applies the spec 004 baseline hygiene DACL to
// the file at `path`. The DACL is protected — SE_DACL_PROTECTED
// severs inheritance so ancestor ACL policy on ProgramData cannot
// silently over-permit the IPC surface (spec 004 REQ-05).
//
// Four ACEs, no others:
//
//	NT AUTHORITY\SYSTEM               (S-1-5-18)   full control
//	BUILTIN\Administrators            (S-1-5-32-544) full control
//	NT SERVICE\DefenseClawGateway     (via LookupSID) full control
//	NT AUTHORITY\Authenticated Users  (varies by object class,
//	                                   see aclObjectClass docs)
//
// Everything else is denied by omission. Never world-writable
// (Everyone / Anonymous never appear as trustees).
//
// `class` picks a per-object-type mask for Authenticated Users:
//
//   - aclObjectDirectory  ⇒ traverse + list ONLY. Authenticated
//     Users MUST NOT gain FILE_ADD_FILE on the directory or a
//     malicious local user could pre-create a file at the socket
//     path while the daemon is stopped.
//   - aclObjectSocketFile ⇒ read + write. Enough for UDS connect()
//   - gRPC handshake; still refuses WRITE_DAC so the auth-user
//     population cannot rewrite the socket's ACL.
//
// Access boundary rationale: the initial-cut deferred-auth posture
// (spec 004 REQ-06 → REQ-08) does NO accept-time codesign or
// signer-CN validation. The DACL is the only access control. Full
// peer-auth lands in a follow-up spec per parity plan §4.4; until
// then the GA release-gate at authposture_gagate.go refuses a
// release-candidate build in which this posture remains reachable.
func applyBaselineIPCACL(path string, class aclObjectClass) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("ipc: applyBaselineIPCACL: empty path")
	}
	entries, err := baselineIPCACEs(class)
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("ipc: build baseline ACL: %w", err)
	}
	// DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION:
	// write the DACL AND set the protected flag so the object does not
	// inherit any additional ACEs from its parent (spec 004 REQ-05).
	// Owner/group left alone — the file's original owner (usually the
	// process account) retains WRITE_DAC via ownership, which is fine:
	// only SYSTEM/admins can rewrite the process account's DACL from
	// outside anyway.
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("ipc: SetNamedSecurityInfo %s: %w", path, err)
	}
	return nil
}

// baselineIPCACEs builds the four EXPLICIT_ACCESS entries the spec
// requires. Broken out from applyBaselineIPCACL so unit tests can
// assert the entry set independently of the SetNamedSecurityInfo
// call (which needs a real Windows filesystem object). `class`
// selects the per-object-type Authenticated Users mask; see
// applyBaselineIPCACL's docs for the rationale.
func baselineIPCACEs(class aclObjectClass) ([]windows.EXPLICIT_ACCESS, error) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, fmt.Errorf("ipc: resolve SYSTEM SID: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, fmt.Errorf("ipc: resolve Administrators SID: %w", err)
	}
	authUsers, err := windows.CreateWellKnownSid(windows.WinAuthenticatedUserSid)
	if err != nil {
		return nil, fmt.Errorf("ipc: resolve Authenticated Users SID: %w", err)
	}
	gatewaySID, err := resolveGatewayServiceSID()
	if err != nil {
		return nil, err
	}

	// SYSTEM + Administrators + gateway service: full control on
	// both object classes. Authenticated Users: per-class mask.
	//
	// Directory mask: FILE_TRAVERSE (execute the dir) + FILE_LIST_DIRECTORY
	// (list child names). Enough for a UDS client to path-resolve
	// `<parent>\<socket>` and open() it. FILE_ADD_FILE is REFUSED —
	// a malicious auth-user must NOT be able to pre-create a decoy
	// file at the socket path while the daemon is stopped. Windows'
	// specific rights for a directory object; NOT the generic bits
	// (which map to FILE_ADD_FILE etc.). See CR
	// spec-004:PRRT_kwDORuAK-s6ankzk.
	//
	// Socket-file mask: GENERIC_READ | GENERIC_WRITE. Enough for the
	// UDS `connect()` + gRPC handshake byte streams. WRITE_DAC is
	// refused (not present in GENERIC_WRITE for FILE objects).
	const directoryTraverseList windows.ACCESS_MASK = windows.FILE_TRAVERSE | windows.FILE_LIST_DIRECTORY
	const socketReadWrite windows.ACCESS_MASK = windows.GENERIC_READ | windows.GENERIC_WRITE

	var authUsersMask windows.ACCESS_MASK
	switch class {
	case aclObjectDirectory:
		authUsersMask = directoryTraverseList
	case aclObjectSocketFile:
		authUsersMask = socketReadWrite
	default:
		return nil, fmt.Errorf("ipc: unsupported ACL object class: %d", class)
	}

	entries := []windows.EXPLICIT_ACCESS{
		explicitAllow(system, windows.GENERIC_ALL),
		explicitAllow(admins, windows.GENERIC_ALL),
		explicitAllow(gatewaySID, windows.GENERIC_ALL),
		explicitAllow(authUsers, authUsersMask),
	}
	return entries, nil
}

// explicitAllow is a tiny helper to keep the four-entry list above
// visually parallel (no nesting). NO_INHERITANCE — every one of the
// four ACEs applies to THIS object only. The socket-file DACL is a
// self-contained assertion; there is no child object under a UDS
// socket to inherit anything.
func explicitAllow(sid *windows.SID, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

// resolveGatewayServiceSID looks up the SID for the gateway service
// virtual account. Reads the account name from
// managed.WindowsServiceAccountEnv (set by the SCM installer at
// service registration time) and falls back to
// defaultGatewayServiceAccount when unset.
//
// The lookup goes through LookupSID. The resolved SID is validated
// as an NT SERVICE virtual account (S-1-5-80-...) BEFORE it enters
// the DACL — under the initial-cut deferred-auth posture, the DACL
// is the ONLY access boundary, so an unvalidated principal in the
// DACL would be the single point of failure. A spoofed
// WindowsServiceAccountEnv that resolved to e.g. `Everyone` or an
// unrelated user must NOT slip into the ACE list. See CR
// spec-004:PRRT_kwDORuAK-s6ankzl.
//
// `internal/managed/trust_windows.go` performs a similar check on a
// different code path (trusted-path binding at daemon startup); this
// helper duplicates the authority check so the ACL construction is
// fail-closed on its OWN — a caller that reaches this function
// without having gone through the managed trust path still gets a
// safe SID.
func resolveGatewayServiceSID() (*windows.SID, error) {
	account := strings.TrimSpace(os.Getenv(managed.WindowsServiceAccountEnv))
	if account == "" {
		account = defaultGatewayServiceAccount
	}
	// Refuse an account name whose textual prefix is not
	// `NT SERVICE\` up front, matching the discipline in
	// internal/managed/trust_windows.go's windowsVirtualServiceSID.
	// A LookupSID that resolves a non-service-prefixed name to a
	// UnifiedFolder / group SID would otherwise slip past the
	// authority check below.
	const ntServicePrefix = `NT SERVICE\`
	if len(account) <= len(ntServicePrefix) ||
		!strings.EqualFold(account[:len(ntServicePrefix)], ntServicePrefix) {
		return nil, fmt.Errorf(
			"ipc: gateway service account must start with %q (got %q)",
			ntServicePrefix, account,
		)
	}
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return nil, fmt.Errorf("ipc: resolve gateway service SID for %q: %w", account, err)
	}
	if !sidIsNTService(sid) {
		return nil, fmt.Errorf(
			"ipc: gateway service SID for %q does not live under NT SERVICE authority "+
				"(S-1-5-80-…); refusing to grant it a DACL ACE",
			account,
		)
	}
	return sid, nil
}

// sidIsNTService reports whether sid is a virtual-service SID under
// NT AUTHORITY (identifier authority 5) with subauthority 0 equal to
// SECURITY_SERVICE_ID_BASE_RID (80). Any other combination — including
// SIDs under other NT AUTHORITY subauthorities like NT LOGON (2) or
// well-known SIDs like Anonymous (S-1-5-7) — is rejected. Matches
// the discipline in internal/managed/trust_windows.go's sidIsNTService
// so both call sites agree on what "virtual service account" means.
//
// SECURITY_SERVICE_ID_BASE_RID = 80 is the documented Windows value
// for virtual service accounts (see the Microsoft docs on
// well-known-SID structures). Duplicated here as a literal to avoid
// pulling in an internal/managed import that would create a cycle
// (internal/managed already imports internal/ipc's config plumbing
// indirectly via config → managed).
func sidIsNTService(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	// IdentifierAuthority is a 6-byte value; NT_AUTHORITY is
	// {0, 0, 0, 0, 0, 5}. Read directly from IdentifierAuthority
	// rather than via a helper method to keep the dependency
	// footprint minimal.
	if sid.IdentifierAuthority().Value != [6]byte{0, 0, 0, 0, 0, 5} {
		return false
	}
	if sid.SubAuthorityCount() == 0 {
		return false
	}
	const securityServiceIDBaseRID uint32 = 80
	return sid.SubAuthority(0) == securityServiceIDBaseRID
}
