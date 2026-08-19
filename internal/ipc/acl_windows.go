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

// applyBaselineIPCACL applies the spec 004 baseline hygiene DACL to
// the file at `path`. The DACL is protected — SE_DACL_PROTECTED
// severs inheritance so ancestor ACL policy on ProgramData cannot
// silently over-permit the IPC surface (spec 004 REQ-05).
//
// Four ACEs, no others:
//
//   NT AUTHORITY\SYSTEM               (S-1-5-18)   full control
//   BUILTIN\Administrators            (S-1-5-32-544) full control
//   NT SERVICE\DefenseClawGateway     (via LookupSID) full control
//   NT AUTHORITY\Authenticated Users  (S-1-5-11)   read + write
//
// Everything else is denied by omission. Never world-writable
// (Everyone / Anonymous never appear as trustees).
//
// The helper is invoked for both the socket's parent directory AND
// the socket file itself (spec 004 REQ-03 + REQ-04). Applying at
// both layers keeps the socket's DACL independent of any post-hoc
// modification an installer might apply to a shared ProgramData
// ancestor.
//
// Access boundary rationale: the initial-cut deferred-auth posture
// (spec 004 REQ-06 → REQ-08) does NO accept-time codesign or
// signer-CN validation. The DACL is the only access control. Full
// peer-auth lands in a follow-up spec per parity plan §4.4; until
// then the GA release-gate at authposture_gagate.go refuses a
// release-candidate build in which this posture remains reachable.
func applyBaselineIPCACL(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("ipc: applyBaselineIPCACL: empty path")
	}
	entries, err := baselineIPCACEs()
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
// call (which needs a real Windows filesystem object).
func baselineIPCACEs() ([]windows.EXPLICIT_ACCESS, error) {
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

	// SYSTEM + Administrators + gateway service: full control.
	// Authenticated Users: read + write only. Read+write is enough
	// for a UDS `connect()` + gRPC handshake; full-control would grant
	// the auth-user population WRITE_DAC, which we explicitly refuse.
	const authUsersMask = windows.GENERIC_READ | windows.GENERIC_WRITE
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
// The lookup goes through LookupSID (same primitive
// internal/managed/trust_windows.go's windowsVirtualServiceSID
// uses), so a badly-cased account name or a spoofed SID resolves
// consistently across the codebase. We do NOT validate the SID is
// under NT SERVICE authority here — internal/managed already does
// that check when the daemon binds trusted paths at startup. If the
// daemon reached the IPC bind step, the service SID has already
// passed authority validation.
func resolveGatewayServiceSID() (*windows.SID, error) {
	account := strings.TrimSpace(os.Getenv(managed.WindowsServiceAccountEnv))
	if account == "" {
		account = defaultGatewayServiceAccount
	}
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return nil, fmt.Errorf("ipc: resolve gateway service SID for %q: %w", account, err)
	}
	return sid, nil
}
