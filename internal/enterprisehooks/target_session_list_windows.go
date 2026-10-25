// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modEnterpriseWTSAPI32                     = windows.NewLazySystemDLL("wtsapi32.dll")
	procEnterpriseWTSQuerySessionInformationW = modEnterpriseWTSAPI32.NewProc("WTSQuerySessionInformationW")
)

// WTS_INFO_CLASS values.
const (
	enterpriseWTSUserName   = 5
	enterpriseWTSDomainName = 7
)

// WindowsTargetHasNoSession reports whether no Windows session, in any
// state, is signed in as sid. Unlike the session-token check it does not
// need LocalSystem: an elevated administrator can list the sessions and read
// whose each one is, though it cannot query their tokens. A session whose
// account cannot be read or resolved is an error, so sign-out is never
// inferred from what the caller could not see (GAP-1433).
func WindowsTargetHasNoSession(sid string) (bool, error) {
	target, err := windows.StringToSid(strings.TrimSpace(sid))
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: parse target SID %q: %w", sid, err)
	}
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return false, fmt.Errorf("enterprise hooks: list Windows sessions for target SID %s: %w", target, err)
	}
	if sessions == nil {
		return true, nil
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	for _, session := range unsafe.Slice(sessions, count) {
		if session.SessionID == 0 {
			continue // services only; nobody signs in to session 0
		}
		user, err := enterpriseWTSSessionString(session.SessionID, enterpriseWTSUserName)
		if err != nil {
			return false, fmt.Errorf("enterprise hooks: read the account of Windows session %d: %w", session.SessionID, err)
		}
		if user == "" {
			continue // nobody is signed in to this session
		}
		domain, err := enterpriseWTSSessionString(session.SessionID, enterpriseWTSDomainName)
		if err != nil {
			return false, fmt.Errorf("enterprise hooks: read the domain of Windows session %d: %w", session.SessionID, err)
		}
		account := user
		if domain != "" {
			account = domain + `\` + user
		}
		owner, _, _, err := windows.LookupSID("", account)
		if err != nil {
			return false, fmt.Errorf("enterprise hooks: resolve the account of Windows session %d: %w", session.SessionID, err)
		}
		if owner.Equals(target) {
			return false, nil
		}
	}
	return true, nil
}

func enterpriseWTSSessionString(session uint32, class uintptr) (string, error) {
	var buffer *uint16
	var size uint32
	r, _, callErr := procEnterpriseWTSQuerySessionInformationW.Call(0, uintptr(session), class,
		uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return "", callErr
	}
	if buffer == nil {
		return "", nil
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buffer)))
	return windows.UTF16PtrToString(buffer), nil
}
