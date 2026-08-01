//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	windowsEnterpriseMutationIdentityCheck = requireWindowsEnterpriseLocalSystem
	windowsEnterpriseTargetTokenResolver   = resolveWindowsEnterpriseTargetToken
	windowsEnterpriseSetThreadToken        = windows.SetThreadToken
	windowsEnterpriseRevertThreadToken     = windows.RevertToSelf
	windowsEnterpriseLockOSThread          = runtime.LockOSThread
	windowsEnterpriseUnlockOSThread        = runtime.UnlockOSThread
	windowsEnterpriseEffectiveTokenCheck   = func(target *windows.SID) error {
		effective := windows.GetCurrentThreadEffectiveToken()
		return validateWindowsEnterpriseTargetToken(effective, target)
	}
	windowsEnterpriseTokenProfileDirectory = func(token windows.Token) (string, error) {
		return token.GetUserProfileDirectory()
	}
)

// withWindowsEnterpriseTargetImpersonation runs a bounded per-user connector
// mutation on one locked OS thread under an active-session token whose TokenUser
// exactly matches the manifest-pinned SID. There is deliberately no fallback to
// LocalSystem path-string writes: if the user has no active token, the guardian
// fails this row and its periodic backstop retries later.
func withWindowsEnterpriseTargetImpersonation(
	target *windows.SID,
	expectedHome string,
	fn func() error,
) error {
	if target == nil || windowsEnterpriseSystemIdentity(target) {
		return fmt.Errorf("enterprise hooks: refusing invalid impersonation target SID %s", windowsSIDString(target))
	}
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return err
	}
	token, err := windowsEnterpriseTargetTokenResolver(target)
	if err != nil {
		return err
	}
	defer token.Close()
	if err := validateWindowsEnterpriseTargetToken(token, target); err != nil {
		return err
	}
	if err := validateWindowsEnterpriseTokenProfile(token, expectedHome); err != nil {
		return err
	}
	return runWindowsEnterpriseImpersonatedCallback(token, target, fn)
}

func validateWindowsEnterpriseTokenProfile(token windows.Token, expectedHome string) error {
	expected := strings.TrimSpace(expectedHome)
	if expected == "" {
		return fmt.Errorf("enterprise hooks: expected target profile directory is required")
	}
	expectedAbs, err := filepath.Abs(expected)
	if err != nil {
		return fmt.Errorf("enterprise hooks: canonicalize manifest user_home %s: %w", expected, err)
	}
	actual, err := windowsEnterpriseTokenProfileDirectory(token)
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve active target token profile directory: %w", err)
	}
	actual = strings.TrimSpace(actual)
	if actual == "" {
		return fmt.Errorf("enterprise hooks: active target token profile directory is empty")
	}
	actualAbs, err := filepath.Abs(actual)
	if err != nil {
		return fmt.Errorf("enterprise hooks: canonicalize active target token profile directory %s: %w", actual, err)
	}
	expectedAbs = filepath.Clean(expectedAbs)
	actualAbs = filepath.Clean(actualAbs)
	if !strings.EqualFold(expectedAbs, actualAbs) {
		return fmt.Errorf(
			"enterprise hooks: manifest user_home %s does not match active target token profile %s",
			expectedAbs,
			actualAbs,
		)
	}
	return nil
}

func runWindowsEnterpriseImpersonatedCallback(
	token windows.Token,
	target *windows.SID,
	fn func() error,
) error {
	result := make(chan error, 1)
	go func() {
		windowsEnterpriseLockOSThread()
		if err := windowsEnterpriseSetThreadToken(nil, token); err != nil {
			windowsEnterpriseUnlockOSThread()
			result <- fmt.Errorf("enterprise hooks: impersonate target SID %s: %w", target, err)
			return
		}
		if err := windowsEnterpriseEffectiveTokenCheck(target); err != nil {
			revertErr := windowsEnterpriseRevertThreadToken()
			if revertErr == nil {
				windowsEnterpriseUnlockOSThread()
				result <- fmt.Errorf("enterprise hooks: effective thread token mismatch after impersonation: %w", err)
				return
			}
			// Never unlock a thread whose identity could not be reverted. A
			// goroutine that exits while locked causes the Go runtime to
			// terminate that OS thread instead of returning it to the pool.
			result <- fmt.Errorf(
				"enterprise hooks: effective thread token mismatch after impersonation: %v (revert failed: %v)",
				err,
				revertErr,
			)
			return
		}

		callbackErr := fn()
		if revertErr := windowsEnterpriseRevertThreadToken(); revertErr != nil {
			// Intentionally omit UnlockOSThread: this dedicated goroutine now
			// exits and the runtime destroys the still-impersonated OS thread.
			if callbackErr == nil {
				result <- fmt.Errorf("enterprise hooks: revert target SID impersonation: %w", revertErr)
			} else {
				result <- fmt.Errorf("%v (revert target SID impersonation failed: %v)", callbackErr, revertErr)
			}
			return
		}
		windowsEnterpriseUnlockOSThread()
		result <- callbackErr
	}()
	return <-result
}

func requireWindowsEnterpriseLocalSystem() error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve guardian process SID: %w", err)
	}
	if user == nil || user.User.Sid == nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return fmt.Errorf("enterprise hooks: per-user Windows hook mutation requires the LocalSystem guardian service")
	}
	return nil
}

func validateWindowsEnterpriseTokenSID(token windows.Token, target *windows.SID) error {
	if token == 0 || target == nil {
		return fmt.Errorf("target token or SID is unavailable")
	}
	user, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("read target token user: %w", err)
	}
	if user == nil || user.User.Sid == nil {
		return fmt.Errorf("target token has no user SID")
	}
	if !user.User.Sid.Equals(target) {
		return fmt.Errorf("target token SID %s does not match manifest SID %s", user.User.Sid, target)
	}
	if windowsEnterpriseSystemIdentity(user.User.Sid) {
		return fmt.Errorf("target token SID %s is not an interactive user", user.User.Sid)
	}
	return nil
}

func validateWindowsEnterpriseTargetToken(token windows.Token, target *windows.SID) error {
	if err := validateWindowsEnterpriseTokenSID(token, target); err != nil {
		return err
	}
	if err := validateWindowsEnterpriseNonElevatedToken(token); err != nil {
		return fmt.Errorf("target token for SID %s is not safe for per-user mutation: %w", target, err)
	}
	return nil
}

type windowsEnterpriseTokenSecurityFacts struct {
	elevated      uint32
	elevationType uint32
	integrityRID  uint32
	uiAccess      uint32
}

func validateWindowsEnterpriseNonElevatedToken(token windows.Token) error {
	elevated, err := windowsEnterpriseTokenUint32(token, windows.TokenElevation)
	if err != nil {
		return fmt.Errorf("read token elevation: %w", err)
	}
	elevationType, err := windowsEnterpriseTokenUint32(token, windows.TokenElevationType)
	if err != nil {
		return fmt.Errorf("read token elevation type: %w", err)
	}
	integrityRID, err := windowsEnterpriseTokenIntegrityRID(token)
	if err != nil {
		return fmt.Errorf("read token integrity: %w", err)
	}
	uiAccess, err := windowsEnterpriseTokenUint32(token, windows.TokenUIAccess)
	if err != nil {
		return fmt.Errorf("read token UIAccess: %w", err)
	}
	return validateWindowsEnterpriseTokenSecurityFacts(windowsEnterpriseTokenSecurityFacts{
		elevated:      elevated,
		elevationType: elevationType,
		integrityRID:  integrityRID,
		uiAccess:      uiAccess,
	})
}

func validateWindowsEnterpriseTokenSecurityFacts(facts windowsEnterpriseTokenSecurityFacts) error {
	const (
		tokenElevationTypeDefault = 1
		tokenElevationTypeFull    = 2
		tokenElevationTypeLimited = 3
		mandatoryHighRID          = 0x3000
	)
	if facts.elevated != 0 {
		return fmt.Errorf("elevated token is rejected")
	}
	switch facts.elevationType {
	case tokenElevationTypeDefault, tokenElevationTypeLimited:
	case tokenElevationTypeFull:
		return fmt.Errorf("full administrator token is rejected")
	default:
		return fmt.Errorf("unknown token elevation type %d", facts.elevationType)
	}
	if facts.integrityRID >= mandatoryHighRID {
		return fmt.Errorf("high-integrity token (RID 0x%x) is rejected", facts.integrityRID)
	}
	if facts.uiAccess != 0 {
		return fmt.Errorf("UIAccess token is rejected")
	}
	return nil
}

func windowsEnterpriseTokenUint32(token windows.Token, informationClass uint32) (uint32, error) {
	if token == 0 {
		return 0, fmt.Errorf("token is unavailable")
	}
	var value uint32
	var returned uint32
	if err := windows.GetTokenInformation(
		token,
		informationClass,
		(*byte)(unsafe.Pointer(&value)),
		uint32(unsafe.Sizeof(value)),
		&returned,
	); err != nil {
		return 0, err
	}
	if returned != uint32(unsafe.Sizeof(value)) {
		return 0, fmt.Errorf("unexpected token information size %d", returned)
	}
	return value, nil
}

func windowsEnterpriseTokenIntegrityRID(token windows.Token) (uint32, error) {
	if token == 0 {
		return 0, fmt.Errorf("token is unavailable")
	}
	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenIntegrityLevel, nil, 0, &size)
	if err != windows.ERROR_INSUFFICIENT_BUFFER {
		return 0, fmt.Errorf("query token integrity size: %w", err)
	}
	if size < uint32(unsafe.Sizeof(windows.Tokenmandatorylabel{})) {
		return 0, fmt.Errorf("query token integrity size: returned %d bytes", size)
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(
		token,
		windows.TokenIntegrityLevel,
		&buffer[0],
		size,
		&size,
	); err != nil {
		return 0, err
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buffer[0]))
	sid := label.Label.Sid
	if sid == nil || !sid.IsValid() || sid.SubAuthorityCount() == 0 {
		return 0, fmt.Errorf("token integrity label has no valid SID")
	}
	return sid.SubAuthority(uint32(sid.SubAuthorityCount() - 1)), nil
}

func resolveWindowsEnterpriseTargetToken(target *windows.SID) (windows.Token, error) {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &sessions, &count); err != nil {
		return 0, fmt.Errorf("enterprise hooks: enumerate active Windows sessions for target SID %s: %w", target, err)
	}
	if sessions != nil {
		defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))
	}
	sessionIDs := make([]uint32, 0, count)
	if count > 0 && sessions != nil {
		for _, session := range unsafe.Slice(sessions, count) {
			if session.State == windows.WTSActive {
				sessionIDs = append(sessionIDs, session.SessionID)
			}
		}
	}
	sort.Slice(sessionIDs, func(i, j int) bool { return sessionIDs[i] < sessionIDs[j] })
	var queryFailures []string
	for _, sessionID := range sessionIDs {
		var primary windows.Token
		if err := windows.WTSQueryUserToken(sessionID, &primary); err != nil {
			queryFailures = append(queryFailures, fmt.Sprintf("session %d: %v", sessionID, err))
			continue
		}
		if err := validateWindowsEnterpriseTokenSID(primary, target); err != nil {
			primary.Close()
			continue
		}
		if err := validateWindowsEnterpriseNonElevatedToken(primary); err != nil {
			primary.Close()
			return 0, fmt.Errorf(
				"enterprise hooks: active-session token for explicit target SID %s is elevated or otherwise unsafe: %w",
				target,
				err,
			)
		}
		var impersonation windows.Token
		err := windows.DuplicateTokenEx(
			primary,
			windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE|windows.TOKEN_DUPLICATE,
			nil,
			windows.SecurityImpersonation,
			windows.TokenImpersonation,
			&impersonation,
		)
		primary.Close()
		if err != nil {
			return 0, fmt.Errorf("enterprise hooks: duplicate active-session token for target SID %s: %w", target, err)
		}
		if err := validateWindowsEnterpriseTargetToken(impersonation, target); err != nil {
			impersonation.Close()
			return 0, fmt.Errorf("enterprise hooks: duplicated target token validation failed: %w", err)
		}
		return impersonation, nil
	}
	detail := ""
	if len(queryFailures) > 0 {
		detail = "; token query failures: " + strings.Join(queryFailures, "; ")
	}
	return 0, fmt.Errorf("enterprise hooks: no active interactive session token matches explicit target SID %s; guardian will retry%s", target, detail)
}
