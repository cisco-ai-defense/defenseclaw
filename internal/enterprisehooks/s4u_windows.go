// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A service-for-user (S4U) logon gives LocalSystem a token for an account
// that has no session, without its password. The rollback of a failed first
// install uses it to put back a signed-out account's agent files as that
// account; see RestoreWindowsStandaloneUserAgentConfigs.

var (
	modWindowsSecur32                       = windows.NewLazySystemDLL("secur32.dll")
	procWindowsLsaRegisterLogonProcess      = modWindowsSecur32.NewProc("LsaRegisterLogonProcess")
	procWindowsLsaDeregisterLogonProcess    = modWindowsSecur32.NewProc("LsaDeregisterLogonProcess")
	procWindowsLsaLookupAuthenticationPkg   = modWindowsSecur32.NewProc("LsaLookupAuthenticationPackage")
	procWindowsLsaLogonUser                 = modWindowsSecur32.NewProc("LsaLogonUser")
	procWindowsLsaFreeReturnBuffer          = modWindowsSecur32.NewProc("LsaFreeReturnBuffer")
	procWindowsAllocateLocallyUniqueID      = windows.NewLazySystemDLL("advapi32.dll").NewProc("AllocateLocallyUniqueId")
	windowsEnterpriseS4UTargetTokenResolver = resolveWindowsEnterpriseS4UTargetToken
)

const (
	// MsV1_0S4ULogon and KerbS4ULogon share the value and the layout.
	windowsS4ULogonMessageType = 12
	windowsNetworkLogonType    = 3
)

type windowsLSAString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *byte
}

type windowsS4ULogon struct {
	MessageType uint32
	Flags       uint32
	User        windows.NTUnicodeString
	Domain      windows.NTUnicodeString
}

type windowsTokenSource struct {
	SourceName       [8]byte
	SourceIdentifier windows.LUID
}

type windowsQuotaLimits struct {
	PagedPoolLimit        uintptr
	NonPagedPoolLimit     uintptr
	MinimumWorkingSetSize uintptr
	MaximumWorkingSetSize uintptr
	PagefileLimit         uintptr
	TimeLimit             int64
}

func newWindowsLSAString(value string) *windowsLSAString {
	buffer := append([]byte(value), 0)
	return &windowsLSAString{Length: uint16(len(value)), MaximumLength: uint16(len(buffer)), Buffer: &buffer[0]}
}

func windowsLSAStatus(r1 uintptr) error {
	if r1 == 0 {
		return nil
	}
	return windows.NTStatus(uint32(r1))
}

// windowsS4ULogonBuffer lays out the S4U request with its strings in the same
// allocation, as LsaLogonUser requires.
func windowsS4ULogonBuffer(user, domain string) ([]uint64, uint32, error) {
	userUTF16, err := windows.UTF16FromString(user)
	if err != nil {
		return nil, 0, err
	}
	domainUTF16, err := windows.UTF16FromString(domain)
	if err != nil {
		return nil, 0, err
	}
	userUTF16, domainUTF16 = userUTF16[:len(userUTF16)-1], domainUTF16[:len(domainUTF16)-1]
	if len(userUTF16) == 0 || len(userUTF16) > 256 || len(domainUTF16) > 256 {
		return nil, 0, fmt.Errorf("enterprise hooks: account name %q\\%q is not valid for an S4U logon", domain, user)
	}
	header := unsafe.Sizeof(windowsS4ULogon{})
	size := header + uintptr(len(userUTF16)+len(domainUTF16))*2
	buffer := make([]uint64, (size+7)/8)
	base := unsafe.Pointer(&buffer[0])
	logon := (*windowsS4ULogon)(base)
	logon.MessageType = windowsS4ULogonMessageType
	userPtr := (*uint16)(unsafe.Add(base, header))
	copy(unsafe.Slice(userPtr, len(userUTF16)), userUTF16)
	logon.User = windows.NTUnicodeString{Length: uint16(len(userUTF16) * 2), MaximumLength: uint16(len(userUTF16) * 2), Buffer: userPtr}
	if len(domainUTF16) > 0 {
		domainPtr := (*uint16)(unsafe.Add(base, header+uintptr(len(userUTF16))*2))
		copy(unsafe.Slice(domainPtr, len(domainUTF16)), domainUTF16)
		logon.Domain = windows.NTUnicodeString{Length: uint16(len(domainUTF16) * 2), MaximumLength: uint16(len(domainUTF16) * 2), Buffer: domainPtr}
	}
	return buffer, uint32(size), nil
}

// resolveWindowsEnterpriseS4UTargetToken returns an impersonation token for
// target from an S4U logon: MSV1_0 for a local account, Kerberos (which needs
// a reachable domain controller) for a domain account. It needs
// SeTcbPrivilege, which LocalSystem holds; without it LSA would return only an
// identification token, so the registration fails instead.
func resolveWindowsEnterpriseS4UTargetToken(target *windows.SID) (windows.Token, error) {
	if target == nil || windowsEnterpriseSystemIdentity(target) {
		return 0, fmt.Errorf("enterprise hooks: refusing S4U logon for SID %s", windowsSIDString(target))
	}
	account, domain, use, err := target.LookupAccount("")
	if err != nil {
		return 0, fmt.Errorf("enterprise hooks: look up account of SID %s: %w", target, err)
	}
	if use != windows.SidTypeUser {
		return 0, fmt.Errorf("enterprise hooks: SID %s is not a user account", target)
	}
	computer, err := windows.ComputerName()
	if err != nil {
		return 0, err
	}
	pkg := "Kerberos"
	if strings.EqualFold(domain, computer) {
		pkg = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
	}
	request, requestSize, err := windowsS4ULogonBuffer(account, domain)
	if err != nil {
		return 0, err
	}

	var lsa windows.Handle
	var mode uint32
	r1, _, _ := procWindowsLsaRegisterLogonProcess.Call(
		uintptr(unsafe.Pointer(newWindowsLSAString("DefenseClaw"))),
		uintptr(unsafe.Pointer(&lsa)),
		uintptr(unsafe.Pointer(&mode)),
	)
	if err := windowsLSAStatus(r1); err != nil {
		return 0, fmt.Errorf("enterprise hooks: register S4U logon process: %w", err)
	}
	defer procWindowsLsaDeregisterLogonProcess.Call(uintptr(lsa))
	var pkgID uint32
	r1, _, _ = procWindowsLsaLookupAuthenticationPkg.Call(
		uintptr(lsa),
		uintptr(unsafe.Pointer(newWindowsLSAString(pkg))),
		uintptr(unsafe.Pointer(&pkgID)),
	)
	if err := windowsLSAStatus(r1); err != nil {
		return 0, fmt.Errorf("enterprise hooks: look up %s for S4U: %w", pkg, err)
	}
	source := windowsTokenSource{}
	copy(source.SourceName[:], "DfnsClaw")
	if ok, _, err := procWindowsAllocateLocallyUniqueID.Call(uintptr(unsafe.Pointer(&source.SourceIdentifier))); ok == 0 {
		return 0, fmt.Errorf("enterprise hooks: allocate S4U source identifier: %w", err)
	}
	var (
		profile       uintptr
		profileLength uint32
		logonID       windows.LUID
		token         windows.Token
		quotas        windowsQuotaLimits
		subStatus     uint32
	)
	r1, _, _ = procWindowsLsaLogonUser.Call(
		uintptr(lsa),
		uintptr(unsafe.Pointer(newWindowsLSAString("DefenseClaw"))),
		windowsNetworkLogonType,
		uintptr(pkgID),
		uintptr(unsafe.Pointer(&request[0])),
		uintptr(requestSize),
		0,
		uintptr(unsafe.Pointer(&source)),
		uintptr(unsafe.Pointer(&profile)),
		uintptr(unsafe.Pointer(&profileLength)),
		uintptr(unsafe.Pointer(&logonID)),
		uintptr(unsafe.Pointer(&token)),
		uintptr(unsafe.Pointer(&quotas)),
		uintptr(unsafe.Pointer(&subStatus)),
	)
	if profile != 0 {
		procWindowsLsaFreeReturnBuffer.Call(profile)
	}
	if err := windowsLSAStatus(r1); err != nil {
		return 0, fmt.Errorf("enterprise hooks: S4U logon for SID %s: %w (substatus 0x%x)", target, err, subStatus)
	}
	defer token.Close()
	var impersonation windows.Token
	if err := windows.DuplicateTokenEx(
		token,
		windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE|windows.TOKEN_DUPLICATE,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&impersonation,
	); err != nil {
		return 0, fmt.Errorf("enterprise hooks: duplicate S4U token for SID %s: %w", target, err)
	}
	return impersonation, nil
}
