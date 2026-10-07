// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package useridentity

import (
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows the hook reads its own logon session from the LSA
// (LsaGetLogonSessionData for the token's AuthenticationId): the UPN, the
// authentication package (Kerberos, NTLM, CloudAP for Entra) and the logon
// type, which marks a Remote Desktop session. It is one in-process call, so
// no cache file is written. Every value is claimed.

var (
	modSecur32                 = windows.NewLazySystemDLL("secur32.dll")
	procLsaGetLogonSessionData = modSecur32.NewProc("LsaGetLogonSessionData")
	procLsaFreeReturnBuffer    = modSecur32.NewProc("LsaFreeReturnBuffer")
)

// securityLogonSessionData is the prefix of SECURITY_LOGON_SESSION_DATA up
// to Upn; Size says how much of it the LSA filled.
type securityLogonSessionData struct {
	Size                  uint32
	LogonID               windows.LUID
	UserName              windows.NTUnicodeString
	LogonDomain           windows.NTUnicodeString
	AuthenticationPackage windows.NTUnicodeString
	LogonType             uint32
	Session               uint32
	Sid                   *windows.SID
	LogonTime             int64
	LogonServer           windows.NTUnicodeString
	DNSDomainName         windows.NTUnicodeString
	Upn                   windows.NTUnicodeString
}

// tokenStatistics is TOKEN_STATISTICS.
type tokenStatistics struct {
	TokenID            windows.LUID
	AuthenticationID   windows.LUID
	ExpirationTime     int64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedID         windows.LUID
}

// Logon types (NTSecAPI.h SECURITY_LOGON_TYPE).
const (
	logonInteractive             = 2
	logonRemoteInteractive       = 10
	logonCachedInteractive       = 11
	logonCachedRemoteInteractive = 12
)

func currentSessionFactsHeaderLive(now time.Time) string { return currentSessionFactsHeader(now) }

func currentSessionFactsHeader(time.Time) string {
	facts := SessionFromSSHEnv(os.Getenv)
	upn := ""
	if data, ok := readOwnLogonSession(); ok {
		upn = NormalizeUPN(data.upn)
		if facts.Kind == "" {
			facts.Kind = windowsSessionKind(data.logonType)
		}
		if strings.EqualFold(data.authPackage, "Kerberos") {
			facts.CCacheType = CCacheMSLSA
			if data.user != "" && data.dnsDomain != "" {
				facts.KerberosPrincipal = NormalizePrincipal(data.user + "@" + data.dnsDomain)
			}
		}
	}
	return EncodeSessionFactsHeader(ClaimedSessionHeader{Session: facts, UPN: upn})
}

func windowsSessionKind(logonType uint32) SessionKind {
	switch logonType {
	case logonRemoteInteractive, logonCachedRemoteInteractive:
		return SessionRDP
	case logonInteractive, logonCachedInteractive:
		return SessionLocal
	}
	return ""
}

type ownLogonSession struct {
	user, dnsDomain, authPackage, upn string
	logonType                         uint32
}

func readOwnLogonSession() (ownLogonSession, bool) {
	if err := procLsaGetLogonSessionData.Find(); err != nil {
		return ownLogonSession{}, false
	}
	token := windows.GetCurrentProcessToken()
	var stats tokenStatistics
	var returned uint32
	if err := windows.GetTokenInformation(token, windows.TokenStatistics,
		(*byte)(unsafe.Pointer(&stats)), uint32(unsafe.Sizeof(stats)), &returned); err != nil {
		return ownLogonSession{}, false
	}
	var data *securityLogonSessionData
	status, _, _ := procLsaGetLogonSessionData.Call(
		uintptr(unsafe.Pointer(&stats.AuthenticationID)),
		uintptr(unsafe.Pointer(&data)),
	)
	if status != 0 || data == nil {
		return ownLogonSession{}, false
	}
	defer procLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(data)))
	out := ownLogonSession{
		user:        data.UserName.String(),
		authPackage: data.AuthenticationPackage.String(),
		logonType:   data.LogonType,
	}
	if uintptr(data.Size) >= unsafe.Offsetof(data.Upn)+unsafe.Sizeof(data.Upn) {
		out.dnsDomain = data.DNSDomainName.String()
		out.upn = data.Upn.String()
	}
	return out, true
}
