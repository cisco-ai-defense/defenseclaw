// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package useridentity

import (
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// WindowsDirectoryFacts resolves the verified directory facts of a SID from
// the machine's own state (see directory_windows_facts.go). An AD UPN comes
// from TranslateNameW, which may contact a domain controller: the call waits
// at most wait for it (0 does not wait), and a lookup still running then
// finishes in the background and answers a later call.
func WindowsDirectoryFacts(sid string, wait time.Duration) DirectoryFacts {
	return resolveWindowsDirectoryFacts(osWindowsDirectoryReader{}, sid,
		func(sid, samName string) string { return adUPNs.lookup(sid, samName, wait) }, time.Now())
}

// WindowsGroupNames renders group SIDs as DOMAIN\name where LookupAccountSid
// answers, keeping the SID otherwise. At most limit SIDs are looked up and
// no lookup can hold the caller past the budget. Remaining SIDs stay as SIDs.
func WindowsGroupNames(sids []string, limit int, budget time.Duration) []string {
	return windowsGroupNamesWithLookup(sids, limit, budget, (osWindowsDirectoryReader{}).LookupAccount)
}

type osWindowsDirectoryReader struct{}

func (osWindowsDirectoryReader) StringValue(path, name string) (string, bool) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer key.Close()
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return "", false
	}
	return value, true
}

func (osWindowsDirectoryReader) SubKeys(path string) []string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(64)
	if err != nil && len(names) == 0 {
		return nil
	}
	return names
}

func (osWindowsDirectoryReader) LookupAccount(sid string) (string, string, bool) {
	parsed, err := windows.StringToSid(sid)
	if err != nil {
		return "", "", false
	}
	account, domain, _, err := parsed.LookupAccount("")
	if err != nil {
		return "", "", false
	}
	return account, domain, true
}

func (osWindowsDirectoryReader) ComputerName() string {
	name, err := windows.ComputerName()
	if err != nil {
		return ""
	}
	return name
}

// LSA policy reports the joined AD domain independently of the computer's
// primary DNS suffix. Its DNS domain is empty on a workgroup computer.
type lsaUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

func (s lsaUnicodeString) value() string {
	if s.Buffer == nil || s.Length == 0 || s.Length%2 != 0 ||
		s.Length > s.MaximumLength || s.Length > 1024 {
		return ""
	}
	return windows.UTF16ToString(unsafe.Slice(s.Buffer, int(s.Length/2)))
}

type lsaObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type lsaDNSDomainInfo struct {
	Name          lsaUnicodeString
	DNSDomainName lsaUnicodeString
	DNSForestName lsaUnicodeString
	DomainGUID    [16]byte
	SID           uintptr
}

var (
	modAdvapi32                   = windows.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy             = modAdvapi32.NewProc("LsaOpenPolicy")
	procLsaQueryInformationPolicy = modAdvapi32.NewProc("LsaQueryInformationPolicy")
	procLsaFreeMemory             = modAdvapi32.NewProc("LsaFreeMemory")
	procLsaClose                  = modAdvapi32.NewProc("LsaClose")
)

const (
	policyViewLocalInformation = 0x00000001
	policyDnsDomainInformation = 12
)

func (osWindowsDirectoryReader) DomainJoin() (string, string, bool) {
	attributes := lsaObjectAttributes{Length: uint32(unsafe.Sizeof(lsaObjectAttributes{}))}
	var policy uintptr
	status, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attributes)),
		policyViewLocalInformation, uintptr(unsafe.Pointer(&policy)))
	if status != 0 || policy == 0 {
		return "", "", false
	}
	defer procLsaClose.Call(policy)

	var info *lsaDNSDomainInfo
	status, _, _ = procLsaQueryInformationPolicy.Call(policy, policyDnsDomainInformation,
		uintptr(unsafe.Pointer(&info)))
	if status != 0 || info == nil {
		return "", "", false
	}
	defer procLsaFreeMemory.Call(uintptr(unsafe.Pointer(info)))
	domain := strings.TrimSpace(info.Name.value())
	dnsDomain := strings.TrimSpace(info.DNSDomainName.value())
	if domain == "" || dnsDomain == "" {
		return "", "", false
	}
	return domain, dnsDomain, true
}

var adUPNs = newADUPNCache(translateNameToUPN)

// Name formats for TranslateNameW (EXTENDED_NAME_FORMAT).
const (
	nameSamCompatible = 2
	nameUserPrincipal = 8
)

func translateNameToUPN(samName string) string {
	return translateName(samName, nameSamCompatible, nameUserPrincipal)
}

// SAMNameForUPN returns the DOMAIN\sAMAccountName of the AD account a UPN
// names, or "" when none answers within wait. LookupAccountName takes a UPN
// only in a suffix it knows as a domain; TranslateNameW resolves one with an
// alternate UPN suffix too, as the account signs in with it (GAP-0609).
func SAMNameForUPN(upn string, wait time.Duration) string {
	if NormalizeUPN(upn) == "" {
		return ""
	}
	answer := make(chan string, 1)
	go func() { answer <- translateName(strings.TrimSpace(upn), nameUserPrincipal, nameSamCompatible) }()
	select {
	case sam := <-answer:
		return sam
	case <-time.After(wait):
		return ""
	}
}

func translateName(name string, from, to uint32) string {
	input, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return ""
	}
	var size uint32 = 512
	buf := make([]uint16, size)
	if err := windows.TranslateName(input, from, to, &buf[0], &size); err != nil {
		return ""
	}
	if size > uint32(len(buf)) {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}
