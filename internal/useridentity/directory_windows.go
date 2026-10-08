// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package useridentity

import (
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
// the loop stops when budget elapses, so a slow directory cannot hold up the
// caller; the remaining SIDs are kept as SIDs.
func WindowsGroupNames(sids []string, limit int, budget time.Duration) []string {
	deadline := time.Now().Add(budget)
	out := make([]string, 0, len(sids))
	for i, sid := range sids {
		name := ""
		if i < limit && time.Now().Before(deadline) {
			if account, domain, ok := (osWindowsDirectoryReader{}).LookupAccount(sid); ok && account != "" {
				name = account
				if domain != "" {
					name = domain + `\` + account
				}
			}
		}
		if name == "" {
			name = sid
		}
		out = append(out, name)
	}
	return out
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

func (osWindowsDirectoryReader) DNSDomain() string {
	var size uint32 = 256
	buf := make([]uint16, size)
	if err := windows.GetComputerNameEx(windows.ComputerNameDnsDomain, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

var (
	modNetapi32               = windows.NewLazySystemDLL("netapi32.dll")
	procNetGetJoinInformation = modNetapi32.NewProc("NetGetJoinInformation")
	procNetAPIBufferFree      = modNetapi32.NewProc("NetApiBufferFree")
)

// netSetupDomainName is NETSETUP_JOIN_STATUS NetSetupDomainName.
const netSetupDomainName = 3

func (osWindowsDirectoryReader) DomainJoin() (string, bool) {
	if procNetGetJoinInformation.Find() != nil {
		return "", false
	}
	var name *uint16
	var status uint32
	rc, _, _ := procNetGetJoinInformation.Call(0, uintptr(unsafe.Pointer(&name)), uintptr(unsafe.Pointer(&status)))
	if rc != 0 || name == nil {
		return "", false
	}
	defer procNetAPIBufferFree.Call(uintptr(unsafe.Pointer(name)))
	if status != netSetupDomainName {
		return "", false
	}
	return windows.UTF16PtrToString(name), true
}

var adUPNs = newADUPNCache(translateNameToUPN)

// Name formats for TranslateNameW (EXTENDED_NAME_FORMAT).
const (
	nameSamCompatible = 2
	nameUserPrincipal = 8
)

func translateNameToUPN(samName string) string {
	input, err := windows.UTF16PtrFromString(samName)
	if err != nil {
		return ""
	}
	var size uint32 = 512
	buf := make([]uint16, size)
	if err := windows.TranslateName(input, nameSamCompatible, nameUserPrincipal, &buf[0], &size); err != nil {
		return ""
	}
	if size > uint32(len(buf)) {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}
