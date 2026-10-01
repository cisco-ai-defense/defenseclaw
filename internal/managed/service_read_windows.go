//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// serviceReadTreeMaxEntries bounds the folder walk of a rule-pack tree.
const serviceReadTreeMaxEntries = 4096

// serviceReadTokenSIDs are the well-known groups every NT SERVICE virtual
// account's token carries, besides its own service SID.
var serviceReadTokenSIDs = []windows.WELL_KNOWN_SID_TYPE{
	windows.WinServiceSid,
	windows.WinAuthenticatedUserSid,
	windows.WinBuiltinUsersSid,
	windows.WinWorldSid,
	windows.WinLocalSid,
}

// allServicesSID is NT SERVICE\ALL SERVICES, in every service SID's token.
const allServicesSID = "S-1-5-80-0"

// ValidateServiceCanReadTree reports a folder, or a file in it, that the
// gateway's NT SERVICE virtual account cannot read. Setup's preflight runs
// as LocalSystem, which reads everything, so without this check a policy
// folder only administrators can read passed preflight and the gateway
// service then failed to start. It checks the allow and deny entries for
// the service SID and the well-known groups its token carries; an entry
// whose DACL this process cannot read is skipped.
func ValidateServiceCanReadTree(root, label, serviceAccount string) error {
	serviceSID, err := windowsVirtualServiceSID(serviceAccount)
	if err != nil || serviceSID == nil {
		return err
	}
	// The gateway itself reads the tree directly; the DACL check is for a
	// preflight that runs as another account.
	if user, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil && user.User.Sid.Equals(serviceSID) {
		return nil
	}
	allServices, err := windows.StringToSid(allServicesSID)
	if err != nil {
		return err
	}
	sids := []*windows.SID{serviceSID, allServices}
	for _, kind := range serviceReadTokenSIDs {
		sid, err := windows.CreateWellKnownSid(kind)
		if err != nil {
			return err
		}
		sids = append(sids, sid)
	}
	entries := 0
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if entries++; entries > serviceReadTreeMaxEntries {
			return filepath.SkipAll
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return nil
		}
		if serviceCanRead(path, sids) {
			return nil
		}
		return fmt.Errorf(
			"%s %s: the gateway service account %s cannot read %s; grant it Read & execute, for example: icacls %q /grant \"%s:(OI)(CI)RX\" /T",
			label, root, serviceAccount, path, root, serviceAccount)
	})
}

// serviceCanRead reports whether the DACL of path grants FILE_READ_DATA
// (FILE_LIST_DIRECTORY for a folder) to one of sids and denies it to none.
func serviceCanRead(path string, sids []*windows.SID) bool {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return true
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return true
	}
	if dacl == nil {
		return true // a NULL DACL grants everyone access
	}
	const readBits = windows.ACCESS_MASK(0x0001) | windows.GENERIC_READ | windows.GENERIC_ALL
	allowed := false
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(index), &ace) != nil || ace == nil ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Mask&readBits == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		matches := false
		for _, want := range sids {
			if sid.Equals(want) {
				matches = true
				break
			}
		}
		if !matches {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			return false
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			allowed = true
		}
	}
	return allowed
}
