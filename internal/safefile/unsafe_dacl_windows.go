// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// UnsafePrivateDACLError is the refusal of a private path whose DACL another
// account can write through. It names the account and the folder whose DACL
// carries the entry, which is not the refused path when the entry is
// inherited: removing it from the refused path alone does nothing.
type UnsafePrivateDACLError struct {
	// Path is the path whose DACL was refused.
	Path string
	// Carrier is the folder or file that holds the entry itself (its own,
	// not inherited). Empty when it could not be found.
	Carrier string
	// Trustee is the account of the entry as DOMAIN\name, or *SID when the
	// name cannot be resolved. Empty when no single entry is to blame.
	Trustee string
	// Deny reports that the entry is a deny entry.
	Deny bool
}

func (e *UnsafePrivateDACLError) Error() string {
	msg := "safefile: private path DACL is unsafe to repair: " + e.Path
	if e.Trustee == "" {
		return msg
	}
	kind := "has write access"
	if e.Deny {
		kind = "has a deny entry"
	}
	if e.Carrier != "" && e.Carrier != e.Path {
		return fmt.Sprintf("%s (%s %s there, inherited from %s)", msg, e.Trustee, kind, e.Carrier)
	}
	return fmt.Sprintf("%s (%s %s there)", msg, e.Trustee, kind)
}

// unsafePrivateDACLError builds the refusal of path. It asks the one rule that
// refused the DACL (privateSecurityDescriptorRefusal) which entry it was, so
// the named account is the one the check meant. Anything that cannot be read
// leaves the account and folder out and keeps the refusal.
func unsafePrivateDACLError(path string, identity windowsProtectionSubject, trustSystemOwners bool) error {
	refusal := &UnsafePrivateDACLError{Path: path}
	sd, err := privateDACLDescriptor(path)
	if err != nil {
		return refusal
	}
	why, err := privateSecurityDescriptorRefusal(sd, identity, trustSystemOwners)
	if err != nil || why == nil || why.sid == nil {
		return refusal
	}
	refusal.Trustee = trusteeName(why.sid)
	refusal.Deny = why.deny
	refusal.Carrier = daclEntryCarrier(path, why)
	return refusal
}

func privateDACLDescriptor(path string) (*windows.SECURITY_DESCRIPTOR, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil, err
	}
	return windows.GetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
}

func trusteeName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil || account == "" {
		return "*" + sid.String()
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}

// daclEntryCarrier follows an inherited entry up the parents to the folder
// that holds it as its own entry. It returns path when the entry is path's
// own, and "" when the parents do not show it.
func daclEntryCarrier(path string, why *daclRefusal) string {
	current := path
	for depth := 0; depth < 64; depth++ {
		if current == path && !why.inherited {
			return path
		}
		parent := filepath.Dir(current)
		if parent == current {
			return ""
		}
		flags, found := daclEntryFlags(parent, why.sid, why.deny)
		if !found {
			return ""
		}
		if flags&windows.INHERITED_ACE == 0 {
			return parent
		}
		current = parent
	}
	return ""
}

// daclEntryFlags returns the flags of the first allow (or deny) entry of sid in
// path's DACL.
func daclEntryFlags(path string, sid *windows.SID, deny bool) (byte, bool) {
	sd, err := privateDACLDescriptor(path)
	if err != nil {
		return 0, false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return 0, false
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(index), &ace) != nil || ace == nil || !isSimpleDiscretionaryACE(ace.Header.AceType) {
			continue
		}
		isDeny := ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE
		if isDeny == deny && (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
			return ace.Header.AceFlags, true
		}
	}
	return 0, false
}
