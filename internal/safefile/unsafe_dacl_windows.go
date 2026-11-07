// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"fmt"
	"os"
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
// that holds it as its own entry. At each parent it looks for the entry the
// check refused (the same account and kind, judged by daclEntryRefused, and
// inheritable onto the child below it), not merely for any entry of the same
// account: a parent can hold a harmless read entry of that account and inherit
// the write entry from higher up, and removing the read entry would leave the
// refusal. It returns path when the entry is path's own, and "" when the
// parents do not show it.
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
		childIsDir := true
		if info, err := os.Stat(current); err == nil {
			childIsDir = info.IsDir()
		}
		explicit, inherited := daclRefusedEntryOf(parent, why, childIsDir)
		switch {
		case explicit:
			return parent
		case inherited:
			current = parent
		default:
			return ""
		}
	}
	return ""
}

// daclRefusedEntryOf reports whether path's DACL holds the entry why refused,
// as its own entry (explicit) or inherited from above (inherited), among the
// entries that pass on to a child that is a folder (childIsDir) or a file.
func daclRefusedEntryOf(path string, why *daclRefusal, childIsDir bool) (explicit, inherited bool) {
	sd, err := privateDACLDescriptor(path)
	if err != nil {
		return false, false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false, false
	}
	passes := byte(windows.OBJECT_INHERIT_ACE)
	if childIsDir {
		passes = windows.CONTAINER_INHERIT_ACE
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(index), &ace) != nil || ace == nil || !isSimpleDiscretionaryACE(ace.Header.AceType) {
			continue
		}
		deny := ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE
		// The refused entry's account is trusted exactly when it is a deny entry.
		if deny != why.deny || ace.Header.AceFlags&passes == 0 ||
			!(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(why.sid) || !daclEntryRefused(deny, deny, ace.Mask) {
			continue
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE == 0 {
			return true, inherited
		}
		inherited = true
	}
	return false, inherited
}
