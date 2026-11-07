// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// UnsafePrivateDACLError is the refusal of a private path whose DACL another
// account can write through. It names the account and every folder whose DACL
// carries the entry, which is not the refused path when the entry is
// inherited: removing it from the refused path alone does nothing, and an
// entry granted again higher up is inherited again, so all of them are named.
type UnsafePrivateDACLError struct {
	// Path is the path whose DACL was refused.
	Path string
	// Carriers are the folders or files that hold the refused entry as their
	// own (not inherited), outermost first; removing the trustee from all of
	// them clears the refusal. Empty when none could be found.
	Carriers []string
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
	own := false
	var above []string
	for _, carrier := range e.Carriers {
		if carrier == e.Path {
			own = true
		} else {
			above = append(above, carrier)
		}
	}
	switch {
	case len(above) == 0:
		return fmt.Sprintf("%s (%s %s there)", msg, e.Trustee, kind)
	case own:
		return fmt.Sprintf("%s (%s %s there and inherited from %s)", msg, e.Trustee, kind, strings.Join(above, ", "))
	default:
		return fmt.Sprintf("%s (%s %s there, inherited from %s)", msg, e.Trustee, kind, strings.Join(above, ", "))
	}
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
	refusal.Carriers = daclEntryCarriers(path, why)
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

// daclEntryCarriers finds every folder that holds the refused entry as its own
// entry, outermost first. It starts at path (whose own entries count whatever
// they inherit) and goes up through the parents for as long as the entry is
// also inherited. At each parent it looks for the entry the check refused (the
// same account and kind, judged by daclEntryRefused, and inheritable onto the
// child below it), not merely for any entry of the same account: a parent can
// hold a harmless read entry of that account. A parent that holds the entry
// itself and also inherits it from higher up is a carrier and the walk goes on,
// because removing the entry there leaves the one granted above. It returns
// nil when the parents do not show where an inherited entry comes from.
func daclEntryCarriers(path string, why *daclRefusal) []string {
	var carriers []string
	current := path
	var passes byte
	for depth := 0; depth < 64; depth++ {
		explicit, inherited := daclRefusedEntryOf(current, why, passes)
		if explicit {
			carriers = append([]string{current}, carriers...)
		}
		if !inherited {
			return carriers
		}
		parent := filepath.Dir(current)
		if parent == current {
			return carriers
		}
		passes = byte(windows.OBJECT_INHERIT_ACE)
		if info, err := os.Stat(current); err != nil || info.IsDir() {
			passes = windows.CONTAINER_INHERIT_ACE
		}
		current = parent
	}
	return carriers
}

// daclRefusedEntryOf reports whether path's DACL holds the entry why refused,
// as its own entry (explicit) or inherited from above (inherited). A non-zero
// passes keeps only the entries that carry that inherit flag, which are the
// ones that pass on to a child that is a folder or a file; zero keeps all.
func daclRefusedEntryOf(path string, why *daclRefusal, passes byte) (explicit, inherited bool) {
	sd, err := privateDACLDescriptor(path)
	if err != nil {
		return false, false
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false, false
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(index), &ace) != nil || ace == nil || !isSimpleDiscretionaryACE(ace.Header.AceType) {
			continue
		}
		deny := ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE
		// The refused entry's account is trusted exactly when it is a deny entry.
		if deny != why.deny || (passes != 0 && ace.Header.AceFlags&passes == 0) ||
			!(*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(why.sid) || !daclEntryRefused(deny, deny, ace.Mask) {
			continue
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE == 0 {
			explicit = true
		} else {
			inherited = true
		}
	}
	return explicit, inherited
}
