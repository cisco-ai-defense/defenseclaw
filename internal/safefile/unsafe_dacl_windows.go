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

// UnsafeDACLEntry is one refused entry of a private path DACL: the account, the
// kind, and every folder or file that holds the entry as its own (not
// inherited), outermost first. Removing the account from all of them clears
// this entry; an entry granted again higher up is inherited again, so all of
// them are named.
type UnsafeDACLEntry struct {
	// Trustee is the account of the entry as DOMAIN\name, or *SID when the
	// name cannot be resolved.
	Trustee string
	// Deny reports that the entry is a deny entry.
	Deny bool
	// Carriers are the folders or files that hold the entry as their own,
	// outermost first. Empty when none could be found.
	Carriers []string
}

// UnsafePrivateDACLError is the refusal of a private path whose DACL another
// account can write through. It names every account whose entry the check
// refuses (a DACL can hold several, and one repaired at a time leaves the
// refusal in place) and, for each, every folder whose DACL carries the entry,
// which is not the refused path when the entry is inherited: removing it from
// the refused path alone does nothing.
type UnsafePrivateDACLError struct {
	// Path is the path whose DACL was refused.
	Path string
	// Entries are the refused entries, one per account and kind, in the order
	// of the DACL. Empty when no single entry is to blame.
	Entries []UnsafeDACLEntry
}

func (e *UnsafePrivateDACLError) Error() string {
	msg := "safefile: private path DACL is unsafe to repair: " + e.Path
	if len(e.Entries) == 0 {
		return msg
	}
	parts := make([]string, len(e.Entries))
	for i, entry := range e.Entries {
		kind := "has write access"
		if entry.Deny {
			kind = "has a deny entry"
		}
		own := false
		var above []string
		for _, carrier := range entry.Carriers {
			if carrier == e.Path {
				own = true
			} else {
				above = append(above, carrier)
			}
		}
		switch {
		case len(above) == 0:
			parts[i] = fmt.Sprintf("%s %s there", entry.Trustee, kind)
		case own:
			parts[i] = fmt.Sprintf("%s %s there and inherited from %s", entry.Trustee, kind, strings.Join(above, ", "))
		default:
			parts[i] = fmt.Sprintf("%s %s there, inherited from %s", entry.Trustee, kind, strings.Join(above, ", "))
		}
	}
	return fmt.Sprintf("%s (%s)", msg, strings.Join(parts, "; "))
}

// unsafePrivateDACLError builds the refusal of path. It asks the one rule that
// refused the DACL (privateSecurityDescriptorRefusals) which entries it
// refused, so the named accounts are the ones the check meant. Anything that
// cannot be read leaves the accounts and folders out and keeps the refusal.
func unsafePrivateDACLError(path string, identity windowsProtectionSubject, trustSystemOwners bool) error {
	refusal := &UnsafePrivateDACLError{Path: path}
	sd, err := privateDACLDescriptor(path)
	if err != nil {
		return refusal
	}
	refused, err := privateSecurityDescriptorRefusals(sd, identity, trustSystemOwners)
	if err != nil {
		return refusal
	}
	for _, why := range refused {
		if why.sid == nil {
			// An entry the check cannot name: the repair cannot be listed whole.
			return &UnsafePrivateDACLError{Path: path}
		}
		refusal.Entries = append(refusal.Entries, UnsafeDACLEntry{
			Trustee:  trusteeName(why.sid),
			Deny:     why.deny,
			Carriers: daclEntryCarriers(path, why),
		})
	}
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
// nil unless the walk reaches the end of every inherited chain: a parent that
// cannot be read, one that no longer shows the entry its child inherits, the
// top of the volume and the depth bound are all an incomplete walk, and a
// partial list would print a repair that leaves the refusal in place.
func daclEntryCarriers(path string, why *daclRefusal) []string {
	return walkDaclCarriers(path, why, daclRefusedEntryOf)
}

// daclCarrierDepth bounds the walk up the parents.
const daclCarrierDepth = 64

// walkDaclCarriers is daclEntryCarriers over a lookup that reports, for one
// folder, whether it holds the refused entry as its own and whether it inherits it.
func walkDaclCarriers(
	path string,
	why *daclRefusal,
	lookup func(path string, why *daclRefusal, passes byte) (explicit, inherited bool),
) []string {
	var carriers []string
	current := path
	var passes byte
	for depth := 0; depth < daclCarrierDepth; depth++ {
		explicit, inherited := lookup(current, why, passes)
		if depth > 0 && !explicit && !inherited {
			// The child inherits an entry this folder does not show.
			return nil
		}
		if explicit {
			carriers = append([]string{current}, carriers...)
		}
		if !inherited {
			return carriers
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		passes = byte(windows.OBJECT_INHERIT_ACE)
		if info, err := os.Stat(current); err != nil || info.IsDir() {
			passes = windows.CONTAINER_INHERIT_ACE
		}
		current = parent
	}
	return nil
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
