// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winowner"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// ForeignWriteGrant is a write grant to another account over a folder: the
// folder that carries the entry, and the account it names.
type ForeignWriteGrant struct {
	Folder  string
	Account string
}

// Cause is the refusal in words: which folder, which account.
func (g ForeignWriteGrant) Cause() error {
	return fmt.Errorf("%s grants write access to %s", g.Folder, g.Account)
}

// Fix is the one command that removes the grant.
func (g ForeignWriteGrant) Fix() string {
	return fmt.Sprintf(`icacls "%s" /remove "%s"`, g.Folder, g.Account)
}

// FirstForeignWriteGrant finds the folder that carries the write grant to
// another account over path. A private-path refusal names the folder it
// checked, which is usually the inherited child; the entry has to be removed
// from the folder above that it was inherited from (GAP-0731). It walks up
// while the folder's grant is inherited and stops at the first folder that
// holds the entry itself. SYSTEM, the current account, Administrators and the
// other system owners are not foreign. ok is false when path has no such
// grant or its DACL cannot be read.
func FirstForeignWriteGrant(path string) (grant ForeignWriteGrant, ok bool) {
	identity, err := windowsProtectionIdentity()
	if err != nil {
		return ForeignWriteGrant{}, false
	}
	for current := filepath.Clean(path); ; {
		grants, err := foreignWriteGrantsOf(current, identity)
		if err != nil || len(grants) == 0 {
			return grant, ok
		}
		if !ok {
			grant, ok = ForeignWriteGrant{Folder: current, Account: grants[0].account}, true
		}
		for _, g := range grants {
			if !g.inherited {
				return ForeignWriteGrant{Folder: current, Account: g.account}, true
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			return grant, ok
		}
		current = parent
	}
}

type foreignGrant struct {
	account   string
	inherited bool
}

func foreignWriteGrantsOf(path string, identity windowsProtectionSubject) ([]foreignGrant, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil, err
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return nil, err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	var grants []foreignGrant
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return nil, err
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		trusted := sid.Equals(identity.sid) || sid.Equals(system) ||
			sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) || winowner.Trusted(sid.String(), "")
		if trusted || ace.Mask&untrustedWriteMask == 0 {
			continue
		}
		grants = append(grants, foreignGrant{
			account:   accountNameOf(sid),
			inherited: ace.Header.AceFlags&windows.INHERITED_ACE != 0,
		})
	}
	return grants, nil
}

// accountNameOf is DOMAIN\name for icacls, or the SID form icacls accepts
// (*S-1-...) when the name cannot be resolved.
func accountNameOf(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil || account == "" {
		return "*" + sid.String()
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}
