//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winowner"
	"golang.org/x/sys/windows"
)

// openClawInstallPolicyPathTrusted applies the OpenClaw rule for an install
// policy command on Windows: the command must be a regular file, and neither
// it nor any folder above it, up to the drive root, may give an account other
// than the current user, LocalSystem or Administrators an allow ACE with a
// right in winowner.CustodyWriteMask (the mask OpenClaw uses). That is the
// trust set of OpenClaw's native ACL reader (fs-safe 0.26: the current user,
// LocalSystem and built-in Administrators; its .NET fallback also trusts
// TrustedInstaller, so DefenseClaw trusts only the narrower set). Inherit-only
// ACEs do not apply to the object and are skipped, as OpenClaw 2026.11.x
// skips them (OpenClaw 2026.8.35, fs-safe 0.5, counted them from icacls
// text; on a drive root hardened as below it may still refuse the command).
// Every OpenClaw release up to at least 2026.11.5 applies the rule to the
// drive root too, and the default ACL of a Windows system drive root has
// BUILTIN\Users:(CI)(AD), a create-folders grant that applies to the root
// itself, so OpenClaw refuses every command on such a drive, and with it
// every skill and plugin install (GAP-1139). Setup then does not write the
// command. A root without that entry (the inherit-only Users and CREATOR
// OWNER entries may stay) passes. An ACL that cannot be read is refused.
func openClawInstallPolicyPathTrusted(command, _ string) error {
	info, err := os.Lstat(command)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", command)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("cannot read the current account to check %s: %v", command, err)
	}
	current := user.User.Sid.String()
	for p := command; ; p = filepath.Dir(p) {
		sd, err := openClawInstallPolicyReadDACL(p)
		if err != nil {
			return fmt.Errorf("cannot read the ACL of %s: %v", p, err)
		}
		if err := openClawInstallPolicyACLTrusted(p, sd, current); err != nil {
			return err
		}
		if parent := filepath.Dir(p); parent == p {
			return nil
		}
	}
}

// openClawInstallPolicyReadDACL reads the DACL of p; tests replace it.
var openClawInstallPolicyReadDACL = func(p string) (*windows.SECURITY_DESCRIPTOR, error) {
	return windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
}

// openClawInstallPolicyWriterTrusted is OpenClaw's native trust set: the
// current user, LocalSystem and built-in Administrators.
func openClawInstallPolicyWriterTrusted(sid, current string) bool {
	return sid != "" && (sid == current || sid == "S-1-5-18" || sid == "S-1-5-32-544")
}

// openClawInstallPolicyACLTrusted is the OpenClaw rule for one file or
// folder p with security descriptor sd, for the account current (a SID). A
// NULL DACL, and an ACE whose layout is not a plain allow or deny, cannot be
// checked and are refused; deny ACEs never subtract a grant.
func openClawInstallPolicyACLTrusted(p string, sd *windows.SECURITY_DESCRIPTOR, current string) error {
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%s has no DACL, so every account may change it", p)
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil {
			return fmt.Errorf("cannot read the ACL of %s", p)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Errorf("the ACL of %s has an entry DefenseClaw cannot check (type %d)", p, ace.Header.AceType)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || uint32(ace.Mask)&winowner.CustodyWriteMask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if openClawInstallPolicyWriterTrusted(sid.String(), current) {
			continue
		}
		return fmt.Errorf("%s lets %s change its entries (access mask 0x%x); OpenClaw refuses an install policy command below such a folder, "+
			"and a Windows drive root grants BUILTIN\\Users this by default (BUILTIN\\Users:(CI)(AD))", p, openClawInstallPolicySIDName(sid), uint32(ace.Mask))
	}
	return nil
}

// openClawInstallPolicySIDName is DOMAIN\name (SID), or the SID alone.
func openClawInstallPolicySIDName(sid *windows.SID) string {
	account, domain, _, err := sid.LookupAccount("")
	if err != nil || account == "" {
		return sid.String()
	}
	if domain != "" {
		account = domain + `\` + account
	}
	return account + " (" + sid.String() + ")"
}
