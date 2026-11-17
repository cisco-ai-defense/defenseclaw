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
// it nor any folder above it, up to the drive root, may let an account other
// than LocalSystem, Administrators, TrustedInstaller or the current user add,
// change or remove entries (OpenClaw reads the DACL and counts every allow
// ACE with a right in winowner.CustodyWriteMask, the same mask OpenClaw
// uses). OpenClaw through 2026.11.5 applies the rule to the drive root too,
// and the default ACL of a Windows system drive root lets BUILTIN\Users
// create folders in it, so on such a drive OpenClaw refuses every command,
// and with it every skill and plugin install (GAP-1139). Setup then does not
// write the command. An ACL that cannot be read is refused as well.
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
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
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

// openClawInstallPolicyACLTrusted is the OpenClaw rule for one file or
// folder p with security descriptor sd, for the account current (a SID).
// An inherit-only ACE counts too, as OpenClaw counts it, and an ACE whose
// layout is not a plain allow or deny cannot be checked and is refused.
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
		if uint32(ace.Mask)&winowner.CustodyWriteMask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if winowner.Trusted(sid.String(), current) {
			continue
		}
		return fmt.Errorf("%s lets %s change its entries (access mask 0x%x); OpenClaw refuses an install policy command below such a folder, "+
			"and a Windows drive root grants BUILTIN\\Users this by default", p, openClawInstallPolicySIDName(sid), uint32(ace.Mask))
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
