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
// policy command on Windows for the OpenClaw release version: the command
// must be a regular file, and neither it nor any folder above it, up to the
// drive root, may give an account other than the current user, LocalSystem
// or Administrators an allow ACE with a right in winowner.CustodyWriteMask
// (the mask OpenClaw uses). That is the trust set of OpenClaw's native ACL
// reader (fs-safe 0.26: the current user, LocalSystem and built-in
// Administrators; its .NET fallback also trusts TrustedInstaller, so
// DefenseClaw trusts only the narrower set).
//
// Inherit-only ACEs do not apply to the object. OpenClaw 2026.11.3 and later
// (fs-safe 0.26) skip them; OpenClaw 2026.8.35 (fs-safe 0.5, icacls text)
// counts them, and an OpenClaw whose version is unknown is held to that
// rule. A command that passes only because inherit-only ACEs are skipped is
// refused on an older OpenClaw with openClawInstallPolicyTooOldError.
//
// Every OpenClaw release up to at least 2026.11.5 applies the rule to the
// drive root too, and the default ACL of a Windows system drive root has
// BUILTIN\Users:(CI)(AD), a create-folders grant that applies to the root
// itself, so OpenClaw refuses every command on such a drive, and with it
// every skill and plugin install (GAP-1139). Setup then does not write the
// command. A root without that entry passes on OpenClaw 2026.11.3 and later.
//
// DefenseClaw also checks the owner of each object, which OpenClaw does not:
// the owner may rewrite the DACL, so an owner outside winowner.Trusted (the
// user, LocalSystem, Administrators, TrustedInstaller: the default owner of
// C:\ is TrustedInstaller) is refused unless an OWNER RIGHTS ACE replaces the
// owner's implicit WRITE_DAC. An ACL or owner that cannot be read is refused.
func openClawInstallPolicyPathTrusted(command, _, version string) error {
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
	type object struct {
		path string
		sd   *windows.SECURITY_DESCRIPTOR
	}
	var chain []object
	for p := command; ; p = filepath.Dir(p) {
		sd, err := openClawInstallPolicyReadSecurity(p)
		if err != nil {
			return fmt.Errorf("cannot read the owner and ACL of %s: %v", p, err)
		}
		chain = append(chain, object{p, sd})
		if parent := filepath.Dir(p); parent == p {
			break
		}
	}
	// The OpenClaw 2026.11.3+ rule first, so a refusal every release shares
	// is reported as itself and not as an old release.
	for _, o := range chain {
		if err := openClawInstallPolicyOwnerTrusted(o.path, o.sd, current); err != nil {
			return err
		}
		if err := openClawInstallPolicyACLTrusted(o.path, o.sd, current, false); err != nil {
			return err
		}
	}
	if openClawSkipsInheritOnlyACEs(version) {
		return nil
	}
	for _, o := range chain {
		if err := openClawInstallPolicyACLTrusted(o.path, o.sd, current, true); err != nil {
			return &openClawInstallPolicyTooOldError{version: NormalizeAgentVersion("openclaw", version), cause: err}
		}
	}
	return nil
}

// openClawInstallPolicyReadSecurity reads the owner and DACL of p; tests
// replace it.
var openClawInstallPolicyReadSecurity = func(p string) (*windows.SECURITY_DESCRIPTOR, error) {
	return windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
}

// openClawInstallPolicyWriterTrusted is OpenClaw's native trust set: the
// current user, LocalSystem and built-in Administrators.
func openClawInstallPolicyWriterTrusted(sid, current string) bool {
	return sid != "" && (sid == current || sid == "S-1-5-18" || sid == "S-1-5-32-544")
}

// openClawInstallPolicyOwnerTrusted refuses an object whose owner is outside
// winowner.Trusted, unless an OWNER RIGHTS ACE that applies to the object
// replaces the owner's implicit WRITE_DAC (an OWNER RIGHTS grant of a write
// right is refused by openClawInstallPolicyACLTrusted).
func openClawInstallPolicyOwnerTrusted(p string, sd *windows.SECURITY_DESCRIPTOR, current string) error {
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("cannot read the owner of %s", p)
	}
	if winowner.Trusted(owner.String(), current) {
		return nil
	}
	dacl, _, err := sd.DACL()
	if err == nil && dacl != nil {
		for index := uint16(0); index < dacl.AceCount; index++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil {
				break
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
				continue
			}
			if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
				continue
			}
			if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String() == winowner.OwnerRightsSID {
				return nil
			}
		}
	}
	return &openClawInstallPolicyOwnerError{msg: fmt.Sprintf("%s is owned by %s, which can change its ACL; OpenClaw would then run a command another account controls",
		p, openClawInstallPolicySIDName(owner))}
}

// openClawInstallPolicyACLTrusted is the OpenClaw rule for one file or
// folder p with security descriptor sd, for the account current (a SID);
// countInheritOnly holds it to OpenClaw 2026.8.35, which counts inherit-only
// ACEs. A NULL DACL, and an ACE whose layout is not a plain allow or deny,
// cannot be checked and are refused; deny ACEs never subtract a grant.
func openClawInstallPolicyACLTrusted(p string, sd *windows.SECURITY_DESCRIPTOR, current string, countInheritOnly bool) error {
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
		inheritOnly := ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0
		if (inheritOnly && !countInheritOnly) || uint32(ace.Mask)&winowner.CustodyWriteMask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if openClawInstallPolicyWriterTrusted(sid.String(), current) {
			continue
		}
		if inheritOnly {
			return fmt.Errorf("%s has the inherit-only entry %s (access mask 0x%x)", p, openClawInstallPolicySIDName(sid), uint32(ace.Mask))
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
