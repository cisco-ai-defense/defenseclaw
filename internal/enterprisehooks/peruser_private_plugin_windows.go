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

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// Amp and OpenCode load DefenseClaw as a whole-file in-agent plugin. The
// connector publishes that file owner-private (the target user and
// LocalSystem, protected DACL) and its setup refuses foreign write authority.
// The guardian's generic footprint DACL adds BUILTIN\Administrators full
// control and a read-only OWNER RIGHTS entry, which the connector treats as
// foreign write authority; the bare publication, on the other hand, leaves an
// administrator-run Setup or `enterprise hooks verify` unable even to open the
// file. Publication, guardian hardening and every verification therefore
// agree on one managed plugin DACL:
//
//	D:P(A;;FA;;;SY)(A;;FA;;;<target SID>)(A;;FR;;;BA)
//
// LocalSystem and the target user keep full control, BUILTIN\Administrators
// may only read (FILE_GENERIC_READ: data, attributes, extended attributes, the
// security descriptor and SYNCHRONIZE), and nobody else has an entry. The
// connector publishes the first two entries; the guardian adds the read-only
// Administrators entry right after setup, under the target user's token and
// through a no-follow handle; verification requires exactly this set.
const windowsManagedPluginSDDLFormat = "D:P(A;;FA;;;SY)(A;;FA;;;%s)(A;;FR;;;BA)"

// Managed plugin DACL shapes (see windowsPrivatePluginDescriptorShape).
const (
	windowsPluginShapeManaged   = "managed"
	windowsPluginShapePublished = "published"
	windowsPluginShapeGuardian  = "guardian"
	windowsPluginShapeForeign   = "foreign"
)

// The guardian repairs a managed plugin DACL with the no-follow handle walker.
// Hardening runs under the target user's token (the published shape leaves
// the owner WRITE_DAC); migrating an older guardian DACL, whose read-only
// OWNER RIGHTS entry removed the owner's WRITE_DAC, needs LocalSystem.
var (
	windowsManagedPluginDACLRepairAsTarget = func(home, path string, target *windows.SID) error {
		return repairWindowsTargetOwnedPathDACLNoFollowWithACL(home, path, target, false, windowsManagedPluginProtectionACL)
	}
	windowsManagedPluginDACLRepairAsService = func(home, path string, target *windows.SID) error {
		return runWindowsEnterpriseGuardianDACLRepairWithACL(home, path, target, false, windowsManagedPluginProtectionACL)
	}
)

func windowsStandalonePrivatePluginPaths(target windowsGenericManagedTarget, configPaths []string) map[string]bool {
	name := strings.ToLower(strings.TrimSpace(target.conn.Name()))
	if name != "amp" && name != "opencode" {
		return nil
	}
	if _, perUser := windowsStandalonePerUserConnector(name); !perUser {
		return nil
	}
	out := map[string]bool{}
	for _, raw := range configPaths {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		out[filepathKey(abs)] = true
	}
	return out
}

// filepathKey is the case-insensitive key Windows path comparisons use.
func filepathKey(path string) string {
	return strings.ToLower(filepath.Clean(path))
}

func windowsPrivatePluginPathSelected(selected map[string]bool, path string) bool {
	if len(selected) == 0 {
		return false
	}
	abs, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return false
	}
	return selected[filepathKey(abs)]
}

// windowsManagedPluginProtectionACL is the managed plugin DACL for target.
// The directory argument matches the no-follow repair's ACL builder; managed
// plugins are always regular files.
func windowsManagedPluginProtectionACL(target *windows.SID, directory bool) (*windows.ACL, error) {
	if target == nil {
		return nil, fmt.Errorf("enterprise hooks: target SID is unavailable for the managed plugin DACL")
	}
	if directory {
		return nil, fmt.Errorf("enterprise hooks: the managed plugin DACL applies only to regular files")
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf(windowsManagedPluginSDDLFormat, target.String()))
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	return dacl, nil
}

// windowsFileAllAccess is FILE_ALL_ACCESS (SDDL "FA").
const windowsFileAllAccess windows.ACCESS_MASK = 0x001F01FF

func windowsPluginFullControlMask(mask windows.ACCESS_MASK) bool {
	return mask == windowsFileAllAccess || mask == windows.GENERIC_ALL
}

// windowsPrivatePluginDescriptorShape classifies a plugin file DACL:
//   - "managed": exactly the managed plugin DACL;
//   - "published": the connector's publication (target and LocalSystem full
//     control only), before the guardian adds the Administrators read entry;
//   - "guardian": a DACL of only trusted principals that is neither, such as
//     the one the guardian wrote on an older release (a read-only OWNER RIGHTS
//     entry, Administrators full control, a narrower target mask);
//   - "foreign": anything else.
func windowsPrivatePluginDescriptorShape(sd *windows.SECURITY_DESCRIPTOR, target *windows.SID) (string, error) {
	if sd == nil || target == nil {
		return windowsPluginShapeForeign, nil
	}
	control, _, err := sd.Control()
	if err != nil {
		return "", err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return "", err
	}
	if dacl == nil || control&windows.SE_DACL_PROTECTED == 0 {
		return windowsPluginShapeForeign, nil
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return "", err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return "", err
	}
	foundTarget, foundSystem, administratorsRead, guardianMarkers := false, false, false, false
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return "", err
		}
		if ace == nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return windowsPluginShapeForeign, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.Equals(target):
			// The older guardian DACL gave the target a generic read,
			// write, execute and delete mask instead of full control.
			foundTarget = true
			guardianMarkers = guardianMarkers || !windowsPluginFullControlMask(ace.Mask)
		case sid.Equals(system):
			foundSystem = true
			guardianMarkers = guardianMarkers || !windowsPluginFullControlMask(ace.Mask)
		case sid.IsWellKnown(windows.WinCreatorOwnerRightsSid):
			if ace.Mask != windows.READ_CONTROL {
				return windowsPluginShapeForeign, nil
			}
			guardianMarkers = true
		case sid.Equals(administrators):
			if ace.Mask == windows.FILE_GENERIC_READ && ace.Header.AceFlags == 0 && !administratorsRead {
				administratorsRead = true
			} else {
				guardianMarkers = true
			}
		default:
			return windowsPluginShapeForeign, nil
		}
	}
	switch {
	case !foundTarget || !foundSystem:
		return windowsPluginShapeForeign, nil
	case guardianMarkers:
		return windowsPluginShapeGuardian, nil
	case administratorsRead:
		return windowsPluginShapeManaged, nil
	default:
		return windowsPluginShapePublished, nil
	}
}

func windowsPrivatePluginFileState(path string, target *windows.SID) (exists bool, shape string, err error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return true, "", fmt.Errorf("enterprise hooks: managed plugin is not a regular file: %s", path)
	}
	if err := winpath.RejectReparseChain(path); err != nil {
		return true, "", fmt.Errorf("enterprise hooks: managed plugin %s: %w", path, err)
	}
	if err := validateWindowsRegularFileSingleLink(path); err != nil {
		return true, "", err
	}
	sd, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return true, "", fmt.Errorf("enterprise hooks: read managed plugin protection %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return true, "", err
	}
	if owner == nil || !owner.Equals(target) {
		return true, "", fmt.Errorf("enterprise hooks: managed plugin is not owned by the target user: %s", path)
	}
	shape, err = windowsPrivatePluginDescriptorShape(sd, target)
	return true, shape, err
}

// verifyWindowsPrivatePluginFile requires the managed plugin DACL.
func verifyWindowsPrivatePluginFile(path string, target *windows.SID, required bool) error {
	exists, shape, err := windowsPrivatePluginFileState(path, target)
	if err != nil {
		return err
	}
	if !exists {
		if required {
			return fmt.Errorf("enterprise hooks: managed plugin is missing: %s", path)
		}
		return nil
	}
	if shape != windowsPluginShapeManaged {
		return fmt.Errorf("enterprise hooks: managed plugin %s has %s protection, want the managed plugin DACL (target user and LocalSystem full control, Administrators read-only)", path, shape)
	}
	return nil
}

// hardenWindowsPrivatePluginFile adds the read-only Administrators entry to a
// plugin the connector just published, completing the managed plugin DACL.
// It runs under the target user's token, which owns the file and still holds
// WRITE_DAC in the published shape, so it can only change a DACL the user
// could change anyway. Any other shape is left for verification to refuse.
func hardenWindowsPrivatePluginFile(home, path string, target *windows.SID) error {
	exists, shape, err := windowsPrivatePluginFileState(path, target)
	if err != nil || !exists {
		return err
	}
	switch shape {
	case windowsPluginShapeManaged:
		return nil
	case windowsPluginShapePublished:
		if err := windowsManagedPluginDACLRepairAsTarget(home, path, target); err != nil {
			return fmt.Errorf("enterprise hooks: apply the managed plugin DACL to %s: %w", path, err)
		}
		return verifyWindowsPrivatePluginFile(path, target, true)
	default:
		return fmt.Errorf("enterprise hooks: managed plugin %s has %s protection after setup", path, shape)
	}
}

// restoreWindowsPrivatePluginFile runs before setup, as LocalSystem (see
// relaxWindowsStandalonePerUserFootprintForSetupAsService). A target-owned,
// single-link, non-reparse plugin that carries a DACL the guardian wrote on an
// older release, or one the user rewrote, gets the managed plugin DACL back so
// the connector can republish it under the user's token. The published and
// managed shapes are left as they are.
func restoreWindowsPrivatePluginFile(home, path string, target *windows.SID) error {
	exists, shape, err := windowsPrivatePluginFileState(path, target)
	if err != nil || !exists {
		return err
	}
	if shape == windowsPluginShapeManaged || shape == windowsPluginShapePublished {
		return nil
	}
	if err := windowsManagedPluginDACLRepairAsService(home, path, target); err != nil {
		return fmt.Errorf("enterprise hooks: restore the managed plugin DACL of %s: %w", path, err)
	}
	return nil
}
