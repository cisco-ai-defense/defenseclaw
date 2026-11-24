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

package inventory

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// trustedInstallerSID is NT SERVICE\TrustedInstaller.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// Folder rights and an access-entry type that x/sys/windows does not name.
const (
	fileAddFile                  = 0x0002 // FILE_ADD_FILE (FILE_WRITE_DATA on a file)
	fileAddSubdirectory          = 0x0004 // FILE_ADD_SUBDIRECTORY (FILE_APPEND_DATA on a file)
	fileDeleteChild              = 0x0040 // FILE_DELETE_CHILD
	accessAllowedCallbackACEType = 0x9
)

// skillChangeAccess is every right that adds to a folder, removes from it or
// changes who may: what only an administrator may hold on a managed one.
const skillChangeAccess = windows.ACCESS_MASK(fileAddFile | fileAddSubdirectory | fileDeleteChild |
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER)

// skillFolderManaged is skillFolderAdminOwned; tests replace it.
var skillFolderManaged = skillFolderAdminOwned

// skillFolderAdminOwned reports whether only administrators can change the
// opened skill folder: SYSTEM, Administrators or TrustedInstaller owns it, and
// its access list lets no other account add to it or change it, directly or
// through an entry its files and folders inherit (GAP-1837). A standard user
// can create a folder such as C:\ProgramData\OpenAI\Codex\skills and owns it,
// and a folder an administrator made under ProgramData lets Users add to it by
// default; the skills in either are not reported as managed. The owner and
// access list are read from dir, the handle the scan hashes from. A folder
// reached through a junction or symbolic link is never managed: path must open
// with no link on the way (safefile.OpenDirectoryNoFollow) and be the same
// folder as dir, so a swap of the folder at path changes nothing (GAP-2147).
func skillFolderAdminOwned(dir *os.File, path string) bool {
	plain, err := safefile.OpenDirectoryNoFollow(path)
	if err != nil {
		return false
	}
	defer plain.Close()
	opened, err := dir.Stat()
	if err != nil {
		return false
	}
	named, err := plain.Stat()
	if err != nil || !os.SameFile(opened, named) {
		return false
	}
	descriptor, _, err := skillSecurity(dir, path)
	return err == nil && skillDescriptorAdminOnly(descriptor)
}

// skillEntryManaged is skillEntryAdminOwned; tests replace it.
var skillEntryManaged = skillEntryAdminOwned

// skillEntryAdminOwned reports whether the opened folder or file below a
// managed skill folder is also one only administrators can change: an
// administrator copy that kept a user's access entry on a subfolder or file
// is not (GAP-2147). The walk opened it from its held parent with no link
// followed, so only its own handle is read.
func skillEntryAdminOwned(opened *os.File, path string) bool {
	descriptor, _, err := skillSecurity(opened, path)
	return err == nil && skillDescriptorAdminOnly(descriptor)
}

// skillDescriptorAdminOnly reports whether descriptor is an administrator's
// and grants no other account a right in skillChangeAccess.
func skillDescriptorAdminOnly(descriptor *windows.SECURITY_DESCRIPTOR) bool {
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !skillAdminSID(owner) {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false // a NULL access list lets everyone change the folder
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return false
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE, accessAllowedCallbackACEType:
		case windows.ACCESS_DENIED_ACE_TYPE, accessDeniedObjectACEType, accessDeniedCallbackACEType, accessDeniedCallbackObjectACEType:
			continue // a deny entry only takes rights away
		default:
			return false // an allow entry whose account is not read here (an object entry)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if skillAdminSID(sid) || skillServiceSID(sid) {
			continue
		}
		if safefile.FileAccessMask(ace.Mask)&skillChangeAccess != 0 {
			return false
		}
	}
	return true
}

// skillAdminSID reports whether sid is SYSTEM, Administrators or TrustedInstaller.
func skillAdminSID(sid *windows.SID) bool {
	return sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		sid.String() == trustedInstallerSID
}

// skillServiceSID reports a principal no ordinary account holds: CREATOR
// OWNER (an inherit-only placeholder for the creator, an administrator when
// only administrators may add), OWNER RIGHTS (the owner, an administrator),
// LocalService, NetworkService and the service SIDs.
func skillServiceSID(sid *windows.SID) bool {
	switch value := sid.String(); value {
	case "S-1-3-0", "S-1-3-4", "S-1-5-19", "S-1-5-20":
		return true
	default:
		return strings.HasPrefix(value, "S-1-5-80-")
	}
}
