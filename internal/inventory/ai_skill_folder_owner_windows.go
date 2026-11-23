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

import "golang.org/x/sys/windows"

// trustedInstallerSID is NT SERVICE\TrustedInstaller.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

// skillFolderManaged is skillFolderAdminOwned; tests replace it.
var skillFolderManaged = skillFolderAdminOwned

// skillFolderAdminOwned reports whether SYSTEM, Administrators or
// TrustedInstaller owns the skill folder at path. A standard user can create
// a folder such as C:\ProgramData\OpenAI\Codex\skills and owns it; its
// skills are not reported as managed.
func skillFolderAdminOwned(path string) bool {
	owner := skillPathOwner(path)
	return owner != nil && skillAdminSID(owner)
}

// skillPathOwner is the owner of the file or folder at path, nil when it
// cannot be read.
func skillPathOwner(path string) *windows.SID {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil
	}
	return owner
}

// skillAdminSID reports whether sid is SYSTEM, Administrators or TrustedInstaller.
func skillAdminSID(sid *windows.SID) bool {
	return sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		sid.String() == trustedInstallerSID
}
