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

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Per-user connectors whose setup binds to a protected, setup-selected
// executable (Amp, OpenCode, Hermes on Windows) need an exact native image the
// LocalSystem guardian can hash as the target user. These are the only images
// the guardian selects; anything else stays unmanaged and is reported, rather
// than failing the reconcile for every other user.
var windowsStandaloneManagedExecutableRelative = map[string][][]string{
	// npm's amp.cmd launches this native image.
	"amp": {{"AppData", "Roaming", "npm", "node_modules", "@ampcode", "cli", "bin", "amp.exe"}},
	// The connector's executable admission accepts the official SST WinGet
	// image and the native image npm's opencode.cmd launches from the
	// opencode-ai package. WinGet wins when both exist.
	"opencode": {
		{"AppData", "Local", "Microsoft", "WinGet", "Packages",
			"SST.opencode_Microsoft.Winget.Source_8wekyb3d8bbwe", "opencode.exe"},
		{"AppData", "Roaming", "npm", "node_modules", "opencode-ai", "bin", "opencode.exe"},
	},
}

// windowsStandalonePerUserManagedExecutable returns the native image the
// guardian binds a per-user connector's executable admission to, or a reason
// the install cannot be managed. Connectors without protected executable
// admission return ("", "").
func windowsStandalonePerUserManagedExecutable(profileHome, connectorName string) (string, string) {
	if !connector.ProtectedSetupSelectionConnector(connectorName) {
		return "", ""
	}
	switch connectorName {
	case "hermes":
		candidate := hermespath.ManagedExecutablePathForUserHome(profileHome)
		if candidate == "" {
			return "", "no updater-managed Hermes executable path could be derived for this profile"
		}
		return windowsStandalonePlainExecutable(connectorName, candidate)
	case "amp", "opencode":
		var last string
		for _, relative := range windowsStandaloneManagedExecutableRelative[connectorName] {
			candidate := filepath.Join(append([]string{profileHome}, relative...)...)
			path, reason := windowsStandalonePlainExecutable(connectorName, candidate)
			if path == "" {
				last = reason
				continue
			}
			if connectorName == "opencode" && !connector.OpenCodeWindowsPackageIdentityVerified(path) {
				last = "the npm opencode-ai package identity could not be verified"
				continue
			}
			return path, ""
		}
		if connectorName == "opencode" {
			return "", "managed OpenCode requires the SST WinGet package or the npm opencode-ai package with its native opencode.exe; " + last
		}
		return "", "no native amp.exe was found under the user's npm global prefix; " + last
	default:
		return "", fmt.Sprintf("connector %s has no managed executable selection on Windows", connectorName)
	}
}

// windowsStandalonePlainExecutable returns candidate when it is a regular
// file reached through a plain (reparse-free) directory chain.
// A path this token cannot read is reported as such, never as missing: an
// elevated administrator's verify is refused by a per-user folder whose
// permissions leave Administrators out (an older release's owner-only
// setup step), while the guardian, as LocalSystem, reads it.
func windowsStandalonePlainExecutable(connectorName, candidate string) (string, string) {
	if err := winpath.RejectReparseChain(filepath.Dir(candidate)); err != nil {
		if errors.Is(err, os.ErrPermission) {
			return "", windowsStandaloneUnreadableExecutable(candidate)
		}
		return "", fmt.Sprintf("the %s install path is not a plain directory chain: %v", connectorName, err)
	}
	info, err := os.Lstat(candidate)
	if err != nil || !info.Mode().IsRegular() {
		if windowsStandaloneExecutableUnreadable(candidate, err) {
			return "", windowsStandaloneUnreadableExecutable(candidate)
		}
		return "", fmt.Sprintf("%s is not present", candidate)
	}
	return candidate, ""
}

// windowsStandaloneExecutableUnreadable reports whether this token cannot
// see candidate: its Lstat was refused, or the deepest folder on its path
// that exists cannot be listed (then an image elsewhere in that folder,
// such as another Hermes launcher, is invisible too). Replaceable in tests:
// an elevated test token may hold backup rights that read past any DACL.
var windowsStandaloneExecutableUnreadable = func(candidate string, lstatErr error) bool {
	if errors.Is(lstatErr, os.ErrPermission) {
		return true
	}
	for dir := filepath.Dir(candidate); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if _, err := os.Lstat(dir); err != nil {
			if errors.Is(err, os.ErrPermission) {
				return true
			}
			continue
		}
		folder, err := os.Open(dir)
		if err == nil {
			_, err = folder.Readdirnames(1)
			_ = folder.Close()
		}
		return errors.Is(err, os.ErrPermission)
	}
	return false
}

func windowsStandaloneUnreadableExecutable(candidate string) string {
	return fmt.Sprintf("%s cannot be read as this account (access denied: a folder on its path does not grant "+
		"Administrators access); the guardian runs as LocalSystem and can read it, so run verify as LocalSystem "+
		"to check this user (repair does not change this folder)", candidate)
}

// windowsStandaloneRowAdmission reports whether the guardian can manage one
// standalone row. Every connector, machine-policy or per-user, needs a
// version that resolves to a known hook contract: the lowest-contract floor
// alone admits versions above a contract's upper bound, outside an
// exact-version pin, or between bands, and those rows can never install. The
// version must also clear the standalone floor, whose Windows platform
// minimum can sit above a known contract's lower bound (Codex 0.131.0), since
// install and verify refuse anything below it. A row that fails is skipped
// with the returned reason, so one user's unsupported client fails closed for
// that user instead of failing the reconcile, and withholding enrollment
// publication, for everyone.
func windowsStandaloneRowAdmission(profileHome, connectorName, version string) (bool, string) {
	if resolution := connector.ResolveHookContract(connectorName, version); resolution.Status != connector.HookCompatibilityKnown {
		return false, fmt.Sprintf("version %s is not verified against a known hook contract", version)
	}
	if minimum := windowsEnterpriseStandaloneAgentMinimum(connectorName); minimum != "" {
		normalized := connector.NormalizeAgentVersion(connectorName, version)
		if normalized == "" || compareWindowsEnterpriseVersion(normalized, minimum) < 0 {
			return false, fmt.Sprintf("version %s is below the Windows enterprise minimum %s", version, minimum)
		}
	}
	return windowsStandalonePerUserAdmission(profileHome, connectorName, version)
}

// windowsStandalonePerUserAdmission reports whether the guardian can manage a
// per-user connector install for one user: the discovered version must have a
// known hook contract and any protected executable must be present. Rows that
// fail are skipped by the enumerator with the returned reason, so one user's
// unsupported install cannot fail the reconcile for everyone else.
func windowsStandalonePerUserAdmission(profileHome, connectorName, version string) (bool, string) {
	if _, perUser := windowsStandalonePerUserConnector(connectorName); !perUser {
		return true, ""
	}
	if resolution := connector.ResolveHookContract(connectorName, version); resolution.Status != connector.HookCompatibilityKnown {
		return false, fmt.Sprintf("version %s is not verified against a known hook contract", version)
	}
	if _, reason := windowsStandalonePerUserManagedExecutable(profileHome, connectorName); reason != "" {
		return false, reason
	}
	return true, ""
}
