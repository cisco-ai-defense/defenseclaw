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

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// relaxWindowsStandalonePerUserFootprintForSetup returns the per-user
// connector directories the guardian hardened on an earlier reconcile to the
// owner-private shape the connector's own setup maintains, so a repair can
// run the connector under the target user's token. The hardened DACL removes
// the owner's WRITE_DAC (OWNER RIGHTS is read-only), so without this a second
// reconcile of an already-hardened footprint fails and the user's agent stays
// unprotected. It runs as LocalSystem, changes only the DACL of directories
// that already exist and are owned by the target SID, and the caller hardens
// the footprint again right after setup.
// windowsGuardianHardenedOwnerRightsACE is the read-only OWNER RIGHTS entry
// the guardian's managed footprint DACL carries; it is what removes the
// owner's WRITE_DAC.
const windowsGuardianHardenedOwnerRightsACE = "(A;;RC;;;OW)"

func relaxWindowsStandalonePerUserFootprintForSetup(target windowsGenericManagedTarget, configPaths []string, footprint connector.AgentPaths) error {
	if _, perUser := windowsStandalonePerUserConnector(target.conn.Name()); !perUser {
		return nil
	}
	dirs := append([]string{
		filepath.Join(target.dataDir, "connector_backups", target.conn.Name()),
	}, footprint.CreatedDirs...)
	// The connector also re-protects the directories that hold its generated
	// hook files and plugins.
	for _, group := range [][]string{footprint.GeneratedFiles, footprint.HookScripts, footprint.PatchedFiles} {
		for _, file := range group {
			dirs = append(dirs, filepath.Dir(filepath.Clean(file)))
		}
	}
	for _, path := range sortedUnique(dirs) {
		if err := relaxWindowsStandalonePerUserDirectory(target, path); err != nil {
			return err
		}
	}
	// A whole-file plugin the guardian hardened on an older release, or whose
	// DACL the user rewrote, gets the managed plugin DACL back so the
	// connector can republish it.
	for path := range windowsStandalonePrivatePluginPaths(target, configPaths) {
		if !windowsPathWithin(target.home, path) {
			return fmt.Errorf("enterprise hooks: managed plugin is outside the user home: %s", path)
		}
		if err := restoreWindowsPrivatePluginFile(target.home, path, target.sid); err != nil {
			return err
		}
	}
	return nil
}

// relaxWindowsStandalonePerUserFootprintForSetupAsService runs the relax
// step with the guardian's own token from inside the target-user
// impersonation: a new goroutine runs on another OS thread, which carries
// only the LocalSystem process token (the hardened DACL denies the target
// user WRITE_DAC).
func relaxWindowsStandalonePerUserFootprintForSetupAsService(target windowsGenericManagedTarget, configPaths []string, footprint connector.AgentPaths) error {
	done := make(chan error, 1)
	go func() { done <- relaxWindowsStandalonePerUserFootprintForSetup(target, configPaths, footprint) }()
	return <-done
}

func relaxWindowsStandalonePerUserDirectory(target windowsGenericManagedTarget, path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("enterprise hooks: per-user footprint directory is not absolute and clean: %s", path)
	}
	if !windowsPathWithin(target.home, path) {
		return fmt.Errorf("enterprise hooks: per-user footprint directory is outside the user home: %s", path)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect per-user footprint directory %s: %w", path, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("enterprise hooks: per-user footprint path is not a plain directory: %s", path)
	}
	if err := winpath.RejectReparseChain(path); err != nil {
		return fmt.Errorf("enterprise hooks: per-user footprint directory %s: %w", path, err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("enterprise hooks: read owner of %s: %w", path, err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(target.sid) {
		// Not the target's own directory; leave it for the ordinary custody
		// checks to report.
		return nil
	}
	current, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("enterprise hooks: read DACL of %s: %w", path, err)
	}
	if !strings.Contains(current.String(), windowsGuardianHardenedOwnerRightsACE) {
		// Only directories the guardian itself hardened are returned to the
		// owner-private shape; a user's own directories are never rewritten.
		return nil
	}
	private, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)")
	if err != nil {
		return err
	}
	dacl, _, err := private.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("enterprise hooks: prepare per-user footprint directory %s for setup: %w", path, err)
	}
	return nil
}

func windowsPathWithin(root, path string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && relative != "." && relative != ".." &&
		!filepath.IsAbs(relative) && len(relative) > 0 &&
		!(len(relative) >= 3 && relative[:3] == `..\`)
}
