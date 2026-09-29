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

func relaxWindowsStandalonePerUserFootprintForSetup(target windowsGenericManagedTarget, configPaths []string, footprint connector.AgentPaths) ([]string, error) {
	if _, perUser := windowsStandalonePerUserConnector(target.conn.Name()); !perUser {
		return nil, nil
	}
	dirs := append([]string{
		filepath.Join(target.dataDir, "connector_backups", target.conn.Name()),
	}, footprint.CreatedDirs...)
	// Hermes keeps its lifecycle lock in <data dir> itself, and hardening
	// after any earlier connector left that directory without the owner's
	// WRITE_DAC.
	if windowsStandaloneSetupProtectsDataDir(target.conn.Name()) {
		dirs = append(dirs, target.dataDir)
	}
	// The connector also re-protects the directories that hold its generated
	// hook files and plugins.
	for _, group := range [][]string{footprint.GeneratedFiles, footprint.HookScripts, footprint.PatchedFiles} {
		for _, file := range group {
			dirs = append(dirs, filepath.Dir(filepath.Clean(file)))
		}
	}
	var relaxed []string
	for _, path := range sortedUnique(dirs) {
		changed, err := relaxWindowsStandalonePerUserDirectory(target, path)
		if changed {
			relaxed = append(relaxed, path)
		}
		if err != nil {
			return relaxed, err
		}
	}
	// A plugin connector's scoped hook token is republished under the user's
	// token with the existing file's exact protection; the hardened DACL
	// denies the owner the WRITE_DAC that publication needs.
	if connector.RequiresScopedHookToken(target.conn) {
		tokenPath, err := connector.HookAPITokenFilePath(target.dataDir, target.conn.Name())
		if err != nil {
			return relaxed, fmt.Errorf("enterprise hooks: resolve connector-scoped token sidecar: %w", err)
		}
		changed, err := relaxWindowsStandalonePerUserTokenFile(target, tokenPath)
		if changed {
			relaxed = append(relaxed, tokenPath)
		}
		if err != nil {
			return relaxed, err
		}
	}
	// A whole-file plugin the guardian hardened on an older release, or whose
	// DACL the user rewrote, gets the managed plugin DACL back so the
	// connector can republish it.
	for path := range windowsStandalonePrivatePluginPaths(target, configPaths) {
		if !windowsPathWithin(target.home, path) {
			return relaxed, fmt.Errorf("enterprise hooks: managed plugin is outside the user home: %s", path)
		}
		if err := restoreWindowsPrivatePluginFile(target.home, path, target.sid); err != nil {
			return relaxed, err
		}
	}
	return relaxed, nil
}

// relaxWindowsStandalonePerUserFootprintForSetupAsService runs the relax
// step with the guardian's own token from inside the target-user
// impersonation: a new goroutine runs on another OS thread, which carries
// only the LocalSystem process token (the hardened DACL denies the target
// user WRITE_DAC). It returns the directories it relaxed.
func relaxWindowsStandalonePerUserFootprintForSetupAsService(target windowsGenericManagedTarget, configPaths []string, footprint connector.AgentPaths) ([]string, error) {
	type outcome struct {
		relaxed []string
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		relaxed, err := relaxWindowsStandalonePerUserFootprintForSetup(target, configPaths, footprint)
		done <- outcome{relaxed: relaxed, err: err}
	}()
	result := <-done
	return result.relaxed, result.err
}

// restoreWindowsRelaxedPerUserDirectories gives the directories (and the scoped
// hook token) relaxed for a connector setup that then failed the canonical
// managed DACL again, the same
// way hardening does after a successful setup. Without it a failed setup left
// <data dir>\hooks owner-private: every later managed-runtime check for that
// user, and every administrator lifecycle retire, refused the directory. It
// runs inside the target-user impersonation; the relaxed DACL gives the owner
// the WRITE_DAC this needs.
func restoreWindowsRelaxedPerUserDirectories(target windowsGenericManagedTarget, relaxed []string) error {
	var failures []error
	for index := len(relaxed) - 1; index >= 0; index-- {
		wantDir, label := true, "relaxed setup directory"
		if info, err := os.Lstat(relaxed[index]); err == nil && !info.IsDir() {
			wantDir, label = false, "relaxed setup file"
		}
		if err := prepareWindowsGenericPath(target.home, relaxed[index], target.sid, wantDir, false, true, label); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// windowsSetupRelaxedDirectorySDDL is the owner-private DACL a connector
// setup needs on a guardian-hardened directory: LocalSystem and OWNER RIGHTS
// full control, inherited by new children.
const windowsSetupRelaxedDirectorySDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)"

// relaxWindowsStandalonePerUserDirectory returns one guardian-hardened
// directory to the owner-private setup shape and reports whether it changed
// it. It sets the DACL of that directory only. SetNamedSecurityInfo also
// rewrites the inherited ACEs of every existing descendant, and a connector
// home can hold the agent's whole install (Hermes keeps its checkout, virtual
// environment and caches, about 130,000 objects, under %LOCALAPPDATA%\hermes),
// so one reconcile spent minutes walking that tree and the lifecycle stopped
// the guardian halfway through it.
func relaxWindowsStandalonePerUserDirectory(target windowsGenericManagedTarget, path string) (bool, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false, fmt.Errorf("enterprise hooks: per-user footprint directory is not absolute and clean: %s", path)
	}
	if !windowsPathWithin(target.home, path) {
		return false, fmt.Errorf("enterprise hooks: per-user footprint directory is outside the user home: %s", path)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: inspect per-user footprint directory %s: %w", path, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("enterprise hooks: per-user footprint path is not a plain directory: %s", path)
	}
	if err := winpath.RejectReparseChain(path); err != nil {
		return false, fmt.Errorf("enterprise hooks: per-user footprint directory %s: %w", path, err)
	}
	handle, err := openWindowsPerUserDirectoryForDACL(path)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: open per-user footprint directory %s: %w", path, err)
	}
	defer windows.CloseHandle(handle)
	// Every check below is bound to the handle that receives the DACL.
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &handleInfo); err != nil {
		return false, fmt.Errorf("enterprise hooks: inspect per-user footprint directory %s: %w", path, err)
	}
	if handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, fmt.Errorf("enterprise hooks: per-user footprint path is not a plain directory: %s", path)
	}
	owner, err := windowsHandleOwner(handle)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: read owner of %s: %w", path, err)
	}
	if owner == nil || !owner.Equals(target.sid) {
		// Not the target's own directory; leave it for the ordinary custody
		// checks to report.
		return false, nil
	}
	current, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: read DACL of %s: %w", path, err)
	}
	if !strings.Contains(current.String(), windowsGuardianHardenedOwnerRightsACE) {
		// Only directories the guardian itself hardened are returned to the
		// owner-private shape; a user's own directories are never rewritten.
		return false, nil
	}
	private, err := windows.SecurityDescriptorFromString(windowsSetupRelaxedDirectorySDDL)
	if err != nil {
		return false, err
	}
	dacl, _, err := private.DACL()
	if err != nil {
		return false, err
	}
	if err := setWindowsObjectDACLNoPropagation(handle, dacl, true); err != nil {
		return false, fmt.Errorf("enterprise hooks: prepare per-user footprint directory %s for setup: %w", path, err)
	}
	return true, nil
}

// windowsSetupRelaxedFileSDDL is the owner-private DACL a connector setup needs
// on a guardian-hardened file it republishes: LocalSystem and OWNER RIGHTS full
// control. Hardening gives the file the managed footprint DACL again.
const windowsSetupRelaxedFileSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;OW)"

// windowsStandaloneSetupProtectsDataDir reports whether the connector's own
// setup and teardown keep lifecycle state in <data dir> itself (Hermes keeps
// .hermes-lifecycle.lock there), so the relax step returns that directory to
// the owner-private shape too.
func windowsStandaloneSetupProtectsDataDir(name string) bool {
	return strings.EqualFold(strings.TrimSpace(name), "hermes")
}

// relaxWindowsStandalonePerUserTokenFile returns a guardian-hardened
// connector-scoped hook token to the owner-private shape and reports whether it
// changed it. Token publication stages the replacement with the existing
// file's exact protection and then needs WRITE_DAC on it, which the hardened
// DACL (read-only OWNER RIGHTS) denies the owner, so every republication over a
// token an earlier reconcile hardened failed with Access Denied. Only a
// target-owned, single-link, non-reparse regular file carrying the guardian's
// hardened OWNER RIGHTS entry is changed; anything else is left for the token
// custody checks to report.
func relaxWindowsStandalonePerUserTokenFile(target windowsGenericManagedTarget, path string) (bool, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false, fmt.Errorf("enterprise hooks: per-user token path is not absolute and clean: %s", path)
	}
	if !windowsPathWithin(target.home, path) {
		return false, fmt.Errorf("enterprise hooks: per-user token path is outside the user home: %s", path)
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: inspect per-user token %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("enterprise hooks: per-user token path is not a regular file: %s", path)
	}
	if err := winpath.RejectReparseChain(path); err != nil {
		return false, fmt.Errorf("enterprise hooks: per-user token %s: %w", path, err)
	}
	handle, err := openWindowsPerUserDirectoryForDACL(path)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: open per-user token %s: %w", path, err)
	}
	defer windows.CloseHandle(handle)
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &handleInfo); err != nil {
		return false, fmt.Errorf("enterprise hooks: inspect per-user token %s: %w", path, err)
	}
	if handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, fmt.Errorf("enterprise hooks: per-user token path is not a regular file: %s", path)
	}
	if handleInfo.NumberOfLinks != 1 {
		return false, fmt.Errorf("enterprise hooks: refusing per-user token with %d hard links: %s", handleInfo.NumberOfLinks, path)
	}
	owner, err := windowsHandleOwner(handle)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: read owner of %s: %w", path, err)
	}
	if owner == nil || !owner.Equals(target.sid) {
		return false, nil
	}
	current, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: read DACL of %s: %w", path, err)
	}
	if !strings.Contains(current.String(), windowsGuardianHardenedOwnerRightsACE) {
		return false, nil
	}
	private, err := windows.SecurityDescriptorFromString(windowsSetupRelaxedFileSDDL)
	if err != nil {
		return false, err
	}
	dacl, _, err := private.DACL()
	if err != nil {
		return false, err
	}
	if err := setWindowsObjectDACLNoPropagation(handle, dacl, false); err != nil {
		return false, fmt.Errorf("enterprise hooks: prepare per-user token %s for setup: %w", path, err)
	}
	return true, nil
}

// openWindowsPerUserDirectoryForDACL opens a directory (or a file) for a DACL
// update without following a final reparse point.
func openWindowsPerUserDirectoryForDACL(path string) (windows.Handle, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return 0, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(
		ptr,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
}

func windowsPathWithin(root, path string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && relative != "." && relative != ".." &&
		!filepath.IsAbs(relative) && len(relative) > 0 &&
		!(len(relative) >= 3 && relative[:3] == `..\`)
}
