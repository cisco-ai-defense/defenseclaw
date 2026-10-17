// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winfolders"
	"golang.org/x/sys/windows"
)

// windowsCursorUserHooksBackupName is the copy of a user's
// %USERPROFILE%\.cursor\hooks.json kept, beside it, from just before the
// managed installer removed per-user DefenseClaw registrations from it.
const windowsCursorUserHooksBackupName = "hooks.json.defenseclaw-backup"

// windowsCursorUserHookCleanup reports what one cleanup changed.
type windowsCursorUserHookCleanup struct {
	path    string
	backup  string
	removed []connector.CursorUserHookRemoval
}

// cleanupWindowsCursorPerUserHookRegistrations removes the registrations
// that per-user DefenseClaw setup left in the target user's hook files that
// the managed Cursor hook checks: %USERPROFILE%\.cursor\hooks.json, written
// by per-user Cursor setup, and %USERPROFILE%\.claude\settings.json, written
// by per-user Claude Code setup, whose hooks Cursor also loads. The managed
// Cursor hook treats them as foreign and denies every tool call while they
// remain, and nothing else in the managed deployment removes them.
//
// It runs after the managed install or repair is committed, as the target
// user, and never fails that install or repair: a file it cannot clean is
// left as it was, which is the behavior before this cleanup, and the reason
// is logged unless the file holds none of those registrations. Each file is
// cleaned on its own. Uninstall does not put the
// removed entries back, because they belong to the per-user installation the
// managed deployment replaced, and nothing else in the files was changed.
// The previous file is kept beside it as hooks.json.defenseclaw-backup or
// settings.json.defenseclaw-backup for manual recovery.
func cleanupWindowsCursorPerUserHookRegistrations(target windowsGenericManagedTarget) {
	var cursor windowsCursorUserHookCleanup
	var claude windowsClaudeUserHookCleanup
	var cursorErr, claudeErr error
	err := connector.WithUserHomeDir(target.home, func() error {
		return windowsEnterpriseTargetImpersonation(target.sid, target.home, func() error {
			localAppData, userProgramFiles, err := windowsCursorTargetUserFolders()
			if err != nil {
				return err
			}
			cursor, cursorErr = removeWindowsCursorPerUserHookRegistrations(target.home, connector.CursorPerUserInstall{
				DataDir:          target.dataDir,
				LocalAppData:     localAppData,
				UserProgramFiles: userProgramFiles,
			})
			claude, claudeErr = removeWindowsClaudePerUserHookRegistrations(target.home, connector.ClaudeCodePerUserInstall{
				LocalAppData:     localAppData,
				UserProgramFiles: userProgramFiles,
			})
			return nil
		})
	})
	if err != nil {
		cursorErr, claudeErr = err, err
	}
	logWindowsCursorPerUserHookCleanup(target.home, cursor, cursorErr)
	logWindowsClaudePerUserHookCleanup(target.home, claude, claudeErr)
}

// windowsCursorTargetUserFolders resolves the LocalAppData and per-user
// Programs Known Folders of the user the calling thread impersonates.
var windowsCursorTargetUserFolders = resolveWindowsImpersonatedUserFolders

// resolveWindowsImpersonatedUserFolders reads the Known Folders from the
// calling thread's impersonation token. The connector's own Known Folder
// lookups use the process token, which in the guardian is LocalSystem's, so
// they do not name the target user's folders. Without an impersonation token
// it fails instead of using the process user's folders.
func resolveWindowsImpersonatedUserFolders() (localAppData, userProgramFiles string, err error) {
	var token windows.Token
	if err := windows.OpenThreadToken(
		windows.CurrentThread(),
		windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE,
		true,
		&token,
	); err != nil {
		return "", "", fmt.Errorf("open the target user's thread token: %w", err)
	}
	defer token.Close()
	localAppData, err = token.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_NO_PACKAGE_REDIRECTION)
	if err != nil {
		return "", "", fmt.Errorf("resolve the target user's LocalAppData folder: %w", err)
	}
	if strings.TrimSpace(localAppData) == "" {
		return "", "", errors.New("the target user's LocalAppData folder is empty")
	}
	userProgramFiles, err = winfolders.UserProgramFilesForToken(token)
	if err != nil {
		return "", "", fmt.Errorf("resolve the target user's Programs folder: %w", err)
	}
	return filepath.Clean(localAppData), userProgramFiles, nil
}

func logWindowsCursorPerUserHookCleanup(home string, cleanup windowsCursorUserHookCleanup, err error) {
	commands := make([]string, 0, len(cleanup.removed))
	for _, removal := range cleanup.removed {
		commands = append(commands, removal.Command)
	}
	logWindowsPerUserHookCleanup("Cursor", filepath.Join(home, ".cursor", "hooks.json"), cleanup.backup, commands, err)
}

// logWindowsPerUserHookCleanup logs one file's cleanup: a warning when err is
// set, one line naming the removed commands when some were removed, and
// nothing otherwise. It writes to os.Stderr as it is when the line is
// written. The guardian service points os.Stderr at its log file after this
// package is loaded, so a writer saved at package load would still be the
// service's original stderr, which has no destination.
func logWindowsPerUserHookCleanup(label, path, backup string, commands []string, err error) {
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"[enterprise-hooks] WARN: %s: per-user DefenseClaw hook registrations in %s were not removed: %v; "+
				"the managed Cursor hook denies tool calls until they are removed from that file\n",
			label,
			path,
			err,
		)
		return
	}
	if len(commands) == 0 {
		return
	}
	unique := make(map[string]struct{}, 2)
	for _, command := range commands {
		unique[command] = struct{}{}
	}
	names := make([]string, 0, len(unique))
	for command := range unique {
		names = append(names, fmt.Sprintf("%q", command))
	}
	sort.Strings(names)
	fmt.Fprintf(
		os.Stderr,
		"[enterprise-hooks] %s: removed %d per-user DefenseClaw hook registration(s) running %s from %s; "+
			"the previous file is kept at %s\n",
		label,
		len(commands),
		strings.Join(names, ", "),
		path,
		backup,
	)
}

// removeWindowsCursorPerUserHookRegistrations does the cleanup for home and
// the per-user DefenseClaw installation install. The caller acts as the
// user who owns home. A missing file, or one without DefenseClaw
// registrations, is left untouched. A hooks.json that is a link, has other
// hard links, exceeds the size limit, is not one JSON object, or changes
// while it is being cleaned is left as it was and reported as an error; a
// linked .cursor folder or hooks.json, another hard link or a repeated key
// is reported only when the file holds DefenseClaw registrations.
func removeWindowsCursorPerUserHookRegistrations(home string, install connector.CursorPerUserInstall) (windowsCursorUserHookCleanup, error) {
	cursorDir := filepath.Join(home, ".cursor")
	cleanup := windowsCursorUserHookCleanup{
		path:   filepath.Join(cursorDir, "hooks.json"),
		backup: filepath.Join(cursorDir, windowsCursorUserHooksBackupName),
	}
	var removed []connector.CursorUserHookRemoval
	changed, err := rewriteWindowsPerUserHookFile(cursorDir, cleanup.path, cleanup.backup, func(original []byte) ([]byte, bool, error) {
		updated, found, err := connector.RemoveCursorPerUserHookRegistrations(original, install)
		removed = found
		return updated, len(found) > 0, err
	})
	if err != nil || !changed {
		return cleanup, err
	}
	cleanup.removed = removed
	return cleanup, nil
}

// rewriteWindowsPerUserHookFile replaces the per-user hook file path in
// folder with what edit returns for it, after keeping the previous file at
// backup, and reports whether it did. The caller acts as the user who owns
// folder. A missing folder or file, or an edit that changes nothing, leaves
// both files untouched. A folder that is not a plain folder, a file that is a
// link, has other hard links or exceeds the size limit, a backup path that is
// not a regular file, an edit error, and a file that changes while it is
// being edited are reported as errors, and the file is left as it was. A
// folder or file refused before the edit is reported only when the file holds
// something edit would remove (windowsPerUserHookFileRefusal).
func rewriteWindowsPerUserHookFile(folder, path, backup string, edit func([]byte) ([]byte, bool, error)) (bool, error) {
	dirInfo, err := os.Lstat(folder)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return false, windowsPerUserHookFileRefusal(path, edit, fmt.Errorf("%s is not a plain folder", folder))
	}
	original, found, err := readWindowsPerUserHookFile(path)
	if err != nil {
		return false, windowsPerUserHookFileRefusal(path, edit, err)
	}
	if !found {
		return false, nil
	}
	updated, changed, err := edit(original)
	if err != nil || !changed {
		return false, err
	}
	if info, err := os.Lstat(backup); err == nil && !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s exists and is not a regular file", backup)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := writeWindowsRuntimeRollbackFile(backup, original); err != nil {
		return false, fmt.Errorf("keep the previous file at %s: %w", backup, err)
	}
	current, found, err := readWindowsPerUserHookFile(path)
	if err != nil {
		return false, err
	}
	if !found || !bytes.Equal(current, original) {
		return false, fmt.Errorf("%s changed while DefenseClaw entries were being removed", path)
	}
	if err := writeWindowsRuntimeRollbackFile(path, updated); err != nil {
		return false, err
	}
	return true, nil
}

// windowsPerUserHookFileRefusal returns refusal, the reason path is not
// edited, unless path holds nothing edit would remove. The managed Cursor
// hook reads the file through a linked folder and whatever other hard links
// it has, so a file without DefenseClaw's registrations is not why that hook
// denies, and reporting refusal would say it is. The file is read through
// links only to look at it and is never written here. A file that cannot be
// read or decoded this way keeps refusal.
func windowsPerUserHookFileRefusal(path string, edit func([]byte) ([]byte, bool, error), refusal error) error {
	data, found, err := readWindowsPerUserHookFileToLook(path)
	if err != nil {
		return refusal
	}
	if !found {
		return nil
	}
	if _, changed, err := edit(data); err == nil && !changed {
		return nil
	}
	return refusal
}

// readWindowsPerUserHookFileToLook reads path, following links, up to the
// size limit. found is false when nothing is there or it is a folder, which
// the managed Cursor hook does not load either.
func readWindowsPerUserHookFileToLook(path string) ([]byte, bool, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if info.IsDir() {
		return nil, false, nil
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, windowsEnterpriseUserFileMaxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > windowsEnterpriseUserFileMaxBytes {
		return nil, false, fmt.Errorf("%s exceeds %d bytes", path, windowsEnterpriseUserFileMaxBytes)
	}
	return data, true, nil
}

// readWindowsPerUserHookFile reads one regular, singly linked file through
// the runtime snapshot reader, which also rejects a file replaced while it is
// read. found is false when the file does not exist.
func readWindowsPerUserHookFile(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > windowsEnterpriseUserFileMaxBytes {
		return nil, false, fmt.Errorf("%s exceeds %d bytes", path, windowsEnterpriseUserFileMaxBytes)
	}
	data, err := readWindowsRuntimeSnapshotFile(path, info)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}
