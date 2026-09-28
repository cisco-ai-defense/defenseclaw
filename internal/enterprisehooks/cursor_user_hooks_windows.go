// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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
// that per-user DefenseClaw setup left in the target user's
// %USERPROFILE%\.cursor\hooks.json. The managed Cursor hook treats them as
// foreign and denies every tool call while they remain, and nothing else in
// the managed deployment removes them.
//
// It runs after the managed install or repair is committed, as the target
// user, and never fails that install or repair: a file it cannot clean is
// left as it was, which is the behavior before this cleanup, and the reason
// is logged. Uninstall does not put the removed entries back, because they
// belong to the per-user installation the managed deployment replaced, and
// nothing else in the file was changed. The previous file is kept beside it
// as hooks.json.defenseclaw-backup for manual recovery.
func cleanupWindowsCursorPerUserHookRegistrations(target windowsGenericManagedTarget) {
	var cleanup windowsCursorUserHookCleanup
	err := connector.WithUserHomeDir(target.home, func() error {
		return windowsEnterpriseTargetImpersonation(target.sid, target.home, func() error {
			var err error
			cleanup, err = removeWindowsCursorPerUserHookRegistrations(target.home, target.dataDir)
			return err
		})
	})
	logWindowsCursorPerUserHookCleanup(target.home, cleanup, err)
}

// logWindowsCursorPerUserHookCleanup writes to os.Stderr as it is when the
// line is written. The guardian service points os.Stderr at its log file
// after this package is loaded, so a writer saved at package load would
// still be the service's original stderr, which has no destination.
func logWindowsCursorPerUserHookCleanup(home string, cleanup windowsCursorUserHookCleanup, err error) {
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"[enterprise-hooks] WARN: Cursor: per-user DefenseClaw hook registrations in %s were not removed: %v; "+
				"the managed Cursor hook denies tool calls until they are removed from that file\n",
			filepath.Join(home, ".cursor", "hooks.json"),
			err,
		)
		return
	}
	if len(cleanup.removed) == 0 {
		return
	}
	commands := make(map[string]struct{}, 2)
	for _, removal := range cleanup.removed {
		commands[removal.Command] = struct{}{}
	}
	names := make([]string, 0, len(commands))
	for command := range commands {
		names = append(names, fmt.Sprintf("%q", command))
	}
	sort.Strings(names)
	fmt.Fprintf(
		os.Stderr,
		"[enterprise-hooks] Cursor: removed %d per-user DefenseClaw hook registration(s) running %s from %s; "+
			"the previous file is kept at %s\n",
		len(cleanup.removed),
		strings.Join(names, ", "),
		cleanup.path,
		cleanup.backup,
	)
}

// removeWindowsCursorPerUserHookRegistrations does the cleanup for home and
// the per-user DefenseClaw data directory dataDir. The caller acts as the
// user who owns home. A missing file, or one without DefenseClaw
// registrations, is left untouched. A hooks.json that is a link, has other
// hard links, exceeds the size limit, is not one JSON object, or changes
// while it is being cleaned is left as it was and reported as an error.
func removeWindowsCursorPerUserHookRegistrations(home, dataDir string) (windowsCursorUserHookCleanup, error) {
	cursorDir := filepath.Join(home, ".cursor")
	cleanup := windowsCursorUserHookCleanup{
		path:   filepath.Join(cursorDir, "hooks.json"),
		backup: filepath.Join(cursorDir, windowsCursorUserHooksBackupName),
	}
	dirInfo, err := os.Lstat(cursorDir)
	if errors.Is(err, os.ErrNotExist) {
		return cleanup, nil
	}
	if err != nil {
		return cleanup, err
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return cleanup, fmt.Errorf("%s is not a plain folder", cursorDir)
	}
	original, found, err := readWindowsCursorUserHooks(cleanup.path)
	if err != nil || !found {
		return cleanup, err
	}
	updated, removed, err := connector.RemoveCursorPerUserHookRegistrations(original, dataDir)
	if err != nil {
		return cleanup, err
	}
	if len(removed) == 0 {
		return cleanup, nil
	}
	if info, err := os.Lstat(cleanup.backup); err == nil && !info.Mode().IsRegular() {
		return cleanup, fmt.Errorf("%s exists and is not a regular file", cleanup.backup)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return cleanup, err
	}
	if err := writeWindowsRuntimeRollbackFile(cleanup.backup, original); err != nil {
		return cleanup, fmt.Errorf("keep the previous file at %s: %w", cleanup.backup, err)
	}
	current, found, err := readWindowsCursorUserHooks(cleanup.path)
	if err != nil {
		return cleanup, err
	}
	if !found || !bytes.Equal(current, original) {
		return cleanup, fmt.Errorf("%s changed while DefenseClaw entries were being removed", cleanup.path)
	}
	if err := writeWindowsRuntimeRollbackFile(cleanup.path, updated); err != nil {
		return cleanup, err
	}
	cleanup.removed = removed
	return cleanup, nil
}

// readWindowsCursorUserHooks reads one regular, singly linked file through
// the runtime snapshot reader, which also rejects a file replaced while it is
// read. found is false when the file does not exist.
func readWindowsCursorUserHooks(path string) ([]byte, bool, error) {
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
