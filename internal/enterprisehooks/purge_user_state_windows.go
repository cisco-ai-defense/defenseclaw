// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// PurgeWindowsUserState removes one enrolled account's DefenseClaw per-user
// state (%USERPROFILE%\.defenseclaw) for the standalone Windows uninstall
// with purge, after the uninstall committed and removed the registrations it
// could. It runs as LocalSystem, whether or not the account is signed in:
// some of the folder's subfolders grant only the account and SYSTEM, not
// Administrators. It keeps what the Unix purge keeps (the account's own
// hooks the foreign-hook policy moved aside, and each DefenseClaw hook script
// as the disabled stub, for an agent that still calls the hook path it
// loaded; see connector.PurgeUserStateInRoot) and removes the rest, including
// the per-user hook tokens. What it keeps goes back to a DACL the account can
// manage. A missing folder is not an error.
func PurgeWindowsUserState(rawHome, rawSID, rawDataDir string) error {
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return err
	}
	home, sid, err := validateWindowsEnterpriseHome(rawHome, rawSID)
	if err != nil {
		return err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, rawDataDir)
	if err != nil {
		return err
	}
	info, err := os.Lstat(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("enterprise hooks: refusing to purge %s, which is not a plain folder", dataDir)
	}
	// The account can rename or replace its own folder. A handle that does
	// not share delete access keeps it from doing so while the purge runs,
	// and the root must be the folder that handle holds.
	pin, err := openWindowsUserStatePin(dataDir)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		pin.Close()
		return err
	}
	purgeErr := func() error {
		pinned, err := pin.Stat()
		if err != nil {
			return err
		}
		opened, err := root.Stat(".")
		if err != nil {
			return err
		}
		if !pinned.IsDir() || pinned.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !os.SameFile(pinned, opened) {
			return fmt.Errorf("enterprise hooks: refusing to purge %s, which changed while it was opened", dataDir)
		}
		return connector.PurgeUserStateInRoot(root)
	}()
	root.Close()
	pin.Close()
	// Gone only when nothing stayed. Remove takes only an empty folder, and
	// a link put in its place only as the link itself.
	_ = os.Remove(dataDir)
	return errors.Join(purgeErr, relaxWindowsKeptUserState(home, sid, dataDir))
}

// relaxWindowsKeptUserState returns what the purge kept to the owner-private
// shape the per-user CLI keeps (LocalSystem and OWNER RIGHTS full control).
// The managed DACL's read-only OWNER RIGHTS entry denies the account
// WRITE_DAC, so a later per-user install could not protect its own folder and
// its first run failed with Access is denied. Only objects the account owns
// that carry that entry change, and a reparse point is neither followed nor
// changed.
func relaxWindowsKeptUserState(home string, sid *windows.SID, dataDir string) error {
	if _, err := os.Lstat(dataDir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	target := windowsGenericManagedTarget{home: home, sid: sid, dataDir: dataDir}
	var failures []error
	walkErr := filepath.WalkDir(dataDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			failures = append(failures, err)
			return nil
		}
		switch {
		case entry.IsDir():
			_, err = relaxWindowsStandalonePerUserDirectory(target, path)
		case entry.Type().IsRegular():
			_, err = relaxWindowsStandalonePerUserTokenFile(target, path)
		}
		if err != nil {
			failures = append(failures, err)
		}
		return nil
	})
	return errors.Join(walkErr, errors.Join(failures...))
}

// openWindowsUserStatePin opens the folder itself, not what a reparse point
// in its place would name, without sharing delete access.
func openWindowsUserStatePin(path string) (*os.File, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return nil, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: open %s: %w", path, err)
	}
	return os.NewFile(uintptr(handle), path), nil
}
