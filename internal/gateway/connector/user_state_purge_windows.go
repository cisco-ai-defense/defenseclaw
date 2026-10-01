// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

// PurgeUserStateInRoot is PurgeUserState for the Windows uninstall, which
// runs it as LocalSystem on an account's data directory opened as root.
// Every step stays inside root and follows no link, so a link the account
// put in its folder cannot point the removal anywhere else. Each DefenseClaw
// hook script becomes the disabled stub in place, so it keeps the owner and
// access list the account needs to run it. It keeps what PurgeUserState
// keeps and removes the rest, including the per-user hook credentials; the
// caller removes the directory itself once nothing stayed. An entry whose
// access list refuses the removal goes to removeDenied, when set, with its
// path from root (the account can deny SYSTEM on a folder it owns).
func PurgeUserStateInRoot(root *os.Root, removeDenied func(rel string) error) error {
	names, err := rootEntryNames(root)
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range names {
		if name == foreignHooksBackupDir {
			continue
		}
		if name == "hooks" {
			if info, err := root.Lstat(name); err == nil && info.IsDir() {
				if err := purgeHookScriptsInRoot(root, removeDenied); err != nil {
					errs = append(errs, err)
				}
				continue
			}
		}
		if err := removeAllInRoot(root, name, name, removeDenied); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// removeAllInRoot removes name in dir. When the access list refuses it and
// removeDenied is set, removeDenied gets rel, the path from the purge root.
func removeAllInRoot(dir *os.Root, name, rel string, removeDenied func(string) error) error {
	err := dir.RemoveAll(name)
	if err == nil || removeDenied == nil || !errors.Is(err, fs.ErrPermission) {
		return err
	}
	if deniedErr := removeDenied(rel); deniedErr != nil {
		return errors.Join(err, deniedErr)
	}
	return nil
}

// purgeHookScriptsInRoot turns every DefenseClaw hook script in <root>/hooks
// into the disabled stub and removes everything else there (credentials,
// hook config, temporary files).
func purgeHookScriptsInRoot(root *os.Root, removeDenied func(string) error) error {
	hooks, err := root.OpenRoot("hooks")
	if err != nil {
		return err
	}
	names, err := rootEntryNames(hooks)
	if err != nil {
		hooks.Close()
		return err
	}
	var errs []error
	for _, name := range names {
		stubbed, err := stubHookScriptInRoot(hooks, name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if stubbed {
			continue
		}
		if err := removeAllInRoot(hooks, name, `hooks\`+name, removeDenied); err != nil {
			errs = append(errs, err)
		}
	}
	hooks.Close()
	// Gone only when nothing stayed.
	_ = root.Remove("hooks")
	return errors.Join(errs...)
}

// stubHookScriptInRoot overwrites name with the disabled stub when it is a
// DefenseClaw hook script: a regular file with the marker and no other name
// (a hard link would carry the write to a file outside the folder). It
// reports whether name is such a script. The write goes through the handle
// that read the marker; a stub is one short write, and an empty or cut-off
// stub still exits without forwarding anything.
func stubHookScriptInRoot(dir *os.Root, name string) (bool, error) {
	info, err := dir.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		return false, nil
	}
	file, err := dir.OpenFile(name, os.O_RDWR, 0)
	if errors.Is(err, fs.ErrPermission) && info.Mode().Perm()&0o200 == 0 {
		// The read-only attribute, not the access list, refused the write:
		// clear it (Chmod changes only that attribute on Windows) and retry.
		if chmodErr := dir.Chmod(name, 0o600); chmodErr == nil {
			file, err = dir.OpenFile(name, os.O_RDWR, 0)
		}
	}
	if err != nil {
		return false, err
	}
	defer file.Close()
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &handleInfo); err != nil {
		return false, err
	}
	if handleInfo.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		handleInfo.NumberOfLinks != 1 {
		return false, nil
	}
	head := make([]byte, 512)
	n, err := io.ReadFull(file, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return false, err
	}
	if !bytes.Contains(head[:n], []byte(hookMarker)) {
		return false, nil
	}
	stub := []byte(disabledHookTombstone("DefenseClaw"))
	if bytes.Equal(head[:n], stub) {
		return true, nil
	}
	if err := file.Truncate(0); err != nil {
		return true, err
	}
	if _, err := file.WriteAt(stub, 0); err != nil {
		return true, err
	}
	return true, file.Sync()
}

func rootEntryNames(root *os.Root) ([]string, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return dir.Readdirnames(-1)
}
