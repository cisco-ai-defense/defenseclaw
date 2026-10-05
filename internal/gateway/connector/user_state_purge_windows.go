// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"io/fs"
	"os"
)

// PurgeUserStateInRoot is PurgeUserState for the Windows uninstall, which
// runs it as LocalSystem on an account's data directory opened as root.
// Every step stays inside root and follows no link, so a link the account
// put in its folder cannot point the removal anywhere else. Like
// PurgeUserState it removes everything in root: DefenseClaw's hook scripts,
// the per-user hook credentials, and the account's own hooks the
// foreign-hook policy moved aside (foreign-hooks-backup). The caller removes
// the directory itself. An entry whose access list refuses the removal goes
// to removeDenied, when set, with its path from root (the account can deny
// SYSTEM on a folder it owns).
func PurgeUserStateInRoot(root *os.Root, removeDenied func(rel string) error) error {
	names, err := rootEntryNames(root)
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range names {
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

func rootEntryNames(root *os.Root) ([]string, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return dir.Readdirnames(-1)
}
