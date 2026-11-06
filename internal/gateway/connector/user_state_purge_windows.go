// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// PurgeUserStateInRoot is PurgeUserState for the Windows uninstall, which
// runs it as LocalSystem on an account's data directory opened as root.
// Every step stays inside root and follows no link. Only named managed files
// go; unknown account files stay even inside a managed directory. The caller
// removes the directory itself when it is empty. An owned file whose access
// list refuses the removal goes to removeDenied, when set.
func PurgeUserStateInRoot(root *os.Root, removeDenied func(rel string) error) error {
	return purgeUserStateInRootDir(root, ".", removeDenied)
}

func purgeUserStateInRootDir(root *os.Root, rel string, removeDenied func(string) error) error {
	names, err := rootEntryNames(root, ".")
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range names {
		child := filepath.Join(rel, name)
		info, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			// A known managed file may deny LocalSystem even a stat. The
			// privileged callback checks that it is a plain file before
			// removing it; it cannot remove an uninspected directory.
			if errors.Is(err, fs.ErrPermission) && ManagedUserStateFile(child) && removeDenied != nil {
				if deniedErr := removeDenied(child); deniedErr != nil {
					errs = append(errs, errors.Join(err, deniedErr))
				}
				continue
			}
			errs = append(errs, err)
			continue
		}
		switch {
		case info.IsDir() && ManagedUserStateDir(child):
			childRoot, err := root.OpenRoot(name)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			opened, openErr := childRoot.Stat(".")
			if openErr != nil || !os.SameFile(info, opened) {
				_ = childRoot.Close()
				errs = append(errs, fmt.Errorf("per-user state directory changed while opening: %s", child))
				continue
			}
			if err := purgeUserStateInRootDir(childRoot, child, removeDenied); err != nil {
				errs = append(errs, err)
			}
			_ = childRoot.Close()
			if current, statErr := root.Lstat(name); statErr != nil || !os.SameFile(info, current) {
				errs = append(errs, fmt.Errorf("per-user state directory changed before removal: %s", child))
				continue
			}
			if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, fs.ErrExist) {
				// A nonempty directory holds account files and stays.
				if names, listErr := rootEntryNames(root, name); listErr != nil || len(names) == 0 {
					errs = append(errs, err)
				}
			}
		case info.Mode().IsRegular() && ManagedUserStateFile(child):
			if err := removeManagedFileInRoot(root, name, child, removeDenied); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// removeManagedFileInRoot removes one file. When the access list refuses it and
// removeDenied is set, removeDenied gets rel, the path from the purge root.
func removeManagedFileInRoot(dir *os.Root, name, rel string, removeDenied func(string) error) error {
	err := dir.Remove(name)
	if err == nil || removeDenied == nil || !errors.Is(err, fs.ErrPermission) {
		return err
	}
	if deniedErr := removeDenied(rel); deniedErr != nil {
		return errors.Join(err, deniedErr)
	}
	return nil
}

func rootEntryNames(root *os.Root, rel string) ([]string, error) {
	dir, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return dir.Readdirnames(-1)
}
