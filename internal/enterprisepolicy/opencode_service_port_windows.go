//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

// checkOpenCodeServiceConfigFolders runs the folder checks the write runs,
// without creating anything: a reparse point on the way, or a folder another
// account can write, is refused whether or not the port already matches.
func checkOpenCodeServiceConfigFolders(home, path string) ([]string, error) {
	for _, dir := range []string{filepath.Join(home, ".config"), filepath.Dir(path)} {
		if err := safefile.RejectReparseChain(dir); err != nil {
			return nil, err
		}
		if _, err := os.Lstat(dir); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if err := safefile.ValidatePrivateDirectoryOwnershipAllowingAdministrators(dir); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// openCodeServiceFileShared reports a service.json whose owner or write
// entries are not the account and the system owners: the write replaces it
// with a copy that has the account's private DACL.
func openCodeServiceFileShared(path string) bool {
	return safefile.ValidatePrivateFileOwnershipAllowingAdministrators(path) != nil
}

// service.json may carry OpenCode's password. Its new content gets the
// effective account's private file DACL while existing vendor directories
// keep their own ACLs. A directory another account can write is refused.
func writeOpenCodeServiceConfig(home, path string, data []byte) error {
	for _, dir := range []string{filepath.Join(home, ".config"), filepath.Dir(path)} {
		if _, err := safefile.CreatePrivateDirectory(dir); err != nil {
			return err
		}
		if err := safefile.ValidatePrivateDirectoryOwnershipAllowingAdministrators(dir); err != nil {
			return err
		}
	}
	return safefile.Write(path, data)
}

// openCodeImportFileTrusted reports that the open service.json belongs to the
// account or the system owners and no other account has write access. It asks
// the handle, so a final link the open followed is judged by its target (the
// writer still refuses a final link) and what is read is what was checked.
func openCodeImportFileTrusted(_ string, file *os.File) bool {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	return safefile.ValidatePrivateFileHandleAllowingAdministrators(windows.Handle(file.Fd())) == nil
}
