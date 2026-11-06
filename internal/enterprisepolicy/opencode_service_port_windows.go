//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// OpenCodeServicePortWritableAsUser reports whether the account-side writer
// can use the existing service file's parent path. The caller runs under the
// account token, so ownership and ACL checks use the same identity as a write.
func OpenCodeServicePortWritableAsUser(home string) bool {
	path := OpenCodeServiceConfigPath(home)
	for _, dir := range []string{filepath.Join(home, ".config"), filepath.Dir(path)} {
		if err := winpath.RejectReparseChain(dir); err != nil {
			return false
		}
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.IsDir() {
			return false
		}
		if err := safefile.ValidatePrivateDirectoryOwnershipAllowingAdministrators(dir); err != nil {
			return false
		}
	}
	return true
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

// writableDir reports whether dir is a folder; the write itself decides.
func writableDir(dir string) bool {
	info, err := os.Stat(dir)
	return err == nil && info.IsDir()
}
