//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Windows reparse points include forms that os.Lstat does not call symlinks.
func openCodeServiceDirIsReal(path string) bool {
	return winpath.RejectReparseChain(path) == nil
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
