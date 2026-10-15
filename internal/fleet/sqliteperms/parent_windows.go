// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package sqliteperms

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// SQLite creates WAL and shared-memory files after the database is opened.
// Protect their parent first so newly created journals cannot inherit a
// readable DACL, even briefly before Secure sees them.
func protectParent(dbPath string) error {
	return safefile.ProtectDirectory(filepath.Dir(dbPath))
}

// Windows mode bits do not describe the DACL and os.Chmod cannot remove
// inherited Users/Everyone access. Try the handle-bound in-use path first.
// An elevated token may assign Administrators ownership to a new file;
// ProtectFile normalizes that owner in ordinary process mode if needed.
func secureFile(path string, _ os.FileInfo) error {
	if handleErr := safefile.ProtectFileWhileInUse(path); handleErr != nil {
		// The ordinary Safefile writer can take ownership. Restrict that
		// fallback to the current user or the local Administrators group
		// under an elevated token; never bless a foreign user's file.
		allowed, err := canNormalizeSQLiteOwner(path)
		if err != nil {
			return err
		}
		if !allowed {
			return handleErr
		}
		if err := safefile.ProtectFile(path); err != nil {
			return fmt.Errorf("in-use protection: %v; owner normalization: %w", handleErr, err)
		}
	}
	return safefile.ValidatePrivateFile(path)
}

func canNormalizeSQLiteOwner(path string) (bool, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return false, err
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	if sd == nil {
		return false, fmt.Errorf("SQLite file security descriptor unavailable")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, err
	}
	if user == nil || user.User.Sid == nil {
		return false, fmt.Errorf("current Windows user SID unavailable")
	}
	if owner.Equals(user.User.Sid) {
		return true, nil
	}
	if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return false, nil
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false, err
	}
	return windows.Token(0).IsMember(administrators)
}
