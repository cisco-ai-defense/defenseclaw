// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package fleet

import (
	"fmt"
	"os"
)

func widenSQLiteFileAccess(path string) error { return os.Chmod(path, 0o644) }

func widenSQLiteParentAccess(path string) error { return os.Chmod(path, 0o755) }

func assertSQLiteParentPrivate(string) error { return nil }

func assertSQLiteFilePrivate(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if got := info.Mode().Perm(); got != 0o600 {
		return fmt.Errorf("mode=%04o, want 0600", got)
	}
	return nil
}
