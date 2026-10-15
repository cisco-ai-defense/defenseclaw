// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package sqliteperms secures Fleet SQLite database and journal files.
package sqliteperms

import (
	"fmt"
	"os"
)

// Prepare creates a private database file, and fixes permissions on any
// existing database, WAL, and shared-memory files before SQLite opens them.
// It refuses symlinks and other non-regular files in these positions.
func Prepare(dbPath string) error {
	if err := Secure(dbPath); err != nil {
		return err
	}
	f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		if closeErr := f.Close(); closeErr != nil {
			return fmt.Errorf("close new SQLite database %s: %w", dbPath, closeErr)
		}
	} else if !os.IsExist(err) {
		return fmt.Errorf("create SQLite database %s: %w", dbPath, err)
	}
	return Secure(dbPath)
}

// Secure applies owner-only permissions to all existing SQLite files. Call it
// again after schema setup to cover journal files SQLite created on first use.
func Secure(dbPath string) error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		path := dbPath + suffix
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("stat SQLite file %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("SQLite file %s is not a regular file", path)
		}
		if info.Mode().Perm() != 0o600 {
			if err := os.Chmod(path, 0o600); err != nil {
				return fmt.Errorf("restrict SQLite file %s: %w", path, err)
			}
		}
	}
	return nil
}
