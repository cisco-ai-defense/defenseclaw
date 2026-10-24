// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package audit

import "os"

// syncDatabaseFileData writes the database file's dirty pages to the disk.
func syncDatabaseFileData(f *os.File) error {
	return f.Sync()
}
