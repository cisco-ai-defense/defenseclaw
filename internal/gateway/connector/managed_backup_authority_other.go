// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package connector

func ensureManagedBackupAuthorityDirs(connectorDir string) error {
	return ensureManagedBackupDirRestricted(connectorDir)
}

func writeManagedBackupAuthority(path string, data []byte) error {
	return atomicWriteFile(path, data, 0o600)
}
