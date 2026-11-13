// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

// RejectUntrustedSecretReaders requires that only LocalSystem and
// Administrators may read path (the fleet budget store's key file and TLS
// key on a Windows store host).
func RejectUntrustedSecretReaders(path string) error {
	return rejectUntrustedCredentialReaders(path, nil)
}
