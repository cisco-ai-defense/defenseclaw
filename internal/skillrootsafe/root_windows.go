//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package skillrootsafe

func validateLinkedPath(path, _ string) error {
	// Ownership of Windows reparse points requires a handle and ACL proof.
	return unsafeRoot(path)
}
