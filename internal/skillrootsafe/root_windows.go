//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package skillrootsafe

// acceptLinkedRoot refuses every linked root: ownership of Windows reparse
// points requires a handle and ACL proof that is not implemented.
func acceptLinkedRoot(path, _ string) (string, error) {
	return "", unsafeRoot(path)
}
