//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package skillrootsafe

// acceptLinkedRoot refuses every linked root: ownership of Windows reparse
// points requires a handle and ACL proof that is not implemented.
func acceptLinkedRoot(path, _ string) (string, []string, error) {
	return "", nil, unsafeRoot(path)
}

// No route is ever accepted through a group-writable folder here.
func groupWritableWarnings([]string) []string { return nil }
