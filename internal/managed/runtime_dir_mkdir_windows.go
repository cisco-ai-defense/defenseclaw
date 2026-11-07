// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import "os"

// mkdirServiceRuntimeDir creates a missing service runtime directory. In the
// tree of a standalone managed deployment it is created in the canonical
// RuntimeDirectory protection, so the Guardian has no repair to log for it
// (GAP-0762); anywhere else it is an ordinary directory.
func mkdirServiceRuntimeDir(path string) error {
	account, ok := StandaloneManagedTreeAccount(path)
	if !ok {
		return os.Mkdir(path, 0o700)
	}
	return CreateCanonicalDirectory(path, ObjectRuntimeDirectory, CanonicalOptions{GatewayServiceAccount: account})
}
