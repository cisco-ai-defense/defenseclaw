// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import "testing"

// untrustedWriterAcceptedAsBoundary: Unix keeps an untrusted writer or owner
// on a managed policy or config file fatal.
const untrustedWriterAcceptedAsBoundary = false

// grantUntrustedWriterForTest is a no-op on Unix: the fixtures there are
// already untrusted through their owner or a world-writable parent.
func grantUntrustedWriterForTest(t *testing.T, _ string) {
	t.Helper()
}
