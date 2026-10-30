// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package config

import "testing"

// grantUntrustedWriterForTest is a no-op on Unix: the fixtures there are
// already untrusted through their owner or a world-writable parent.
func grantUntrustedWriterForTest(t *testing.T, _ string) {
	t.Helper()
}
