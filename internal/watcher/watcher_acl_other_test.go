// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package watcher

import "testing"

// The Windows access-list and open-handle fixtures have no POSIX use: the POSIX
// branches of the tests use file modes. The stubs keep the tests one source.
func denyAccessForTest(t *testing.T, _, _ string) func() {
	t.Helper()
	t.Fatal("denyAccessForTest is Windows only")
	return func() {}
}

func holdOpenForTest(t *testing.T, _ string) func() {
	t.Helper()
	t.Fatal("holdOpenForTest is Windows only")
	return func() {}
}
