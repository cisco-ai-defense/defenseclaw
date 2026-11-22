// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package testenv

import "testing"

// RealFSTestsEnv turns on the tests that mount a real, size-limited
// filesystem; they run on Linux only.
const RealFSTestsEnv = "DEFENSECLAW_REAL_FS_TESTS"

// RealSmallFilesystem skips the test: mounting a size-limited filesystem is
// implemented on Linux only.
func RealSmallFilesystem(t *testing.T, _ int) string {
	t.Helper()
	t.Skip("real full-filesystem tests mount a tmpfs and run on Linux only")
	return ""
}

// FillFilesystem is not reached off Linux (RealSmallFilesystem skips).
func FillFilesystem(t *testing.T, _ string) func() {
	t.Helper()
	t.Skip("real full-filesystem tests run on Linux only")
	return func() {}
}
