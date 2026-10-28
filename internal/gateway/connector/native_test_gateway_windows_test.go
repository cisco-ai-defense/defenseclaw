// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import "testing"

// Shell-hook tests skip on Windows, where the native hook executor is used.
// Keep their shared fixture callable so cross-compiling the package tests
// still checks those tests' Go source.
func installNativeGatewayForHookTest(t *testing.T, _ string) {
	t.Helper()
	t.Skip("POSIX shell-hook runtime is not used on Windows")
}
