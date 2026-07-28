// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

// Non-Windows builds exercise Windows command serialization without a Windows
// API. Production Windows builds use GetSystemDirectoryW instead.
func trustedWindowsSystemDirectory() string {
	return `C:\Windows\System32`
}
