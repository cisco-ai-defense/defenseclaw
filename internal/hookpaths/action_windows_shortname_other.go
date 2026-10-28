// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

// Only the native filesystem can identify a Windows 8.3 alias.
func actionWindowsExpandShortPath(string) (string, bool) { return "", false }
