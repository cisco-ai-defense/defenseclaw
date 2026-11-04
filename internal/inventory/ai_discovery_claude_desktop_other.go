// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import "os"

// claudeDesktopReparsePoint is Windows-only; elsewhere a link shows in Lstat.
func claudeDesktopReparsePoint(string) bool { return false }

// claudeDesktopOpenedIsChecked is Windows-only; elsewhere the Lstat and
// fstat identities of the opened folder are compared (os.SameFile).
func claudeDesktopOpenedIsChecked(string, *os.File) bool { return true }
