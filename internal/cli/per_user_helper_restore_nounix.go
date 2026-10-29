// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "os"

// install.ps1 keeps no installer copy of a helper: nothing to restore.
func perUserHelperRestoreSupported() bool { return false }

func perUserPrivateDir(string) bool { return false }

func perUserOwnedPrivateFile(os.FileInfo) bool { return false }
