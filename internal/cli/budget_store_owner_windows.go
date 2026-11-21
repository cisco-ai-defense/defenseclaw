// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "os"

// ownedByCurrentUser is not used on Windows (the DACL check decides).
func ownedByCurrentUser(os.FileInfo) bool { return true }
