// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !linux && !darwin

package ideplugins

import "os"

// openedPath names no opened file on this system: the scan checks the folders
// above a file again after it opens it instead.
func openedPath(*os.File) (string, bool) { return "", false }
