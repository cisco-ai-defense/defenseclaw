// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package ideplugins

import "os"

// openedOneName reports whether f has one name. Unix scans of another
// account's home run with protected hard links (Linux) or as that account
// (the per-user scan), so they do not check it.
func openedOneName(*os.File) bool { return true }
