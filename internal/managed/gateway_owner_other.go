//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

// UseCurrentUserAsWindowsDefaultOwner changes nothing off Windows: a file
// there is owned by the process user.
func UseCurrentUserAsWindowsDefaultOwner([]string) bool { return false }
