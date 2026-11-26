// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookguard

// hookExecutableAlias: off Windows a path has no 8.3 alias.
func hookExecutableAlias(string) bool { return false }
