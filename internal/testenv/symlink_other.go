// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package testenv

// SymlinkPrivilegeMissing is false where creating a symbolic link needs no
// privilege.
func SymlinkPrivilegeMissing(error) bool { return false }
