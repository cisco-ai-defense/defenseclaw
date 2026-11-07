// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import "os"

// OwnerPrivateGroup reports whether the group of path is the private group of
// its owner, with no other member (GAP-0657). It is the proof the plugin
// destination check uses, shared with the guardian OpenCode service port
// setter so one rule answers whether another account can write a folder.
// False off Linux, and for anything unreadable or ambiguous.
func OwnerPrivateGroup(path string, info os.FileInfo) bool {
	return ownerPrivateGroup(path, info)
}
