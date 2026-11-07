// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import "os"

// OwnerPrivateGroup reports whether the group of path is the private group of
// its owner, with no other member (GAP-0657). It is the proof the guardian
// OpenCode service port setter uses to tell whether another account can write
// a folder. It is stricter than the plugin destination check: it also asks the
// name service for members a directory service adds, as the CLI preflight does
// (GAP-0053 REVIEW-3 MF1). False off Linux, and for anything unreadable or
// ambiguous.
func OwnerPrivateGroup(path string, info os.FileInfo) bool {
	return ownerPrivateGroupStrict(path, info)
}
