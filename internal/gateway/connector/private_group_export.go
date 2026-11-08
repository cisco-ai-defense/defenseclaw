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
// (GAP-0053 REVIEW-3 MF1). The caller must already have judged every named
// entry of the access ACL of path (managed.ValidatePathACLForAccount) and read
// the group bits as the group object (managed.ModeWithoutACLMask); an ACL on
// the path does not rule the private group out here. False off Linux, and for
// anything unreadable or ambiguous.
func OwnerPrivateGroup(path string, info os.FileInfo) bool {
	return ownerPrivateGroupStrictAfterACL(path, info)
}

// OwnerPrivateGroupLocal is the local-files proof of OwnerPrivateGroup: the
// group and account files, os/user, and no access ACL on path (an ACL fails
// it). It starts no process, so a check that runs on every watcher event can
// ask it for each folder of a path (GAP-0905); it cannot see a member only a
// directory service adds, so the managed setter keeps OwnerPrivateGroup.
func OwnerPrivateGroupLocal(path string, info os.FileInfo) bool {
	return ownerPrivateGroup(path, info)
}
