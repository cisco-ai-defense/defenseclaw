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

// OwnerPrivateGroupLocalSources is OwnerPrivateGroup for a check that runs on
// every watcher event (GAP-0905). It starts no process and remembers nothing:
// the account files, the ACL and the nsswitch sources are read on each call.
// True only when the group is the private group of its owner and the host takes
// its accounts and groups from local files alone, because the name service
// cannot list every account that has the group as its primary group. A host
// with a directory service refuses group write on the route. False off Linux,
// and for anything unreadable or ambiguous.
func OwnerPrivateGroupLocalSources(path string, info os.FileInfo) bool {
	return ownerPrivateGroupLocalSources(path, info)
}

// PAMGroupLoaded reports whether a PAM stack file loads pam_group, which adds
// an account to a group at login by rules the private-group proof does not
// read. A caller that trusts a group-writable folder because its group is the
// private group of the owner watches it when this is true (GAP-0905). True
// for anything unreadable, and off Linux.
func PAMGroupLoaded() bool {
	return pamGroupLoaded()
}
