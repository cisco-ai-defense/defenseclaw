//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

// ownerFootprintRepairedAsRoot: on macOS the guardian hands the per-user
// tree back to the user as root, outside the euid drop and through
// descriptors (RepairUserTarget, RepairUserDataTreeAfterInstall), so the
// path-based chown inside the drop is not used.
const ownerFootprintRepairedAsRoot = true

// platformRepairAfterOwnerInstall runs as root once Install's work as the
// user has returned. A failure here never fails the install; the next
// guardian tick repairs again.
func platformRepairAfterOwnerInstall(home, dataDir string, uid, gid int) {
	_ = RepairUserDataTreeAfterInstall(home, dataDir, uid, gid)
}
