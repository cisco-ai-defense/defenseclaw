//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The macOS gateway is root and owns its audit store, so it repairs the
// store before each attempt and keeps retrying at the maximum delay after
// the budget instead of exiting into a launchd restart loop.
const gatewayAuditOpenWaitReason = "audit store unavailable at startup; repairing it and retrying: "

var gatewayAuditOpenUnbounded = true

// repairGatewayAuditStorePlatform re-stamps the audit folder, audit.db and
// its SQLite side files on no-follow descriptors. Only a store inside the
// pinned runtime folder is touched, and only by a root managed gateway. A
// symlinked or hard-linked database is moved aside so a fresh store opens.
func repairGatewayAuditStorePlatform(deploymentMode, path string) {
	if !managed.IsManagedEnterprise(deploymentMode) {
		return
	}
	layout, ok := managed.PinnedManagedServiceLayout()
	if !ok || !managed.SelfRepairEnabled() || !enterpriseHookInsideRuntime(layout, path) {
		return
	}
	objects := []managed.OwnedObject{
		{Path: filepath.Dir(path), Kind: managed.ObjectRuntimeDirectory, MoveAsideStructural: true, Recreate: true},
		{Path: path, Kind: managed.ObjectRuntimeFile, Mode: 0o600, MoveAsideStructural: true},
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		objects = append(objects, managed.OwnedObject{
			Path: path + suffix, Kind: managed.ObjectRuntimeFile, Mode: 0o600, MoveAsideStructural: true,
		})
	}
	managed.RepairOwnedObjects(objects)
}
