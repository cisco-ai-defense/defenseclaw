// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package assetfacts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0535UnknownSupplementaryGroupKeepsDirectoryUnproven(t *testing.T) {
	root, err := os.MkdirTemp("/var/tmp", "gap0535-groups-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "candidate")
	if err := os.Mkdir(dir, 0o701); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Geteuid()+1001, os.Getegid()+1001
	if callerCanEnterDirectory(dir, uid, gid) {
		t.Error("group-denied directory was treated as certainly enterable")
	}
	if err := os.Chmod(dir, 0o711); err != nil {
		t.Fatal(err)
	}
	if !callerCanEnterDirectory(dir, uid, gid) {
		t.Error("directory searchable by both group and other remained uncertain")
	}
}
