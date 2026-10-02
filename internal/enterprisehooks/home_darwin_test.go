//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "testing"

func TestPlatformMountAtReadsTheDarwinMountTable(t *testing.T) {
	mount, ok, err := platformMountAt("/")
	if err != nil || !ok || mount.FSType == "" {
		t.Fatalf("the root volume must be in the mount table: %+v %v %v", mount, ok, err)
	}
	if mount.userMounted() {
		t.Fatalf("the root volume is not user-mounted: %+v", mount)
	}
	if _, ok, err := platformMountAt("/definitely/not/a/mount/point"); ok || err != nil {
		t.Fatalf("a plain path is not a mount point: %v %v", ok, err)
	}
}
