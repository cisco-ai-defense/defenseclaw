//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseMountInfoAtFindsTheVisibleMount(t *testing.T) {
	table := strings.Join([]string{
		"22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw",
		"40 22 0:35 / /home/alice rw,nosuid shared:20 - nfs4 srv:/home/alice rw,vers=4.2",
		"41 40 0:36 / /home/alice rw,nosuid,nodev - fuse.sshfs remote: rw,user_id=1000,group_id=1000",
		`42 22 0:37 / /home/with\040space rw - ecryptfs /home/.ecryptfs/x/.Private rw,ecryptfs_sig=abc`,
		"43 22 0:38 / /home/bob rw - fuse /dev/fuse rw,allow_other",
	}, "\n")
	parse := func(path string) (unixMount, bool) {
		mount, ok, err := parseMountInfoAt(bufio.NewScanner(strings.NewReader(table)), path)
		if err != nil {
			t.Fatal(err)
		}
		return mount, ok
	}
	if mount, ok := parse("/home/alice"); !ok || mount.FSType != "fuse.sshfs" || mount.Owner != 1000 || !mount.userMounted() {
		t.Fatalf("the top mount at /home/alice is the user's FUSE mount: %+v %v", mount, ok)
	}
	if mount, ok := parse("/home/with space"); !ok || mount.FSType != "ecryptfs" || mount.userMounted() {
		t.Fatalf("escaped mount points must decode: %+v %v", mount, ok)
	}
	if mount, ok := parse("/home/bob"); !ok || !mount.userMounted() {
		t.Fatalf("a FUSE mount that does not name its owner is treated as user-mounted: %+v %v", mount, ok)
	}
	if _, ok := parse("/home/carol"); ok {
		t.Fatal("no mount at /home/carol")
	}
}

func TestPlatformMountAtReadsTheLinuxMountTable(t *testing.T) {
	mount, ok, err := platformMountAt("/")
	if err != nil || !ok || mount.FSType == "" {
		t.Fatalf("the root filesystem must be in the mount table: %+v %v %v", mount, ok, err)
	}
	if _, ok, err := platformMountAt("/definitely/not/a/mount/point"); ok || err != nil {
		t.Fatalf("a plain path is not a mount point: %v %v", ok, err)
	}
}
