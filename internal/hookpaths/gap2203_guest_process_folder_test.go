// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// TestGAP2203GuestOtherProcessFolderFollowsLinux: on a gateway host that is
// not Linux, the guest walk leaves unknown exactly the /proc folders an
// unprivileged Linux gateway cannot read (RV-2203 P2-1): another process's
// root, cwd and exe and the entries below its fd, fdinfo, map_files and ns
// folders, also under task/<tid>. The rest is placed as written.
func TestGAP2203GuestOtherProcessFolderFollowsLinux(t *testing.T) {
	for _, row := range []struct {
		folder string
		other  bool
	}{
		{"/proc/1/root", true},
		{"/proc/1/root/tmp", true},
		{"/proc/1/cwd", true},
		{"/proc/1/cwd/sub", true},
		{"/proc/1/exe", true},
		{"/proc/1/fd/0", true},
		{"/proc/42/fdinfo/3", true},
		{"/proc/1/map_files/x", true},
		{"/proc/1/ns/net", true},
		{"/proc/1/task/1/root", true},
		{"/proc/1/task/1/fd/2", true},
		{"/proc/1", false},
		{"/proc/1/fd", false},
		{"/proc/1/ns", false},
		{"/proc/1/task", false},
		{"/proc/1/task/1", false},
		{"/proc/1/environ", false},
		{"/proc", false},
		{"/proc/sys/kernel", false},
		{"/proc/self/cwd", false},
		{"/proc/self/root", false},
		{"/proc/self/fd/0", false},
		{"/proc/thread-self/cwd", false},
		{"/proc/thread-self/root", false},
		{"/PROC/1/root", false},
		{"/procx/1/root", false},
		{"/tmp", false},
	} {
		if got := guestOtherProcessFolder(row.folder); got != row.other {
			t.Errorf("guestOtherProcessFolder(%q) = %v, want %v", row.folder, got, row.other)
		}
	}
}
