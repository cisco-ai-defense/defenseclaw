// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// TestGAP2223GuestOwnRootPathIsTheGuestRoot: a Linux sandbox guest reads its
// /proc/self/root and /proc/thread-self/root as its own /, as a Linux
// gateway reads its own, so a gateway host with no /proc folds them the
// same way, again and again (rel-1-0-10:GAP-2223, RV-2203c P2-1). Another
// process's root, a task/<tid> root and other spellings stay as written.
func TestGAP2223GuestOwnRootPathIsTheGuestRoot(t *testing.T) {
	for _, row := range []struct{ path, want string }{
		{"/proc/self/root", "/"},
		{"/proc/thread-self/root", "/"},
		{"/proc/self/root/sandbox", "/sandbox"},
		{"/proc/thread-self/root/sandbox/app", "/sandbox/app"},
		{"/proc/self/root/proc/1/root", "/proc/1/root"},
		{"/proc/self/root/proc/self/root/tmp", "/tmp"},
		{"/proc/thread-self/root/proc/self/root", "/"},
		{"/proc/self/root/proc/thread-self/root/proc/1/cwd", "/proc/1/cwd"},
		{"/proc/self/rootx", "/proc/self/rootx"},
		{"/proc/self/cwd", "/proc/self/cwd"},
		{"/proc/self", "/proc/self"},
		{"/proc/self/task/1/root", "/proc/self/task/1/root"},
		{"/proc/1/root", "/proc/1/root"},
		{"/PROC/self/root", "/PROC/self/root"},
		{"/tmp/proc/self/root", "/tmp/proc/self/root"},
		{"/", "/"},
	} {
		if got := GuestOwnRootPath(row.path); got != row.want {
			t.Errorf("GuestOwnRootPath(%q) = %q, want %q", row.path, got, row.want)
		}
	}
	// The walk on a gateway host that is not Linux sees the folded folder:
	// another process's root reached through the guest's own root is
	// unknown, as an unprivileged Linux gateway leaves it.
	if !guestOtherProcessFolder(GuestOwnRootPath("/proc/self/root/proc/1/root")) {
		t.Error("/proc/self/root/proc/1/root is another process's root once folded")
	}
}
