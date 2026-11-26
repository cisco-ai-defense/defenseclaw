// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

func TestGAP2237ProcessLinkWriteBelowOpenerRelativeLink(t *testing.T) {
	rows := []struct {
		path string
		want bool
	}{
		{"/dev/fd/3/.ssh/authorized_keys", true},
		{"/dev/stdin/.ssh/authorized_keys", true},
		{"/dev/stdout/.ssh/authorized_keys", true},
		{"/dev/stderr/.ssh/authorized_keys", true},
		{"/proc/4242/../4242/root/sandbox/.ssh/authorized_keys", true},
		{"//proc/4242/root/../sandbox/.ssh/authorized_keys", true},
		{"/proc/4242/./root/../sandbox/.ssh/authorized_keys", true},
		{"/proc/self/root/tmp/authorized_keys", false},
		{"/proc/thread-self/root/tmp/authorized_keys", false},
		{"/proc/self/fd/3/.ssh/authorized_keys", true},
		{"/proc/thread-self/fd/3/.ssh/authorized_keys", true},
		{"/proc/self/task/42/root/home/u/.ssh/authorized_keys", true},
		{"/proc/self/task/42/cwd/.ssh/authorized_keys", true},
		{"/proc/self/task/42/fd/3/.ssh/authorized_keys", true},
		{"/proc/42/task/42/fd/3/.ssh/authorized_keys", true},
		{"/dev/fd/1", false},
		{"/proc/self/fd/2", false},
		{"/proc/thread-self/fd/3", false},
		{"/proc/self/task/42/root", false},
		{"/proc/self/task/42/fd/3", false},
		{"/proc/self/task/42/fd/any/.ssh/authorized_keys", false},
		{"/tmp/authorized_keys", false},
	}
	for _, row := range rows {
		if got := ProcessLinkWriteUnproved(row.path, true); got != row.want {
			t.Errorf("ProcessLinkWriteUnproved(%q, true) = %v, want %v", row.path, got, row.want)
		}
	}
}
