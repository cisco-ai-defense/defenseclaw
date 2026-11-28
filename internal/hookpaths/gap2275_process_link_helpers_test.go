// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import "testing"

func TestGAP2275ThroughProcessLink(t *testing.T) {
	rows := []struct {
		path string
		want bool
	}{
		{"/proc/self/cwd/../x", true},
		{"/proc/4242/root/tmp/x", true},
		{"/proc/self/task/42/cwd/x", true},
		{"/dev/fd/3/x", true},
		{"/dev/stdout", true},
		{"//proc/./self/cwd", true},
		{"/home/u/proc/self/cwd/x", false},
		{"/proc/self/status", false},
		{"/tmp/dst", false},
		{"dst/", false},
	}
	for _, row := range rows {
		if got := throughProcessLink(row.path); got != row.want {
			t.Errorf("throughProcessLink(%q) = %t, want %t", row.path, got, row.want)
		}
	}
	if got := processLinkWrites([]string{"/srv/out/a"}, "/proc/self/cwd", nil); len(got) != 1 {
		t.Errorf("a call placed below a process link keeps its operands, got %q", got)
	}
}

func TestGAP2274CopyDestinationPath(t *testing.T) {
	cwd := t.TempDir()
	if got := copyDestinationPath("/proc/self/cwd/../x", cwd, nil); got != "/proc/self/cwd/../x" {
		t.Errorf("process-link destination = %q, want it raw", got)
	}
	if got := copyDestinationPath("out/../x", cwd, nil); got != cwd+"/x" {
		t.Errorf("relative destination = %q, want %s/x", got, cwd)
	}
	if got := copyDestinationPath("/home/u/p/../.claude/settings.json", cwd, nil); got != "/home/u/.claude/settings.json" {
		t.Errorf("absolute dot-dot destination = %q, want it cleaned", got)
	}
}
