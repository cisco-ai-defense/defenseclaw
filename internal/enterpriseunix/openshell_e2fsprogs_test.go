// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ensure accepts an e2fsprogs_dir only by the rule the gateway's exec shim
// starts the MicroVM driver with (GAP-0506): the install prefix or the folder
// that holds mke2fs and debugfs side by side, and it names that folder. The
// rc.1 check took the tools from any of sbin, bin or the folder itself
// while the shim always appended sbin, so ensure and verify passed and the
// managed gateway exited 78.
func TestCheckE2fsprogsFollowsTheGatewayRule(t *testing.T) {
	h := newOSHost(t, "darwin")
	write := func(rel ...string) string {
		dir := "/opt/cisco/defenseclaw-deps/" + t.Name() + "-" + strings.Join(rel, "-")
		for _, tool := range rel {
			p := h.env.P(filepath.Join(dir, tool))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	check := func(dir string) prereqRow {
		t.Helper()
		rows := h.env.checkE2fsprogs(context.Background(), openshellSettings{E2fsprogsDir: dir})
		if len(rows) != 1 {
			t.Fatalf("rows = %+v", rows)
		}
		return rows[0]
	}
	if row := check(""); row.OK || !strings.Contains(row.Detail, "~/.local/opt/e2fsprogs") || strings.Contains(row.Detail, "trusted Homebrew keg") {
		t.Errorf("unset administrator directory: %+v", row)
	}
	prefix := write("sbin/mke2fs", "sbin/debugfs")
	if row := check(prefix); !row.OK || row.Detail != prefix+"/sbin" {
		t.Errorf("install prefix: %+v, want ok naming %s/sbin", row, prefix)
	}
	// The directory the rc.1 wave configured: the sbin folder itself.
	if row := check(prefix + "/sbin"); !row.OK || row.Detail != prefix+"/sbin" {
		t.Errorf("tool folder: %+v, want ok naming it", row)
	}
	// Root can see a private or non-executable tool; the account's
	// gateway cannot use it, so ensure must reject it first.
	if err := os.Chmod(h.env.P(prefix+"/sbin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if row := check(prefix); row.OK || !strings.Contains(row.Detail, "cannot be traversed") {
		t.Errorf("root-only tool folder passed ensure: %+v", row)
	}
	if err := os.Chmod(h.env.P(prefix+"/sbin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.env.P(prefix+"/sbin/mke2fs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if row := check(prefix); row.OK || !strings.Contains(row.Detail, "cannot be executed") {
		t.Errorf("root-only tool file passed ensure: %+v", row)
	}
	if err := os.Chmod(h.env.P(prefix+"/sbin/mke2fs"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Tools the shim could not put on one PATH entry are refused, with the fix.
	split := write("sbin/mke2fs", "bin/debugfs")
	if row := check(split); row.OK || !strings.Contains(row.Detail, "no mke2fs and debugfs side by side") || !strings.Contains(row.Fix, "install prefix") {
		t.Errorf("split tools pass: %+v", row)
	}
	// A folder named like a tool is not one.
	dirTool := write("sbin/debugfs")
	if err := os.MkdirAll(h.env.P(filepath.Join(dirTool, "sbin", "mke2fs")), 0o755); err != nil {
		t.Fatal(err)
	}
	if row := check(dirTool); row.OK {
		t.Errorf("a folder named mke2fs passes: %+v", row)
	}
}
