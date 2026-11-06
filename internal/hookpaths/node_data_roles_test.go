// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0624NodeInlineDataRoles(t *testing.T) {
	const cwd, home = "/home/alice/project", "/home/alice"
	for _, row := range []struct {
		name, code string
		ordinary   bool
	}{
		{"literal data", `require("fs").writeFileSync("/tmp/report.txt", "~/.ssh/authorized_keys")`, true},
		{"JSON data", `require("fs").writeFileSync(process.env.HOME + "/report.json", JSON.stringify({path:"~/.ssh/authorized_keys"}))`, true},
		{"nested data", `require("fs").appendFileSync("/tmp/log", JSON.stringify({paths:["~/.ssh/authorized_keys", "notes.txt"]}))`, true},
		{"protected destination", `require("fs").writeFileSync(process.env.HOME + "/.ssh/authorized_keys", "marker")`, false},
		{"computed data", `require("fs").writeFileSync("/tmp/report.txt", JSON.stringify({path:process.env.HOME}))`, false},
		{"additional call", `require("fs").writeFileSync("/tmp/report.txt", "~/.ssh/authorized_keys"); require("fs").writeFileSync("/tmp/other", "x")`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := nodeInertWriteData(row.code, cwd, home); got != row.ordinary {
				t.Fatalf("inert data = %t, want %t", got, row.ordinary)
			}
		})
	}
}

func TestGAP0624NodeInlineDataNeedsKnownHome(t *testing.T) {
	const code = `require("fs").writeFileSync("/tmp/report.txt", "~/.ssh/authorized_keys")`
	if nodeInertWriteData(code, "/home/alice/project", "") {
		t.Fatal("missing home received an ordinary data proof")
	}
}

func TestGAP0624NodeInlineDataNeedsResolvedDestination(t *testing.T) {
	home := t.TempDir()
	if err := os.Symlink("loop", filepath.Join(home, "loop")); err != nil {
		t.Fatal(err)
	}
	const code = `require("fs").writeFileSync("loop", "~/.ssh/authorized_keys")`
	if nodeInertWriteData(code, home, home) {
		t.Fatal("unresolved destination received an ordinary data proof")
	}
}
