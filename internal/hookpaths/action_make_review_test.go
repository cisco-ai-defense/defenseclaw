// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGAP0996MakeCopySourceIsData(t *testing.T) {
	home, cwd, links := gap0996Fixture(t)
	for _, tc := range []struct {
		name, recipe string
		block        bool
	}{
		{"copy", `cp ~/.ssh/authorized_keys report.txt`, false},
		{"gnu copy", `gcp ~/.ssh/authorized_keys report.txt`, false},
		{"copy with target directory", `cp -t . ~/.ssh/authorized_keys`, false},
		{"copy through env", `env cp ~/.ssh/authorized_keys report.txt`, false},
		{"copy through env split", `env -S 'cp ~/.ssh/authorized_keys report.txt'`, false},
		{"copy through nice", `nice -n 5 cp ~/.ssh/authorized_keys report.txt`, false},
		{"copy through timeout", `timeout 5 cp ~/.ssh/authorized_keys report.txt`, false},
		{"copy through command", `command cp ~/.ssh/authorized_keys report.txt`, false},
		{"copy through busybox", `busybox cp ~/.ssh/authorized_keys report.txt`, false},
		{"copy through sudo", `sudo cp ~/.ssh/authorized_keys report.txt`, false},
		{"copy through shell", `sh -c 'cp ~/.ssh/authorized_keys report.txt'`, false},
		{"install source", `install -m 600 ~/.ssh/authorized_keys report.txt`, false},
		{"install target directory", `install -t . ~/.ssh/authorized_keys`, false},
		{"rsync source", `rsync -a ~/.ssh/authorized_keys report.txt`, false},
		{"rsync through env", `env rsync ~/.ssh/authorized_keys report.txt`, false},
		{"copy to protected file", `cp report.txt ~/.ssh/authorized_keys`, true},
		{"copy to protected directory", `cp -t ~/.ssh report.txt`, true},
		{"copy private key", `cp ~/.ssh/id_ed25519 report.txt`, true},
		{"copy parents unproved", `cp --parents ~/.ssh/authorized_keys .`, true},
		{"copy abbreviated parents unproved", `cp --par ~/.ssh/authorized_keys .`, true},
		{"copy backup unproved", `cp -b ~/.ssh/authorized_keys report.txt`, true},
		{"copy abbreviated backup unproved", `cp --back ~/.ssh/authorized_keys report.txt`, true},
		{"copy suffix unproved", `cp -S.~ ~/.ssh/authorized_keys report.txt`, true},
		{"qualified copy program unproved", `./cp ~/.ssh/authorized_keys report.txt`, true},
		{"move protected file", `mv report.txt ~/.ssh/authorized_keys`, true},
		{"install protected file", `install report.txt ~/.ssh/authorized_keys`, true},
		{"rsync protected file", `rsync report.txt ~/.ssh/authorized_keys`, true},
		{"dd protected output", `dd if=report.txt of=~/.ssh/authorized_keys`, true},
		{"remove protected file", `rm ~/.ssh/authorized_keys`, true},
		{"chmod protected file", `chmod 600 ~/.ssh/authorized_keys`, true},
		{"tar into protected directory", `tar -xf archive.tar -C ~/.ssh`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := "safe:\n\t" + tc.recipe + "\n"
			if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := ActionCommandDecision("make safe", cwd, home); (got != "") != tc.block {
				t.Fatalf("decision=%q, want block=%t", got, tc.block)
			}
		})
	}
	if links {
		for _, tc := range []struct {
			name, recipe string
			block        bool
		}{
			{"ordinary copy through source link", `cp disklink report.txt`, false},
			{"preserved source link unproved", `cp -a disklink report.txt`, true},
			{"rsync preserved source link unproved", `rsync -a disklink report.txt`, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte("safe:\n\t"+tc.recipe+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if got := ActionCommandDecision("make safe", cwd, home); (got != "") != tc.block {
					t.Fatalf("decision=%q, want block=%t", got, tc.block)
				}
			})
		}
	}
	t.Run("long static variable name", func(t *testing.T) {
		name := "SOURCE" + strings.Repeat("X", 300)
		content := name + " := ~/.ssh/authorized_keys\nsafe:\n\tcp $(" + name + ") report.txt\n"
		if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := ActionCommandDecision("make safe", cwd, home); got != "" {
			t.Fatalf("ordinary copy through a long static variable blocked: %q", got)
		}
	})
	for _, tc := range []struct {
		name, recipe, assignment string
		block                    bool
	}{
		{"punctuated source variable", `cp $(SOURCE-READ) report.txt`, `SOURCE-READ=~/.ssh/authorized_keys`, false},
		{"punctuated destination variable", `cp report.txt $(DEST-KEY)`, `DEST-KEY=~/.ssh/authorized_keys`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte("safe:\n\t"+tc.recipe+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := ActionCommandDecision("make '"+tc.assignment+"' safe", cwd, home); (got != "") != tc.block {
				t.Fatalf("decision=%q, want block=%t", got, tc.block)
			}
		})
	}
}

func TestGAP0996MakeDependencyGraphBounded(t *testing.T) {
	home, cwd, _ := gap0996Fixture(t)
	t.Run("ten thousand rule chain", func(t *testing.T) {
		var content strings.Builder
		for i := range 10000 {
			if i == 9999 {
				content.WriteString("node9999: ; @true\n")
			} else {
				fmt.Fprintf(&content, "node%d: node%d\n", i, i+1)
			}
		}
		if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte(content.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := ActionCommandDecision("make node0", cwd, home); got != "" {
			t.Fatalf("ordinary 10,000-rule chain blocked: %q", got)
		}
	})
	t.Run("self extending pattern", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte("%.a: %.a.a\n\t@true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := ActionCommandDecision("make x.a", cwd, home); got == "" {
			t.Fatal("self-extending pattern chain was not bounded")
		}
	})
	t.Run("pattern fanout stays bounded before expansion", func(t *testing.T) {
		content := "%.x: " + strings.Repeat("%", 10000) + "\n\t@true\n"
		if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		goal := strings.Repeat("x", 4000) + ".x"
		if got := ActionCommandDecision("make "+goal, cwd, home); got == "" {
			t.Fatal("expanded pattern prerequisite was not bounded")
		}
	})
	t.Run("aggregate source budget", func(t *testing.T) {
		var includes strings.Builder
		filler := []byte(strings.Repeat("# filler\n", 1<<18))
		for i := range 17 {
			name := fmt.Sprintf("part%d.mk", i)
			fmt.Fprintf(&includes, "include %s\n", name)
			if err := os.WriteFile(filepath.Join(cwd, name), filler, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		includes.WriteString("safe: ; @true\n")
		if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte(includes.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := ActionCommandDecision("make safe", cwd, home); got == "" {
			t.Fatal("makefiles beyond the aggregate work budget were not bounded")
		}
	})
	t.Run("repeated variable append budget", func(t *testing.T) {
		content := strings.Repeat("INERT += "+strings.Repeat("x", 256)+"\n", 1000) + "safe: ; @true\n"
		if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := ActionCommandDecision("make safe", cwd, home); got == "" {
			t.Fatal("repeated variable growth was not bounded")
		}
	})
	t.Run("many references share one closing delimiter", func(t *testing.T) {
		content := "INERT := " + strings.Repeat("$(", 100000) + ")\nsafe: ; @true\n"
		if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := ActionCommandDecision("make safe", cwd, home); got != "" {
			t.Fatalf("ordinary inert assignment blocked: %q", got)
		}
	})
}
