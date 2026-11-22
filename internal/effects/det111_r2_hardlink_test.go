// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These gaps have no corpus rows. The fixture proves the alias is the same
// inode as authorized_keys, while the reader test pins the table-consumed role
// or explicit unknown that the protected-path layer must classify.
func TestDET111R2HardLinkFixtures(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(root, "project")
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(ssh, "authorized_keys")
	if err := os.WriteFile(keys, []byte("ssh-ed25519 fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"key[9]", "keya"} {
		p := filepath.Join(project, alias)
		if err := os.Link(keys, p); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		ki, err := os.Stat(keys)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(fi, ki) {
			t.Fatalf("%s is not a hard link of authorized_keys", alias)
		}
	}
	ordinary := filepath.Join(project, "ordinary")
	if err := os.MkdirAll(ordinary, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ordinary, "x"), []byte("source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opt := Options{Flavor: FlavorPOSIX, Dialect: DialectPOSIX, Home: home, CWD: project, Env: map[string]string{"HOME": home}}
	cases := []struct {
		gap, command string
		kind         Kind
		alias        string
		unknown      ReasonCode
	}{
		{"GAP-1288", `sed -i -e 'w key[9]' ordinary/x`, KindWrite, "key[9]", ""},
		{"GAP-1289", `dd of=./key[9]`, KindWrite, "key[9]", ""},
		{"GAP-1317", `echo keya | xargs cp ordinary/x`, KindWrite, "keya", ""},
		{"GAP-1318", `sed 's/a/b/w keya' ordinary/x`, KindWrite, "keya", ""},
	}
	for _, tc := range cases {
		t.Run(tc.gap, func(t *testing.T) {
			r := Extract(Call{Surface: SurfaceShell, Tool: "shell", Command: tc.command, Workdir: project}, opt)
			for _, e := range r.Effects {
				if e.Kind != tc.kind {
					continue
				}
				if tc.unknown != "" {
					for _, reason := range e.Reasons {
						if reason.Code == tc.unknown {
							return
						}
					}
					continue
				}
				for _, p := range []string{e.Target.Path, e.Target.Glob, e.Target.Spelling} {
					if strings.Contains(p, tc.alias) {
						return
					}
				}
			}
			t.Fatalf("%s did not expose its alias write or explicit unknown\\n%s", tc.gap, fmtRes(r))
		})
	}
}
