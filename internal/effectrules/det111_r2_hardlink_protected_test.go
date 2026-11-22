// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effectrules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// Current Protected semantics return Maybe/R-NAME for a glob-bracket alias
// inside .ssh. The parallel project aliases exercise the same table roles and
// are reserved for the inode identity assertion when S4-R3B publishes it.
func TestDET111R2HardLinkOperandsReachProtectedClassifier(t *testing.T) {
	root := t.TempDir()
	home, project := filepath.Join(root, "home"), filepath.Join(root, "project")
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(ssh, "authorized_keys")
	if err := os.WriteFile(keys, []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	aliases := []string{filepath.Join(project, "key[9]"), filepath.Join(project, "keya"), filepath.Join(ssh, "authorized_keys[9]")}
	for _, alias := range aliases {
		if err := os.Link(keys, alias); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Stat(alias)
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
	if err := os.MkdirAll(filepath.Join(project, "ordinary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "ordinary", "x"), []byte("source\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	opt := effects.Options{Flavor: effects.FlavorPOSIX, Dialect: effects.DialectPOSIX, Home: home, CWD: project, Env: map[string]string{"HOME": home}}
	alias := filepath.Join(ssh, "authorized_keys[9]")
	cases := []struct{ gap, command string }{
		{"GAP-1288", `sed -i -e 'w ` + alias + `' ordinary/x`},
		{"GAP-1289", `dd of=` + alias},
		{"GAP-1317", `echo ` + alias + ` | xargs cp ordinary/x`},
		{"GAP-1318", `sed 's/a/b/w ` + alias + `' ordinary/x`},
	}
	resolve := func(p string) (string, bool) { return p, true }
	for _, tc := range cases {
		t.Run(tc.gap, func(t *testing.T) {
			result := effects.Extract(effects.Call{Surface: effects.SurfaceShell, Command: tc.command, Workdir: project}, opt)
			facts := Project(result, Env{Home: home, Flavor: effects.FlavorPOSIX, Resolve: resolve})
			for _, fact := range facts {
				for _, protection := range Protected(fact.Target) {
					if protection.Class == "authorized_keys" && protection.Certainty == "maybe" && protection.Reach == "R-NAME" {
						return
					}
				}
			}
			t.Fatalf("%s did not reach Maybe/R-NAME through Protected\n%+v", tc.gap, result)
		})
	}
}
