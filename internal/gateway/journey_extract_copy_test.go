// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestR107JourneyCorpusExtractMoveAndCopyThenArchive: the vsweep8 journey forms
// (rel-1-0-6:GAP-0292). A project folder holding a link to a project file
// (latest -> calc.py) is extracted and the extracted folder renamed, or
// copied with cp -a and then archived again, in one command. Neither form
// writes through a link into a protected file, so each gets the verdict of
// its halves, per user and managed. A rename onto, or a write through, a
// name the extraction may make a link still blocks.
func TestR107JourneyCorpusExtractMoveAndCopyThenArchive(t *testing.T) {
	setup := func(t *testing.T, f b36ManagedHookFixture) {
		dir := filepath.Join(f.project, "journey1")
		if err := os.MkdirAll(filepath.Join(f.project, "x"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "calc.py"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("calc.py", filepath.Join(dir, "latest")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.project, "journey1.tgz"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r106Reader2CheckWith(t, []r106Reader2Row{
		{"extract alone", "project", `tar -C {P}/x -xzf {P}/journey1.tgz`, "allow"},
		{"rename alone", "project", `mv {P}/x/journey1 {P}/x/journey1-x`, "allow"},
		{"extract then rename the extracted folder", "project", `tar -C {P}/x -xzf {P}/journey1.tgz && mv {P}/x/journey1 {P}/x/journey1-x`, "allow"},
		{"extract under /tmp then rename", "project", `tar -C /tmp -xzf {P}/journey1.tgz && mv /tmp/journey1 /tmp/journey1-r107x`, "allow"},
		{"cp -a alone", "home", `cd project && cp -a journey1 journey1-bak5`, "allow"},
		{"cp -a then archive the folder", "home", `cd project && cp -a journey1 journey1-bak5 && tar -czf journey1b.tgz journey1`, "allow"},
		{"cp -a then archive, no cd", "project", `cp -a journey1 journey1-bak5 && tar -czf journey1b.tgz journey1`, "allow"},
		{"extract then rename onto the keys file", "project", `tar -C {P}/x -xzf {P}/journey1.tgz && mv {P}/x/journey1 ~/.ssh/authorized_keys`, "block"},
		{"extract then rename to authorized_keys in a scoped folder", "project", `tar -C {P}/x -xzf keys.tar && mv a.txt {P}/x/d/authorized_keys`, "block"},
		{"extract then rename into a folder under the scope root", "project", `tar -C {P}/x -xzf {P}/journey1.tgz && mv {P}/x/journey1 {P}/x/sub/journey1-x`, "block"},
		{"extract then move into the scope root", "project", `tar -C {P}/x -xzf keys.tar && mv authorized_keys {P}/x`, "block"},
		{"cd, cp -a of the keys link, write the copy", "home", `cd project && cp -a keylink kbak && echo k >> kbak`, "block"},
		{"write into the extraction scope", "project", `tar -C unpack -xf keys.tar; echo k >> unpack/n1.txt`, "block"},
		{"cp -a of the keys link then write", "project", `cp -a keylink notes.txt && echo k >> notes.txt`, "block"},
	}, setup)
}
