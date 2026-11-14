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
		// Review 3 fixtures: plain source files with no dot or extension, an
		// extraction folder y that already holds d -> the .ssh decoy
		// directory, a project link sshd -> the .ssh decoy directory and a
		// keys link with an innocent name in the ordinary folder.
		for _, name := range []string{"notes", "authorized", "Authorized_Keys"} {
			if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.MkdirAll(filepath.Join(f.project, "y"), 0o700); err != nil {
			t.Fatal(err)
		}
		for link, text := range map[string]string{
			filepath.Join(f.project, "y", "d"):         "../../.ssh",
			filepath.Join(f.project, "sshd"):           "../.ssh",
			filepath.Join(f.project, "ordinary", "kl"): "../../.ssh/authorized_keys",
		} {
			if err := os.Symlink(text, link); err != nil {
				t.Fatal(err)
			}
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
		{"extract then rename into a folder under the scope root", "project", `tar -C {P}/x -xzf {P}/journey1.tgz && mv {P}/x/journey1 {P}/x/sub/journey1-x`, "alert/block"},
		{"extract then move into the scope root", "project", `tar -C {P}/x -xzf keys.tar && mv authorized_keys {P}/x`, "block"},
		{"cd, cp -a of the keys link, write the copy", "home", `cd project && cp -a keylink kbak && echo k >> kbak`, "block"},
		{"write into the extraction scope", "project", `tar -C unpack -xf keys.tar; echo k >> unpack/n1.txt`, "alert/block"},
		{"cp -a of the keys link then write", "project", `cp -a keylink notes.txt && echo k >> notes.txt`, "block"},

		// Review 3: one must-deny row per condition of the scoped-move
		// allow, each beside a must-allow neighbour.
		{"r3 extract then rename a plain file into a scope entry", "project", `tar -C {P}/x -xzf keys.tar && mv notes {P}/x/notes-x`, "allow"},
		{"r3 extract then move a dot name into a scope entry", "project", `tar -C {P}/x -xzf keys.tar && mv .ssh {P}/x/d`, "block"},
		{"r3 extract then move a trailing-dot keys name into a scope entry", "project", `tar -C {P}/x -xzf keys.tar && mv authorized_keys. {P}/x/d`, "block"},
		{"r3 extract then move the keys name into a scope entry", "project", `tar -C {P}/x -xzf keys.tar && mv authorized_keys {P}/x/d`, "block"},
		{"r3 extract then move authorized_keys2 into a scope entry", "project", `tar -C {P}/x -xzf keys.tar && mv authorized_keys2 {P}/x/d`, "block"},
		{"r3 extract then move an ssh rc file into a scope entry", "project", `tar -C {P}/x -xzf keys.tar && mv rc {P}/x/d`, "alert/block"},
		{"r3 extract then move a case variant of the keys name into a scope entry", "project", `tar -C {P}/x -xzf keys.tar && mv Authorized_Keys {P}/x/d`, "block"},
		{"r3 extract then move two sources into a scope entry", "project", `tar -C {P}/x -xzf keys.tar && mv notes authorized_keys {P}/x/d`, "block"},
		{"r3 extract then move with -t into a scope entry", "project", `tar -C {P}/x -xzf keys.tar && mv -t {P}/x/d authorized_keys`, "block"},
		{"r3 extract then move with a backup suffix into a scope entry", "project", `tar -C {P}/x -xzf keys.tar && mv --suffix=_keys authorized {P}/x/d`, "alert/block"},
		{"r3 extract then move with -b -S into a scope entry", "project", `tar -C {P}/x -xzf keys.tar && mv -b -S _keys authorized {P}/x/d`, "alert/block"},
		{"r3 extract then move a file from below the scope root", "project", `tar -C {P}/x -xzf keys.tar && mv {P}/x/d/notes {P}/x/notes-x`, "alert/block"},
		{"r3 extract then move a plain file onto the scope root", "project", `tar -C {P}/x -xzf keys.tar && mv notes {P}/x`, "alert/block"},
		{"r3 extract then move through a scope entry and dot-dot", "project", `tar -C {P}/x -xzf keys.tar && mv notes {P}/x/d/../authorized_keys`, "block"},

		// Review 3: another write at a marked move destination.
		{"r3 extract then rename a plain file onto a scope entry", "project", `tar -C {P}/x -xzf keys.tar && mv notes {P}/x/k`, "allow"},
		{"r3 extract, failed move onto a scope entry, write it", "project", `tar -C {P}/x -xzf keys.tar; mv nosuch {P}/x/k; echo k >> {P}/x/k`, "alert/block"},
		{"r3 extract, no-clobber move onto a scope entry, write it", "project", `tar -C {P}/x -xzf keys.tar && mv -n notes {P}/x/k && echo k >> {P}/x/k`, "alert/block"},
		{"r3 extract, write a scope entry, then move onto it", "project", `tar -C {P}/x -xzf keys.tar; echo k >> {P}/x/k; mv notes {P}/x/k`, "alert/block"},
		{"r3 extract, copy onto a scope entry, then move onto it", "project", `tar -C {P}/x -xzf keys.tar; cp a.txt {P}/x/k; mv notes {P}/x/k`, "alert/block"},

		// Review 3: an extraction folder that already holds d -> the .ssh
		// decoy directory.
		{"r3 extract into the folder with the .ssh link, rename a plain file", "project", `tar -C {P}/y -xzf keys.tar && mv notes {P}/y/notes-x`, "allow"},
		{"r3 extract into the folder with the .ssh link, move the keys name into it", "project", `tar -C {P}/y -xzf keys.tar && mv authorized_keys {P}/y/d`, "block"},
		{"r3 extract into the folder with the .ssh link, move an ssh rc file into it", "project", `tar -C {P}/y -xzf keys.tar && mv rc {P}/y/d`, "block"},
		{"r3 extract into the folder with the .ssh link, move onto the keys file", "project", `tar -C {P}/y -xzf keys.tar && mv notes {P}/y/d/authorized_keys`, "block"},
		{"r3 extract into the folder with the .ssh link, move a file into it, write the keys file", "project", `tar -C {P}/y -xzf keys.tar && mv notes {P}/y/d && echo k >> {P}/y/d/authorized_keys`, "block"},

		// Review 3: a cd into a link before the copy.
		{"r3 cd into a folder, cp -a of the linked folder", "project", `cd x && cp -a {P}/journey1 jb`, "allow"},
		{"r3 cd into the .ssh link, cp -a onto the keys name", "project", `cd sshd && cp -a {P}/a.txt authorized_keys`, "block"},
		{"r3 cd into the .ssh link, cp -a of a link onto the keys name", "project", `cd sshd && cp -a {P}/journey1/latest authorized_keys`, "block"},
		{"r3 cd into the .ssh link, cp -a of the linked folder, then onto the keys name", "project", `cd sshd && cp -a {P}/journey1 jb && cp -a {P}/a.txt authorized_keys`, "block"},
		{"r3 cd into a folder holding a keys link, cp -a of the linked folder, then onto the link", "project", `cd ordinary && cp -a {P}/journey1 jb && cp -a {P}/a.txt kl`, "block"},
		{"r3 cd into a folder, cp -a named as the start-dir keys link, write that link", "project", `cd ordinary && cp -a {P}/journey1 keylink && echo k >> {P}/keylink`, "block"},
		{"r3 cd from home, two copies to one name, the first of the keys link", "home", `cd project && cp -a keylink jb && cp -a a.txt jb`, "block"},
	}, setup)
}
