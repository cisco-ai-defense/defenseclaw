// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// directoryStackPlaces reads a stack word as bash expands it only where
// every way to the call gives one directory: a cd or pushd that may have
// failed (;, ||), a stack editor, a function, an OLDPWD or DIRSTACK name
// or a cd outside the list keeps it unknown (GAP-2586).
func TestDirectoryStackPlacesExpandLikeBash(t *testing.T) {
	// A Git Bash call on Windows names drive paths (GAP-1717): the rows
	// root their directories on C: there.
	root := func(p string) string { return p }
	if runtime.GOOS == "windows" {
		root = func(p string) string {
			for _, dir := range []string{"/w", "/a", "/b", "/missing"} {
				p = strings.ReplaceAll(p, " "+dir, " C:"+dir)
			}
			if strings.HasPrefix(p, "/") {
				p = "C:" + p
			}
			return p
		}
	}
	cwd, home := root("/w/project"), root("/w")
	for _, tc := range []struct {
		command, word, want string
	}{
		{"pushd src && cp -r ~1/src s2", "~1/src", "/w/project/src"},
		{"pushd src && cp -r ~-/ordinary x", "~-/ordinary", "/w/project/ordinary"},
		{"cd src && rsync -a ~-/ordinary/ out/", "~-/ordinary/", "/w/project/ordinary/"},
		{"pushd /a && pushd /b && cp -r ~2 x", "~2", "/w/project"},
		{"pushd /a && pushd /b && cp -r ~-0 x", "~-0", "/w/project"},
		{"pushd /a && pushd /b && cp -r ~+ x", "~+", "/b"},
		{"pushd src && cp -r ~+ x", "~+", ""},
		{"pushd src && popd && cp -r ~- x", "~-", ""},
		{"cp -r ~- x", "~-", ""},
		{"pushd src && cp -r ~2 x", "~2", ""},
		{"cd /a; cp -r ~- x", "~-", ""},
		{"cd /a && cd /b || cp -r ~- x", "~-", ""},
		{"cd /a && cd /missing || cp -r ~- x", "~-", ""},
		{"command cd /a && cp -r ~- x", "~-", ""},
		{"f() { cd /a; }; cd /b && cp -r ~- x", "~-", ""},
		{"OLDPWD=/a; cd /b && cp -r ~1 x", "~1", ""},
		{"pushd /a && dirs -c && cp -r ~1 x", "~1", ""},
		{"for d in a; do cd $d; done; pushd /b && cp -r ~1 x", "~1", ""},
		{"(cd /a) && pushd /b && cp -r ~1 x", "~1", "/w/project"},
	} {
		tc.command, tc.want = root(tc.command), root(tc.want)
		file, ok := parseShell(tc.command)
		if !ok {
			t.Fatalf("%q does not parse", tc.command)
		}
		places := directoryStackPlaces(file, tc.command, cwd, home)
		var call []stackPlace
		for c, p := range places {
			if word, _ := StaticWord(c.Args[0], home); word == "cp" || word == "rsync" {
				call = p
			}
		}
		got, ok := expandDirectoryStackWord(tc.word, call)
		if !ok {
			got = ""
		}
		got = filepath.ToSlash(got)
		if got != tc.want {
			t.Errorf("%q %s: got %q, want %q", tc.command, tc.word, got, tc.want)
		}
	}
}
