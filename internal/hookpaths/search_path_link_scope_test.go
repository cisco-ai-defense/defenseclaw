// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// r104Loop3CDPathHome builds a home whose project has sub and sub/deeper, and
// a directory elsewhere that an unexported CDPATH may select. Its sub/out.txt
// and sub/deeper/out.txt link to authorized_keys. The hook cannot see that
// CDPATH, so it cannot tell which sub a relative cd enters.
func r104Loop3CDPathHome(t *testing.T) (home, cwd string) {
	t.Helper()
	home = t.TempDir()
	cwd = filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(cwd, "sub", "deeper"),
		filepath.Join(home, "elsewhere", "sub", "deeper")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "a"), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		filepath.Join(home, "elsewhere", "sub", "out.txt"):           "../../.ssh/authorized_keys",
		filepath.Join(home, "elsewhere", "sub", "deeper", "out.txt"): "../../../.ssh/authorized_keys",
	} {
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	return home, cwd
}

// A cd operand that Bash may resolve through CDPATH does not prove the
// directory the later write lands in, so the ordered cd/link/write shortcut
// does not take it. The link itself is placed in the directory the top-level
// cd statements name (GAP-1742): a link of plain files is not a protected
// write, so the link scope is not opaque and the evidence stays complete.
// An unexported CDPATH that the hook cannot see is a documented limit of the
// pre-tool check; a pushd keeps the conservative opaque scope.
func TestR104Loop3SearchPathCDKeepsLinkScopeOpaque(t *testing.T) {
	home, cwd := r104Loop3CDPathHome(t)
	for _, tc := range []struct {
		command  string
		searched bool // the cd may use CDPATH: no ordered-chain shortcut
		opaque   bool
	}{
		{`cd sub && ln -s ../a b && echo marker > out.txt`, true, false},
		{`cd sub && ln -s ../a b && echo marker >> out.txt`, true, false},
		{`cd sub && ln -s ../a b && echo marker > notes.md`, true, false},
		{`cd "sub" && ln -s ../a b && echo marker > out.txt`, true, false},
		{`cd sub/ && ln -s ../a b && echo marker > out.txt`, true, false},
		{`cd sub/. && ln -s ../a b && echo marker > out.txt`, true, false},
		{`cd sub/deeper && ln -s ../../a b && echo marker > out.txt`, true, false},
		{`cd ../project/sub && ln -s ../a b && echo marker > out.txt`, true, false},
		{`cd ./sub/../sub && ln -s ../a b && echo marker > out.txt`, true, false},
		{`pushd sub && ln -s ../a b && echo marker > out.txt`, true, true},
		{`cd ./sub && ln -s ../a b && echo marker > out.txt`, false, false},
		{`cd ./sub/deeper && ln -s ../../a b && echo marker > out.txt`, false, false},
		{`cd . && ln -s a b && echo marker > out.txt`, false, false},
		{`cd ` + filepath.ToSlash(filepath.Join(cwd, "sub")) + ` && ln -s ../a b && echo marker > out.txt`, false, false},
	} {
		file, ok := parseShell(tc.command)
		if !ok {
			t.Fatalf("%q does not parse", tc.command)
		}
		if call, _ := staticChangedDirectoryLink(file, cwd, home); (call != nil) == tc.searched {
			t.Fatalf("%q: shortcut = %v, want %v", tc.command, call != nil, !tc.searched)
		}
		if links := commandLinksWithFacts(tc.command, cwd, home, nil, false); links.globalOpaque != tc.opaque {
			t.Fatalf("%q: opaque link scope = %v, want %v", tc.command, links.globalOpaque, tc.opaque)
		}
		payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
			"tool_input": map[string]string{"command": tc.command}})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(Resolve(payload))
		if !ok {
			t.Fatalf("%q: hook evidence does not decode", tc.command)
		}
		if incomplete := targets[TruncatedKey] != ""; incomplete != tc.opaque {
			t.Fatalf("%q: hook evidence incomplete = %v, want %v", tc.command, incomplete, tc.opaque)
		}
	}
}
