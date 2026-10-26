// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// r104ReviewProtectedWrite runs the protected-file proof the way a per-user
// gateway does (no client map) and the way a managed gateway does (the hook
// client's map, for Claude Code and Codex). It returns the decisions in that
// order.
func r104ReviewProtectedWrite(t *testing.T, command, cwd, home string) []bool {
	t.Helper()
	input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home,
		DialectHint: actionfacts.DialectPOSIX}
	decisions := []bool{trustedExistingAuthorizedKeysSymlinkWrite(trustedActionRequest{Input: input}, actionfacts.Analyze(input))}
	payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
		"tool_input": map[string]string{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
	if !ok {
		t.Fatal("client proof did not decode")
	}
	for _, connector := range []string{"claudecode", "codex"} {
		request := trustedActionRequest{Input: input, Connector: connector,
			ProtectedHomeHook: true, ResolvedWriteTargets: targets}
		decisions = append(decisions, trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)))
	}
	return decisions
}

func r104ReviewHome(t *testing.T) (home, cwd string) {
	t.Helper()
	home = t.TempDir()
	cwd = filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(protected, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(cwd, "alias")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	return home, cwd
}

func TestR104ReviewFixDecisions(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	for _, dir := range []string{filepath.Join(cwd, "sub"), filepath.Join(home, ".ssh", "sub")} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, command string
		blocked       bool
	}{
		{"called function writer", `f() { python3 -c 'open("alias","a").write("marker")'; }; f`, true},
		{"nested called function writer", `f() { python3 -c 'open("alias","a").write("marker")'; }; g() { f; }; g`, true},
		{"uncalled function protected mention", `f() { python3 -c 'open("alias","a").write("marker")'; }; echo ok`, false}, // GAP-1535
		{"dormant caller protected mention", `f() { python3 -c 'open("alias","a").write("marker")'; }; g() { f; }; echo ok`, true},
		{"function argument protected mention", `f() { python3 -c 'open("alias","a").write("marker")'; }; echo f`, true},
		{"literal writer in reachable caller", `f() { python3 -c 'open("alias","a").write("marker")'; }; g() { f; }; g`, true},
		{"Python FileIO", `python3 -c 'import io; io.FileIO("alias","w").write(b"marker")'`, true},
		{"Python imported FileIO", `python3 -c 'from io import FileIO; FileIO("alias",mode="a").write(b"marker")'`, true},
		{"Python FileIO keyword file", `python3 -c 'import io; io.FileIO(file="alias",mode="w").write(b"marker")'`, true},
		{"Python copy2", `python3 -c 'import shutil; shutil.copy2("payload","alias")'`, true},
		{"Python copy2 optional argument", `python3 -c 'import shutil; shutil.copy2("payload","alias",follow_symlinks=True)'`, true},
		{"Python copy2 keyword destination", `python3 -c 'import shutil; shutil.copy2("payload",dst="alias")'`, true},
		{"Python copy", `python3 -c 'import shutil; shutil.copy("payload","alias")'`, true},
		{"Node copyFileSync", `node -e 'require("fs").copyFileSync("payload","alias")'`, true},
		{"Node async copyFile", `node -e 'require("fs").copyFile("payload","alias",()=>{})'`, true},
		{"Perl File Copy", `perl -e 'use File::Copy; copy("payload","alias")'`, true},
		{"Perl qualified copy", `perl -e 'File::Copy::copy("payload","alias")'`, true},
		{"Perl bare copy", `perl -e 'use File::Copy; copy "payload", "alias"'`, true},
		{"FileIO protected named read", `python3 -c 'import io; io.FileIO("alias","r").read()'`, true},
		{"Perl protected named copy", `perl -e 'sub copy { return 1 }; copy("payload","alias")'`, true},
		{"protected named copy source", `node -e 'require("fs").copyFileSync("alias","out.txt")'`, true},
		{"copy destination control", `python3 -c 'import shutil; shutil.copy2("payload","out.txt")'`, false},
		// The project contains a symlink, so T7's import-path proof cannot
		// certify that Python keeps an inert string inert at runtime.
		{"Python hash comment beside uncertain import path", `python3 -c '#open("alias","a").write("marker")'`, true},
		{"bound pattern redirect", `printf -v f %s 'ali*'; echo marker >> $f`, true},
		{"bound pattern loop", `for f in 'ali*'; do echo marker >> $f; done`, true},
		{"quoted bound pattern", `printf -v f %s 'ali*'; echo marker >> "$f"`, false},
		// GAP-1742: a link after a top-level cd is judged by its operands; an
		// unexported CDPATH is a documented limit of the pre-tool check.
		{"search-path cd writes the link", `cd sub && ln -s ../authorized_keys b && echo marker > b`, false},
		{"search-path cd writes another file", `cd sub && ln -s ../a b && echo marker > out.txt`, false},
		{"explicit cd writes the link", `cd ./sub && ln -s ../authorized_keys b && echo marker > b`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for i, got := range r104ReviewProtectedWrite(t, tc.command, cwd, home) {
				if got != tc.blocked {
					t.Fatalf("decision %d (per-user, managed claudecode, managed codex) = %v, want %v", i, got, tc.blocked)
				}
			}
		})
	}
}
