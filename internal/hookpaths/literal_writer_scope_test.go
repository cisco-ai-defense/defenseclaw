// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// A literal interpreter write in a function body runs where the function is
// called; an uncalled definition stays inert.
func TestR104CalledFunctionLiteralWriter(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
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
	alias := filepath.Join(cwd, "alias")
	if err := os.Symlink(protected, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	called := []string{
		`f() { python3 -c 'open("alias","a").write("marker")'; }; f`,
		`f() { node -e 'require("fs").appendFileSync("alias","marker")'; }; g() { f; }; g`,
		`f() { printf alias | xargs -I{} python3 -c 'open("{}","a").write("marker")'; }; f`,
		`f() { g; }; g() { :; }; f; g() { python3 -c 'open("alias","a").write("marker")'; }; f`,
	}
	for _, command := range called {
		if got := LiteralWriteOperands(command, cwd, home); !slices.Contains(got, alias) {
			t.Fatalf("called function %q: write operands = %q, want %q", command, got, alias)
		}
		payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
			"tool_input": map[string]string{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(Resolve(payload))
		if !ok || targets[alias] != protected {
			t.Fatalf("client proof for %q = %v, want %s -> %s", command, targets, alias, protected)
		}
	}
	// Each body is read once, so recursion and fan-out stay linear.
	fanOut := `f() { f; f; f; f; f; f; f; f; f; f; python3 -c 'open("alias","a").write("marker")'; echo marker > out; }; f`
	start := time.Now()
	if got := LiteralWriteOperands(fanOut, cwd, home); len(got) != 1 || got[0] != alias {
		t.Fatalf("recursive function: write operands = %q, want one %q", got, alias)
	}
	if got, _, _ := ShellWriteOperands(fanOut, cwd, home); len(got) != 1 || got[0] != filepath.Join(cwd, "out") {
		t.Fatalf("recursive function: redirect operands = %q", got)
	}
	if _, unknown := ShellDirectoryWriteOperands("cd /tmp && "+fanOut, cwd, home, nil, false, false); !unknown {
		t.Fatal("a writing body past the expansion bound must be unknown")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("function fan-out took %v", elapsed)
	}
	for _, command := range []string{
		`f() { python3 -c 'open("alias","a").write("marker")'; }; echo ok`,
		`f() { python3 -c 'open("alias","a").write("marker")'; echo marker > alias; }; g() { f; }; echo ok`,
		`f() { python3 -c 'open("alias","a").write("marker")'; }; echo f`,
	} {
		if got := LiteralWriteOperands(command, cwd, home); slices.Contains(got, alias) {
			t.Fatalf("uncalled function %q produced a write operand: %q", command, got)
		}
		if got, _, _ := ShellWriteOperands(command, cwd, home); slices.Contains(got, alias) {
			t.Fatalf("uncalled function %q produced a redirect operand: %q", command, got)
		}
	}
}

// Bash expands an unquoted bound value or literal glob in a redirect as a
// pathname pattern, so the file it opens is unknown.
func TestR104BoundRedirectPatternIsUnknown(t *testing.T) {
	cwd, home := t.TempDir(), "/tmp/home"
	for _, tc := range []struct {
		command string
		unknown bool
		want    string
	}{
		{`printf -v f %s 'ali*'; echo marker >> $f`, true, ""},
		{`printf -v f %s 'ali?s'; echo marker > $f`, true, ""},
		{`printf -v f %s 'al[i]as'; echo marker > $f`, true, ""},
		{`printf -v f %s '@(alias)'; echo marker > $f`, true, ""},
		{`printf -v f %s 'ali\as'; echo marker > $f`, true, ""},
		{`printf -v f %s ali; echo marker >> $f*`, true, ""},
		{`for f in 'ali*'; do echo marker >> $f; done`, true, ""},
		{`printf -v f %s 'ali*'; echo marker >> "$f"`, false, filepath.Join(cwd, "ali*")},
		{`printf -v f %s alias; echo marker >> $f`, false, filepath.Join(cwd, "alias")},
	} {
		operands, unknown := BoundedShellWriteOperands(tc.command, cwd, home)
		if unknown != tc.unknown {
			t.Fatalf("%q: unknown = %v, want %v (operands %q)", tc.command, unknown, tc.unknown, operands)
		}
		if tc.want != "" && !slices.Contains(operands, tc.want) {
			t.Fatalf("%q: operands = %q, want %q", tc.command, operands, tc.want)
		}
		if tc.unknown && len(operands) != 0 {
			t.Fatalf("%q: pattern listed as a fixed operand: %q", tc.command, operands)
		}
	}
}

// The agent's shell may hold a CDPATH that the hook cannot see. Only a cd
// operand that bypasses CDPATH names a proven directory for the link.
func TestR104ChangedDirectoryLinkNeedsProvenDirectory(t *testing.T) {
	cwd, home := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(cwd, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		command  string
		shortcut bool
	}{
		{`cd sub && ln -s ../authorized_keys b && echo marker > b`, false},
		{`cd sub && ln -s ../a . && echo marker > a`, false},
		{`cd sub && ln -s ../x b && echo marker > authorized_keys`, false},
		{`cd sub && ln -s ../x b && echo marker > b/c`, false},
		{`cd ./sub/../sub && ln -s ../authorized_keys b && echo marker > b`, false},
		{`cd sub && ln -s ../a b && echo marker > out.txt`, false},
		{`cd ./sub && ln -s ../authorized_keys b && echo marker > b`, true},
		{`cd ` + filepath.Join(cwd, "sub") + ` && ln -s ../authorized_keys b && echo marker > b`, true},
	} {
		file, ok := parseShell(tc.command)
		if !ok {
			t.Fatalf("%q does not parse", tc.command)
		}
		call, _ := staticChangedDirectoryLink(file, cwd, home)
		if got := call != nil; got != tc.shortcut {
			t.Fatalf("%q: shortcut = %v, want %v", tc.command, got, tc.shortcut)
		}
	}
}
