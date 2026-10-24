// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLiteralInterpreterCodeSurvivesDynamicTrailingArguments(t *testing.T) {
	cwd, home := t.TempDir(), t.TempDir()
	want := filepath.Join(cwd, "alias")
	for _, command := range []string{
		`python3 -c 'open("alias","a").write("marker")' "$USER"`,
		`node -e 'require("fs").writeFileSync("alias","marker")' "$USER"`,
		`ruby -e 'File.write("alias","marker")' "$USER"`,
		`perl -e 'open(F, ">>", "alias")' "$USER"`,
	} {
		if got := LiteralWriteOperands(command, cwd, home); !slices.Contains(got, want) {
			t.Errorf("%q: operands = %q, want %q", command, got, want)
		}
	}
}

func TestUnprovenProtectedWriteEvidence(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh", "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cwd, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(protected, []byte("marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		filepath.Join(cwd, "alias"):                   protected,
		filepath.Join(cwd, "spaced link name"):        protected,
		filepath.Join(cwd, "aliasdir"):                filepath.Join(home, ".ssh"),
		filepath.Join(home, ".ssh", "sub", "out.txt"): "../authorized_keys",
	} {
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(cwd, "writer.sh"), []byte("echo marker >> alias\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "call-f.sh"), []byte("f\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command, reason string
	}{
		{"trap", `f() { echo marker >> alias; }; trap f EXIT`, "function"},
		{"trap handler arguments", `f() { echo marker >> alias; }; trap 'f argument' EXIT`, "function"},
		{"trap handler with multiple calls", `f() { echo marker >> alias; }; trap ':; f' EXIT`, "function"},
		{"trap handler evals function", `f() { echo marker >> alias; }; trap 'eval f' EXIT`, "function"},
		{"dynamic trap handler", `f() { echo marker >> alias; }; trap "$HANDLER" EXIT`, "function"},
		{"trap handler mentioning dormant function", `f() { echo marker >> alias; }; trap 'echo f' EXIT`, ""},
		{"eval calls function with arguments", `f() { echo marker >> alias; }; eval 'f argument'`, "function"},
		{"eval mentions dormant function", `f() { echo marker >> alias; }; eval 'echo f'`, ""},
		{"source calls function", `f() { echo marker >> alias; }; . call-f.sh`, "function"},
		{"dynamic command", `"$writer" alias`, "dynamic-command"},
		{"glob redirect", `echo marker > [a]lias`, "dynamic-argument"},
		{"assigned variable redirect", `f=alias; echo marker >> "$f"`, "dynamic-argument"},
		{"glob redirect with read-only link mention", `echo alias > out-*.txt`, ""},
		{"unrelated executable glob", `/bin/r['m'] -rf /`, ""},
		{"unrelated wrapped executable glob", `sudo -n env MODE=check command -p /bin/r* -rf /`, ""},
		{"eval", `eval 'echo marker >> alias'`, "eval-source"},
		{"dot source", `. writer.sh`, "eval-source"},
		{"function keyword", `function f { custom_writer alias; }; f`, "function"},
		{"nested eval", `bash -c 'eval "echo marker >> alias"'`, "eval-source"},
		{"dynamic interpreter path", `python3 -c 'open(path,"a").write("marker")'`, "interpreter-path"},
		{"home directory reaches unmodelled Ruby code", `cd ~ && ruby -e 'unknown_api()'`, "interpreter-path"},
		{"dynamic interpreter argument", `node -e 'require("fs").writeFileSync("alias","marker")' "$USER"`, "interpreter-argument"},
		{"copy directory", `python3 -c 'import shutil; shutil.copy2("payload/authorized_keys","aliasdir")'`, "copy-directory"},
		{"regex", `ruby -e '/#/.match("x"); File.write("alias","marker")'`, "interpreter-path"},
		{"quoted link name with spaces", `ruby -e 'unknown_api("spaced link name")'`, "interpreter-path"},
		{"async writer", `node -e 'require("fs").appendFile("alias","marker",()=>{})'`, "interpreter-path"},
		{"CDPATH", `cd sub && ln -s ../a b && echo marker > out.txt`, "cdpath"},
		{"inert definition", `f() { echo marker >> alias; }; echo ok`, ""},
		{"read-only Node", `node -e 'require("fs").readFile("alias",()=>{})'`, ""},
		{"read-only Python os.open", `python3 -c 'import os; os.open("alias",os.O_RDONLY)'`, ""},
		{"Node protected data", `node -e 'require("fs").writeFileSync("out.txt","alias")'`, ""},
		{"Python protected data", `python3 -c 'open("out.txt","a").write("alias")'`, ""},
		{"Python separate read and write", `python3 -c 'open("alias","r"); open("out.txt","a")'`, ""},
		{"Ruby read-only open", `ruby -e 'File.open("alias","r") { |f| puts f.read }'`, ""},
		{"unrelated dynamic log path", `truncate -s 0 "$LOG"`, ""},
		{"IPv6 URL brackets are not file globs", `curl --ipv4 --ftp-account marker ftp://[2606:4700:4700::1111]/`, ""},
		{"ordinary explicit cd", `cd ./sub && echo marker > out.txt`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "trap" || tc.name == "trap handler arguments" ||
				tc.name == "trap handler with multiple calls" || tc.name == "trap handler evals function" ||
				tc.name == "dynamic trap handler" || tc.name == "trap handler mentioning dormant function" ||
				tc.name == "eval calls function with arguments" || tc.name == "eval mentions dormant function" ||
				tc.name == "inert definition" {
				operands, parsed, _ := ShellWriteOperands(tc.command, cwd, home)
				called := tc.name == "trap" || tc.name == "trap handler arguments" ||
					tc.name == "trap handler with multiple calls" || tc.name == "trap handler evals function" ||
					tc.name == "dynamic trap handler" || tc.name == "eval calls function with arguments"
				if !parsed || slices.Contains(operands, filepath.Join(cwd, "alias")) != called {
					t.Fatalf("function redirect reachability = %q", operands)
				}
			}
			if got := UnprovenProtectedWrite(tc.command, cwd, home); got != tc.reason {
				t.Fatalf("class = %q, want %q", got, tc.reason)
			}
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]string{"command": tc.command}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			// The action resolver closes write-capable unknowns even when the
			// narrower historical UnprovenProtectedWrite proof returns empty.
			hookReason := tc.reason
			if extra := map[string]string{
				"eval mentions dormant function":            "eval-source",
				"glob redirect with read-only link mention": "dynamic-argument",
				"unrelated dynamic log path":                "dynamic-argument",
			}[tc.name]; extra != "" {
				hookReason = extra
			}
			if !ok || targets[UnprovenReasonKey] != hookReason {
				t.Fatalf("hook evidence class = %q, want %q", targets[UnprovenReasonKey], hookReason)
			}
		})
	}
	patch, err := json.Marshal(map[string]any{"tool_name": "apply_patch", "cwd": cwd,
		"tool_input": map[string]string{"command": "*** Begin Patch\n*** Add File: out.txt\n+ok\n*** End Patch"}})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := Decode(Resolve(patch))
	if !ok || targets[UnprovenReasonKey] != "" {
		t.Fatalf("structured patch mistaken for shell code: %q", targets[UnprovenReasonKey])
	}
	dual, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
		"tool_input": map[string]string{"command": `eval 'echo marker >> alias'`, "cmd": "echo ordinary"}})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok = Decode(Resolve(dual))
	if !ok || targets[UnprovenReasonKey] != "eval-source" {
		t.Fatalf("one benign command field erased protected class evidence: %q", targets[UnprovenReasonKey])
	}
	longCommand := strings.Repeat("echo ordinary; ", 520) + `eval 'echo marker >> alias'`
	if got := UnprovenProtectedWrite(longCommand, cwd, home); got != "eval-source" {
		t.Fatalf("bounded reach scan lost protected tail: %q", got)
	}
}
