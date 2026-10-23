// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestR104ExistingProtectedLinkWriters(t *testing.T) {
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
	if err := os.Symlink(protected, filepath.Join(cwd, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(cwd, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "payload"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "do.sh"), []byte("echo marker >> alias\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "Makefile"), []byte(".PHONY: writekeys\nwritekeys:\n\t@echo marker >> alias\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cwd, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, ".git", "config"),
		[]byte("[remote \"origin\"]\n\turl = ssh://example.invalid/repo.git\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, command string }{
		{"environment unset", `env -u X python3 -c 'open("alias","a").write("marker")'`},
		{"builtin command", `command -p python3 -c 'open("alias","a").write("marker")'`},
		{"priority wrapper", `nice -n 5 python3 -c 'open("alias","a").write("marker")'`},
		{"timeout wrapper", `timeout 30 cp payload alias`},
		{"shell wrapper", `sh -c 'python3 -c "open(\"alias\",\"a\").write(\"marker\")"'`},
		{"child command", `find alias -exec cp payload {} \;`},
		{"pipeline child", `printf alias | xargs -I{} python3 -c 'open("{}","a").write("marker")'`},
		{"pipeline shell child", `printf alias | xargs -I{} sh -c 'echo marker >> {}'`},
		{"find shell child", `find alias -exec sh -c 'echo marker >> "$1"' _ {} \;`},
		{"find named shell child", `find . -name alias -exec sh -c 'echo marker >> "$1"' _ {} \;`},
		{"generated script", `printf 'echo marker >> alias' > do.sh; . ./do.sh`},
		{"existing script", `. ./do.sh`},
		{"build recipe", `make writekeys`},
		{"configured ssh child", `git -c core.sshCommand='sh -c "echo marker >> alias"' ls-remote origin`},
		{"bounded program", `p=python3; "$p" -c 'open("alias","a").write("marker")'`},
		{"literal copy", `python3 -c 'import shutil; shutil.copyfile("payload","alias")'`},
		{"isolated interpreter", `python3 -I -c 'open("alias","a").write("marker")'`},
		{"path object open", `python3 -c 'from pathlib import Path; Path("alias").open("a").write("marker")'`},
		{"here document", "python3 - <<'PY'\nopen(\"alias\",\"a\").write(\"marker\")\nPY"},
		{"directory function", `cd dirlink && f() { echo marker >> authorized_keys; }; f`},
		{"directory coprocess", `cd dirlink && coproc { echo marker >> authorized_keys; }; wait`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: cwd, ActiveHome: home,
				DialectHint: actionfacts.DialectPOSIX}
			request := trustedActionRequest{Input: input}
			if !trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)) {
				t.Fatal("protected write was not proved")
			}
		})
	}
	for _, command := range []string{
		`f() { echo marker >> alias; }; echo ok`,
		`f() { echo marker >> ~/.ssh/authorized_keys; }; echo ok`,
		`python3 -c 'open("report.txt","a").write("marker")'`,
		`for f in safe; do echo marker >> "$f"; done`,
	} {
		input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home,
			DialectHint: actionfacts.DialectPOSIX}
		if trustedExistingAuthorizedKeysSymlinkWrite(trustedActionRequest{Input: input}, actionfacts.Analyze(input)) {
			t.Fatalf("ordinary command was treated as a protected write: %q", command)
		}
	}
}

func TestR104BoundedProtectedLinkWriter(t *testing.T) {
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
	if err := os.Symlink(protected, filepath.Join(cwd, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`printf -v f %s alias; echo marker >> "$f"`,
		`printf -v f '%s%s' ali as; echo marker >> "$f"`,
		`for f in as; do echo marker >> "ali$f"; done`,
		`f=other; g() { f=alias; }; g; echo marker >> "$f"`,
	} {
		input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home,
			DialectHint: actionfacts.DialectPOSIX}
		if !trustedExistingAuthorizedKeysSymlinkWrite(trustedActionRequest{Input: input}, actionfacts.Analyze(input)) {
			t.Fatalf("bounded protected write was not proved: %q", command)
		}
	}
}

func TestR104BoundProgramLinkCreation(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	input := actionfacts.Input{Tool: "Bash", Command: `L=ln; $L -s ~/.ssh/authorized_keys alias && echo marker >> alias`, CWD: cwd,
		ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
	if !trustedAuthorizedKeysSymlinkWrite(input) {
		t.Fatal("bound link command was not proved")
	}
}

func TestR104InterpreterTextNeedsAnExecutableWrite(t *testing.T) {
	home := t.TempDir()
	runtimeAlias := filepath.Join(home, "runtime-alias")
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(protected, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(protected, filepath.Join(home, "linked.txt")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, code string
		want       bool
	}{
		{"docstring", `"""p = Path.home() / '.ssh' / 'authorized_keys'; p.write_text('example')"""; print('ok')`, true},
		{"reassigned path", `from pathlib import Path; p = Path.home() / '.ssh' / 'authorized_keys'; p = Path('notes.txt'); p.write_text('hello')`, false},
		{"relative path after chdir", `from pathlib import Path; import os; os.chdir(Path.home() / '.ssh'); p = Path.home() / '.ssh' / 'authorized_keys'; p = Path('authorized_keys'); p.write_text('hello')`, true},
		{"relative path after aliased chdir", `from pathlib import Path; from os import chdir as enter; enter(Path.home() / '.ssh'); p = Path.home() / '.ssh' / 'authorized_keys'; p = Path('authorized_keys'); p.write_text('hello')`, true},
		{"absolute path after chdir", `from pathlib import Path; import os; os.chdir(Path.home() / '.ssh'); p = Path.home() / '.ssh' / 'authorized_keys'; p = Path('/tmp/ordinary-notes.txt'); p.write_text('hello')`, false},
		{"absolute path after runtime link", fmt.Sprintf(`from pathlib import Path; import os; os.symlink(Path.home() / '.ssh' / 'authorized_keys', %q); p = Path.home() / '.ssh' / 'authorized_keys'; p = Path(%q); p.write_text('hello')`, runtimeAlias, runtimeAlias), true},
		{"hardlink reassignment", `from pathlib import Path; p = Path.home() / '.ssh' / 'authorized_keys'; p = Path('linked.txt'); p.write_text('hello')`, true},
		{"direct path", `from pathlib import Path; p = Path.home() / '.ssh' / 'authorized_keys'; p.write_text('hello')`, true},
		{"docstring direct call", `"""Path('~/.ssh/authorized_keys').expanduser().write_text('example')"""; print('ok')`, true},
		{"executable direct call", `Path('~/.ssh/authorized_keys').expanduser().write_text('hello')`, true},
		{"expression before direct call", `x=1//2; Path('~/.ssh/authorized_keys').expanduser().write_text('hello')`, true},
		{"comment without space", `#open('~/.ssh/authorized_keys','a').write('hello')`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "Bash", Command: "python3 -c '" + tc.code + "'", CWD: home,
				ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
			// The shell quoting of snippets with single quotes is irrelevant to
			// this proof: ActionFacts may reject it, so give the command argv.
			input.Command = ""
			input.Argv = []string{"python3", "-c", tc.code}
			if got := trustedInlineAuthorizedKeysWrite(input, actionfacts.Analyze(input)); got != tc.want {
				t.Fatalf("inline write proof = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestR104OrdinaryBulkRedirectsStayComplete(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	var parts []string
	for i := range 33 {
		parts = append(parts, "printf marker > report"+string(rune('a'+i/26))+string(rune('a'+i%26)))
	}
	command := strings.Join(parts, "; ")
	payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
		"tool_input": map[string]string{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
	if !ok || targets[hookpaths.TruncatedKey] != "" {
		t.Fatalf("ordinary write map incomplete: decoded=%v, truncated=%q", ok, targets[hookpaths.TruncatedKey])
	}
	input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home,
		DialectHint: actionfacts.DialectPOSIX}
	request := trustedActionRequest{Input: input, Connector: "claudecode", ProtectedHomeHook: true,
		ResolvedWriteTargets: targets}
	if trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)) {
		t.Fatal("ordinary bulk redirects were treated as protected writes")
	}
}

func TestR104OrdinaryChainedRedirectInManagedMode(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(project, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "a"), []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, tc := range []struct {
		command string
		blocked bool
	}{
		{`cd ./sub && ln -s ../a b && echo marker > out.txt`, false},
		{`cd sub && ln -s ../a b && echo marker > out.txt`, true},
		{`cd sub && ln -s ../../.ssh/authorized_keys b && echo marker > b`, true},
	} {
		input := actionfacts.Input{Tool: "Bash", Command: tc.command, CWD: project, ActiveHome: home,
			DialectHint: actionfacts.DialectPOSIX}
		for _, connector := range []string{"claudecode", "codex"} {
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": project,
				"tool_input": map[string]string{"command": tc.command}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
			if !ok {
				t.Fatal("client proof did not decode")
			}
			request := trustedActionRequest{Input: input, Connector: connector,
				ProtectedHomeHook: true, ResolvedWriteTargets: targets}
			if got := trustedExistingAuthorizedKeysSymlinkWrite(request, actionfacts.Analyze(input)); got != tc.blocked {
				t.Fatalf("%s command %q: protected=%v, want %v", connector, tc.command, got, tc.blocked)
			}
		}
	}
}

func TestR104StoredPatchTextHasNoProtectedEdit(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	patch := "*** Begin Patch\n*** Update File: " + filepath.Join(home, ".ssh", "authorized_keys") +
		"\n@@\n-old\n+new\n*** End Patch\n"
	command := "cat > review.patch <<'EOF'\n" + patch + "EOF"
	input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home,
		DialectHint: actionfacts.DialectPOSIX}
	if trustedExistingAuthorizedKeysSymlinkWrite(trustedActionRequest{Input: input}, actionfacts.Analyze(input)) {
		t.Fatal("stored patch text was treated as an executed edit")
	}
}
