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

func TestR104LiteralWriterOperands(t *testing.T) {
	cwd, home := t.TempDir(), "/tmp/home"
	want := filepath.Join(cwd, "alias")
	if err := os.WriteFile(want, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, command string }{
		{"environment unset option", `env -u X python3 -c 'open("alias","a").write("marker")'`},
		{"environment empty option", `env -i python3 -c 'open("alias","a").write("marker")'`},
		{"environment diagnostic option", `env -v python3 -c 'open("alias","a").write("marker")'`},
		{"builtin command", `command python3 -c 'open("alias","a").write("marker")'`},
		{"builtin command path option", `command -p python3 -c 'open("alias","a").write("marker")'`},
		{"priority wrapper", `nice -n 5 python3 -c 'open("alias","a").write("marker")'`},
		{"timeout wrapper", `timeout 30 python3 -c 'open("alias","a").write("marker")'`},
		{"session wrapper", `nohup node -e 'require("fs").appendFileSync("alias","marker")' >/dev/null 2>&1`},
		{"shell builtin", `exec python3 -c 'open("alias","a").write("marker")'`},
		{"child shell", `sh -c 'python3 -c "open(\"alias\",\"a\").write(\"marker\")"'`},
		{"bounded program", `p=python3; "$p" -c 'open("alias","a").write("marker")'`},
		{"python copy", `python3 -c 'import shutil; shutil.copyfile("payload","alias")'`},
		{"python isolated option", `python3 -I -c 'open("alias","a").write("marker")'`},
		{"path object open", `python3 -c 'from pathlib import Path; Path("alias").open("a").write("marker")'`},
		{"node stream", `node -e 'require("fs").createWriteStream("alias").write("marker")'`},
		{"here document", "python3 - <<'PY'\nopen(\"alias\",\"a\").write(\"marker\")\nPY"},
		{"child command from find", `find alias -exec python3 -c 'open("alias","a").write("marker")' \;`},
		{"child command from xargs", `printf alias | xargs -I{} python3 -c 'open("{}","a").write("marker")'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := LiteralWriteOperands(tc.command, cwd, home); !slices.Contains(got, want) {
				t.Fatalf("write operands = %q, want %q", got, want)
			}
		})
	}
	for _, command := range []string{
		`echo 'python3 -c '\''open("alias","a")'\'' '`,
		`f() { python3 -c 'open("alias","a").write("marker")'; }; echo ok`,
		`python3 -c 'open("report.txt","a").write("marker")'`,
		`python3 ordinary.py -c 'open("alias","a").write("marker")'`,
		`python3 -X ordinary.py -c 'open("alias","a").write("marker")'`,
		`node ordinary.js -e 'require("fs").writeFileSync("alias","marker")'`,
	} {
		if got := LiteralWriteOperands(command, cwd, home); slices.Contains(got, want) {
			t.Fatalf("inert command produced protected operand: %q", got)
		}
	}
}

func TestR104PatchDataIsNotAnEdit(t *testing.T) {
	cwd, home := t.TempDir(), t.TempDir()
	patch := "*** Begin Patch\n*** Update File: " + filepath.Join(home, ".ssh", "authorized_keys") +
		"\n@@\n-old\n+new\n*** End Patch\n"
	dataCommand := "cat > review.patch <<'EOF'\n" + patch + "EOF"
	args, err := json.Marshal(map[string]string{"command": dataCommand})
	if err != nil {
		t.Fatal(err)
	}
	if targets, known := ApplyPatchWriteTargets("Bash", args, dataCommand, cwd, home); !known || len(targets) != 0 {
		t.Fatalf("patch data targets = %q, known=%v", targets, known)
	}
	mentionedCommand := strings.Replace(patch, "+new", "+apply_patch", 1)
	dataCommand = "cat > review.patch <<'EOF'\n" + mentionedCommand + "EOF"
	if targets, known := ApplyPatchWriteTargets("Bash", nil, dataCommand, cwd, home); !known || len(targets) != 0 {
		t.Fatalf("quoted program name in patch data targets = %q, known=%v", targets, known)
	}
	editCommand := "apply_patch <<'EOF'\n" + patch + "EOF"
	if targets, known := ApplyPatchWriteTargets("Bash", nil, editCommand, cwd, home); !known ||
		!slices.Contains(targets, filepath.Join(home, ".ssh", "authorized_keys")) {
		t.Fatalf("applied patch targets = %q, known=%v", targets, known)
	}
}

func TestR104PatchFeedLiteralBackslash(t *testing.T) {
	cwd := t.TempDir()
	patch := "*** Begin Patch\n*** Update File: ordinary.c\n@@\n-puts(\"a\");\n+printf(\"a\\n\");\n*** End Patch\n"
	for _, tc := range []struct {
		name, opener, closer string
		known                bool
	}{
		{"unquoted here document", "apply_patch <<EOF", "EOF", true},
		{"quoted here document", "apply_patch <<'EOF'", "EOF", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := tc.opener + "\n" + patch + tc.closer
			targets, known := ApplyPatchWriteTargets("Bash", nil, command, cwd, cwd)
			if known != tc.known || !slices.Equal(targets, []string{filepath.Join(cwd, "ordinary.c")}) {
				t.Fatalf("patch targets = %q, known=%v", targets, known)
			}
		})
	}
	for _, line := range []string{"+$EXTRA", "+safe\\", "+safe\\\\"} {
		command := "apply_patch <<EOF\n" + strings.Replace(patch, "+printf(\"a\\n\");", line, 1) + "EOF"
		if targets, known := ApplyPatchWriteTargets("Bash", nil, command, cwd, cwd); known || len(targets) != 0 {
			t.Fatalf("expanding patch line %q: targets = %q, known=%v", line, targets, known)
		}
	}
}

func TestR104ClientProofForProtectedAlias(t *testing.T) {
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
	t.Setenv("HOME", home)
	for _, tc := range []struct{ name, command string }{
		{"wrapped interpreter", `env -i python3 -c 'open("alias","a").write("marker")'`},
		{"literal copy", `python3 -c 'import shutil; shutil.copyfile("payload","alias")'`},
		{"nested shell", `printf alias | xargs -I{} sh -c 'echo marker >> {}'`},
		{"generated script", `printf 'echo marker >> alias' > do.sh; source ./do.sh`},
		{"existing script", `. ./do.sh`},
		{"build recipe", `make writekeys`},
		{"configured ssh child", `git -c core.sshCommand='sh -c "echo marker >> alias"' ls-remote origin`},
		{"bounded redirect", `printf -v f %s alias; echo marker >> "$f"`},
		{"called function value", `f=other; g() { f=alias; }; g; echo marker >> "$f"`},
		{"directory function", `cd dirlink && f() { echo marker >> authorized_keys; }; f`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]string{"command": tc.command}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			if !ok {
				t.Fatal("client proof did not decode")
			}
			for _, target := range targets {
				if target == protected {
					return
				}
			}
			t.Fatalf("client proof has no protected target: %v", targets)
		})
	}
}

func TestR104IndirectWriterControls(t *testing.T) {
	cwd := t.TempDir()
	for name, content := range map[string]string{
		"do.sh":    "echo marker >> alias\n",
		"safe.sh":  "echo marker >> report.txt\n",
		"Makefile": ".PHONY: writekeys safe\nwritekeys:\n\t@echo marker >> alias\nsafe:\n\t@echo marker >> report.txt\n",
	} {
		if err := os.WriteFile(filepath.Join(cwd, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(cwd, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, ".git", "config"),
		[]byte("[remote \"origin\"]\n\turl = https://example.invalid/repo.git\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`. ./safe.sh`,
		`make safe`,
		`make -n writekeys`,
		`printf 'echo marker >> report.txt' > do.sh; . ./do.sh`,
		`git -c core.sshCommand='sh -c "echo marker >> alias"' ls-remote origin`,
	} {
		for _, target := range LiteralWriteOperands(command, cwd, cwd) {
			if target == filepath.Join(cwd, "alias") {
				t.Fatalf("inert indirect command produced protected operand: %q", command)
			}
		}
	}
}

func TestR104IndirectFileReadStaysWithinProject(t *testing.T) {
	skipPOSIXGrammarOnWindows(t)
	parent := t.TempDir()
	cwd := filepath.Join(parent, "project")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(parent, "outside.sh"), []byte("echo marker >> alias\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(parent, "outside.sh"), filepath.Join(cwd, "outside-link.sh")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../outside.sh", "outside-link.sh"} {
		if content, ok := readIndirectSource(name, cwd); ok || content != "" {
			t.Fatalf("external source %q was read", name)
		}
	}
	if err := os.WriteFile(filepath.Join(cwd, "local.sh"), []byte("echo marker >> alias\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if content, ok := readIndirectSource("local.sh", cwd); !ok || content != "echo marker >> alias\n" {
		t.Fatalf("local source read = %q, known=%v", content, ok)
	}
	if err := os.MkdirAll(filepath.Join(cwd, "sub", "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "sub", "actual.sh"), []byte("echo nested\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("sub", "nested"), filepath.Join(cwd, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if content, ok := readIndirectSource("dirlink/../actual.sh", cwd); !ok || content != "echo nested\n" {
		t.Fatalf("linked directory source read = %q, known=%v", content, ok)
	}
}

func TestR104DirectoryExecutionOperands(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(project, "dirlink")); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".ssh", "authorized_keys")
	for _, tc := range []struct{ name, command string }{
		{"called function", `cd dirlink && f() { echo marker >> authorized_keys; }; f`},
		{"called function keyword", `cd dirlink && function f { echo marker >> authorized_keys; }; f`},
		{"concurrent block", `cd dirlink && coproc { echo marker >> authorized_keys; }; wait`},
		{"interpreter after directory", `cd dirlink && python3 -c 'open("authorized_keys","a").write("marker")'`},
		{"environment directory", `env -C dirlink python3 -c 'open("authorized_keys","a").write("marker")'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := ShellDirectoryWriteOperands(tc.command, project, home, nil, false, false)
			if !slices.ContainsFunc(got, func(item RedirectOccurrence) bool { return item.Path == want }) {
				t.Fatalf("directory write operands = %v, want %q", got, want)
			}
		})
	}
	uncalled := `f() { echo marker >> authorized_keys; }; echo ok`
	if got, unknown := ShellDirectoryWriteOperands(uncalled, project, home, nil, false, false); len(got) != 0 || unknown {
		t.Fatalf("uncalled function = %v, unknown=%v", got, unknown)
	}
	if got, _, _ := ShellWriteOperands(uncalled, project, home); len(got) != 0 {
		t.Fatalf("uncalled function redirect = %v", got)
	}
}

func TestR104RecursiveFunctionWithoutFileEffects(t *testing.T) {
	cwd, home := t.TempDir(), t.TempDir()
	for _, command := range []string{`:(){ :|:& };:`, `f() { f | f & }; f`} {
		if writes, unknown := ShellDirectoryWriteOperands(command, cwd, home, nil, false, false); len(writes) != 0 || unknown {
			t.Fatalf("self-recursive body %q: writes=%v, unknown=%v", command, writes, unknown)
		}
	}
	command := `f() { f; echo marker >> ~/.ssh/authorized_keys; }; f`
	if _, unknown := ShellDirectoryWriteOperands(command, cwd, home, nil, false, false); !unknown {
		t.Fatal("recursive body with a file write must stay unknown")
	}
}

// GH #1169 (GAP-2429): the seven interpreter literal writes of the issue
// (Python Path.open and here-doc bodies, both also after cd through a
// directory link, a Perl lexical handle, a Node write stream and env -C)
// reach the protected keys file in the hook client's proof; the same
// writes to an ordinary project file do not.
func TestInterpreterLiteralWritesThroughLinksReachTheKeysFile(t *testing.T) {
	skipPOSIXGrammarOnWindows(t)
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
	if err := os.Symlink(protected, filepath.Join(cwd, "disklink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(cwd, "dirlink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	targets := func(t *testing.T, command string) []string {
		t.Helper()
		payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
			"tool_input": map[string]string{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		got, ok := Decode(Resolve(payload))
		if !ok {
			t.Fatal("client proof did not decode")
		}
		var values []string
		for _, value := range got {
			values = append(values, value)
		}
		return values
	}
	for _, tc := range []struct{ name, command, benign string }{
		{"path open", `python3 -c 'from pathlib import Path; Path("disklink").open("a").write("k")'`,
			`python3 -c 'from pathlib import Path; Path("notes.txt").open("a").write("k")'`},
		{"python here document", "python3 - <<'PY'\nopen(\"disklink\",\"a\").write(\"k\")\nPY",
			"python3 - <<'PY'\nopen(\"notes.txt\",\"a\").write(\"k\")\nPY"},
		{"path open after cd", `cd dirlink && python3 -c 'from pathlib import Path; Path("authorized_keys").open("a").write("k")'`,
			`python3 -c 'from pathlib import Path; Path("authorized_keys").open("a").write("k")'`},
		{"here document after cd", "cd dirlink && python3 - <<'PY'\nopen(\"authorized_keys\",\"a\").write(\"k\")\nPY",
			"python3 - <<'PY'\nopen(\"authorized_keys\",\"a\").write(\"k\")\nPY"},
		{"perl lexical handle after cd", `cd dirlink && perl -e 'open my $fh, ">>", "authorized_keys"; print $fh "k"'`,
			`perl -e 'open my $fh, ">>", "authorized_keys"; print $fh "k"'`},
		{"node write stream after cd", `cd dirlink && node -e 'require("fs").createWriteStream("authorized_keys").write("k")'`,
			`node -e 'require("fs").createWriteStream("authorized_keys").write("k")'`},
		{"env -C child", `env -C dirlink python3 -c 'from pathlib import Path; Path("authorized_keys").open("a").write("k")'`,
			`env -C . python3 -c 'from pathlib import Path; Path("authorized_keys").open("a").write("k")'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := targets(t, tc.command); !slices.Contains(got, protected) {
				t.Fatalf("client proof has no protected target: %v", got)
			}
			if got := targets(t, tc.benign); slices.Contains(got, protected) {
				t.Fatalf("benign twin %q reached the keys file: %v", tc.benign, got)
			}
		})
	}
}
