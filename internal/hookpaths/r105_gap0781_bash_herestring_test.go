// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-0781 (Windows leg, NP4 np4-owin): Codex on Windows runs apply_patch
// through Git Bash, & bash.exe -lc @'...'@, with the arg0 apply_patch.bat
// path or a PATH export. The here-string body was read as one glob pattern:
// it holds a / and the *** envelope markers, so it named a directory that
// does not exist, which counts as a possibly protected expansion on a
// Windows host, and a README.md patch was a protected target. Each line of
// the body is now its own candidate. The decisive run is native Windows
// (windows-native.yml); elsewhere the glob expansion is not reached.
func TestActionWindowsGitBashHereStringIsNotOneGlob(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the Windows scanner expands a glob only on a Windows host")
	}
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "k.pub"), []byte("ssh-ed25519 AAAA test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "README.md"), []byte("plain notes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(proj, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"src/a.py": "x = 1\n", "src/a.ts": "export {};\n", "package.json": "{\n}\n"} {
		if err := os.WriteFile(filepath.Join(proj, filepath.FromSlash(name)), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	msys := filepath.ToSlash(home)
	if volume := filepath.VolumeName(home); len(volume) == 2 && volume[1] == ':' {
		msys = "/" + strings.ToLower(volume[:1]) + filepath.ToSlash(home[2:])
	}
	bash := "& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc @'\n"
	envelope := "*** Begin Patch\n*** Update File: README.md\n@@\n+np4-heredoc-line\n*** End Patch\nPATCH\ncat README.md\n'@"
	arg0 := msys + "/.codex/tmp/arg0/codex-arg0Utk7ea"
	// RV7-1: a patch line split at its last / leaves program text such as
	// glob.glob("data as a directory name; Windows refuses that name
	// (ERROR_INVALID_NAME), so it names no directory rather than one this
	// process could not see.
	patch := func(file, line string) string {
		return bash + "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: " + file + "\n@@\n+" + line + "\n*** End Patch\nPATCH\n'@"
	}
	single := "& 'C:\\Program Files\\Git\\bin\\bash.exe' -lc '"
	for _, tc := range []struct {
		name, command, want string
	}{
		{"arg0 apply_patch.bat", bash + arg0 + "/apply_patch.bat <<'PATCH'\n" + envelope, ""},
		{"PowerShell and bash PATH export", "$env:PATH += ';" + home + "\\.codex\\tmp\\arg0\\codex-arg0Utk7ea'; " +
			bash + "export PATH=\"$PATH:" + arg0 + "\"\napply_patch <<'PATCH'\n" + envelope, ""},
		{"PATH export then apply_patch.bat", bash + "export PATH=\"$PATH:" + arg0 + "\"\napply_patch.bat <<'PATCH'\n" + envelope, ""},
		{"bare apply_patch", bash + "apply_patch <<'PATCH'\n" + envelope, ""},
		{"listing with a glob and a path", bash + "ls /c/tmp/*.md\ncat README.md\n'@", ""},
		{"patch adds a Python glob call", patch("src/a.py", `files = glob.glob("data/*.csv")`), ""},
		{"patch adds a package.json script glob", patch("package.json", `    "test": "jest src/*.test.js"`), ""},
		{"patch adds a TypeScript glob import", patch("src/a.ts", `import "./styles/*.css";`), ""},
		{"here-string grep with a quoted pattern", bash + "grep -n \"TODO\" src/*.py\n'@", ""},
		{"here-string ls of a quoted directory", bash + "ls \"src\"/*.py\n'@", ""},
		{"here-string echo with a colon then ls", bash + "echo \"Status: ok\" && ls src/*.py\n'@", ""},
		{"single-quoted grep with a quoted pattern", single + "grep -n \"TODO\" src/*.py'", ""},
		{"single-quoted ls of a quoted directory", single + "ls \"src\"/*.py'", ""},
		{"single-quoted echo with a colon then ls", single + "echo \"Status: ok\" && ls src/*.py'", ""},
		{"key glob in the script", bash + "cp k.pub ~/.ssh/authorized_k*\n'@", "protected-target"},
		{"key glob under a double-quoted key directory", bash + "cp k.pub \"" + msys + "/.ssh\"/authorized_k*\n'@", "protected-target"},
		{"key glob under a single-quoted key directory", single + "cp k.pub \"" + msys + "/.ssh\"/authorized_k*'", "protected-target"},
		{"key glob after a quoted colon word", bash + "echo \"x: y\" && cp k.pub ~/.ssh/authorized_k*\n'@", "protected-target"},
		{"key path in the script", bash + "printf x >> " + msys + "/.ssh/authorized_keys\n'@", "protected-target"},
		{"key directive in the envelope", bash + "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: " + msys +
			"/.ssh/authorized_keys\n@@\n+k\n*** End Patch\nPATCH\n'@", "protected-target"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ActionCommandDecision(tc.command, proj, home); got != tc.want {
				t.Fatalf("ActionCommandDecision(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
	// RV8-1: the script of bash -c is read as Git Bash reads it (quote
	// removal, ~, $HOME, ${HOME}, cd, the MSYS /c/ drive), in the
	// here-string and in the single-quoted form. Key targets spelled with a
	// quoted, $HOME-based or /c/ directory stay protected targets.
	for _, script := range []string{
		`cp k.pub "$HOME"/.ssh/authorized_k*`,
		`cp k.pub "$HOME/.ssh"/authorized_k*`,
		`cp k.pub "${HOME}"/.ssh/authorized_k*`,
		`cp k.pub ` + filepath.ToSlash(home) + `/".ssh"/authorized_k*`,
		`cp k.pub ""` + msys + `/.ssh/authorized_k*`,
		`cp k.pub "` + msys + `"/.ssh/authorized_k*`,
		`cp k.pub ` + msys + `/.ssh/authorized_k*`,
		`cp k.pub ` + msys + `/".ssh"/authorized_k*`,
		`cp k.pub ~/".ssh"/authorized_k*`,
		`cp k.pub ~/'.ssh'/authorized_k*`,
		`echo k>` + msys + `/.ssh/authorized_k*`,
		`echo k > ` + msys + `/.ssh/authorized_k*`,
		`printf k >> "$HOME"/.ssh/authorized_keys`,
		`cd ~ && cp proj/k.pub .ssh/authorized_k*`,
		`cd ~ && cp proj/k.pub ".ssh"/authorized_k*`,
		`cd ~ && cp proj/k.pub '.ssh'/authorized_k*`,
		`cd ~ && cp proj/k.pub ".ssh/"authorized_k*`,
		`cd ~ && cp proj/k.pub ".s"sh/authorized_k*`,
		`cd ~ && cp proj/k.pub .ssh/authorized_keys`,
		`cd ` + msys + ` && cp proj/k.pub .ssh/authorized_k*`,
	} {
		for form, command := range map[string]string{
			"here-string":   bash + script + "\n'@",
			"single-quoted": single + strings.ReplaceAll(script, "'", "''") + "'",
		} {
			t.Run(form+" "+script, func(t *testing.T) {
				if got := ActionCommandDecision(command, proj, home); got != "protected-target" {
					t.Fatalf("ActionCommandDecision(%q) = %q, want protected-target", command, got)
				}
			})
		}
	}
}

// The MSYS spelling of a name Windows refuses is what Git Bash reads.
func TestActionMSYSMappedPath(t *testing.T) {
	for in, want := range map[string]string{
		`C:\p\glob.glob("data`: "C:\\p\\glob.glob(\uf022data",
		`C:\p\x: y`:            "C:\\p\\x\uf03a y",
		`C:\p\src`:             `C:\p\src`,
	} {
		if runtime.GOOS != "windows" {
			in, want = strings.TrimPrefix(in, "C:"), strings.TrimPrefix(want, "C:")
		}
		if got := actionMSYSMappedPath(in); got != want {
			t.Errorf("actionMSYSMappedPath(%q) = %q, want %q", in, got, want)
		}
	}
}
