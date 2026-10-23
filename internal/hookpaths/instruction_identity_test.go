// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func instructionIdentityFile(t *testing.T, dir, name string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("instructions\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func instructionIdentityLink(t *testing.T, target, link string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, link); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func instructionIdentityRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// GAP-0869: a hard link is the instruction file under another name, wherever
// the link lives. Windows lists a file's names. POSIX cannot, so there a hard
// link is matched with the instruction files of the agent folders and the
// files the session loaded; any other multiply linked file is ordinary.
func TestInstructionAliasFollowsFileIdentity(t *testing.T) {
	root := instructionIdentityRoot(t)
	project := filepath.Join(root, "project")
	instruction := instructionIdentityFile(t, project, "CLAUDE.md")
	home := filepath.Join(root, "home")
	homeInstruction := instructionIdentityFile(t, filepath.Join(home, ".codex"), "AGENTS.md")
	elsewhere := instructionIdentityFile(t, filepath.Join(root, "unrelated"), "SOUL.md")
	ordinary := instructionIdentityFile(t, filepath.Join(root, "work"), "notes.txt")

	sameDir := instructionIdentityLink(t, instruction, filepath.Join(project, "notes.txt"))
	otherDir := instructionIdentityLink(t, instruction, filepath.Join(root, "tmp", "notes.txt"))
	homeAlias := instructionIdentityLink(t, homeInstruction, filepath.Join(root, "tmp", "agents-copy"))
	farAlias := instructionIdentityLink(t, elsewhere, filepath.Join(root, "tmp", "far"))
	pairA := instructionIdentityFile(t, filepath.Join(root, "pair"), "a.txt")
	pairB := instructionIdentityLink(t, pairA, filepath.Join(root, "pair", "b.txt"))
	dotClaude := instructionIdentityFile(t, filepath.Join(project, ".claude"), "CLAUDE.md")
	dotClaudeAlias := instructionIdentityLink(t, dotClaude, filepath.Join(root, "tmp", "project-rules"))
	ampGlobal := instructionIdentityFile(t, filepath.Join(home, ".config", "amp"), "AGENTS.md")
	ampAlias := instructionIdentityLink(t, ampGlobal, filepath.Join(root, "tmp", "amp-rules"))
	subdir := filepath.Join(project, "src", "pkg")
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, path, cwd, want string
		loaded                []string
	}{
		{"same directory", sameDir, project, instruction, nil},
		{"other directory", otherDir, project, instruction, nil},
		{"agent home folder", homeAlias, project, homeInstruction, nil},
		{"parent of the working directory", otherDir, subdir, instruction, nil},
		{"project .claude folder", dotClaudeAlias, subdir, dotClaude, nil},
		{"amp global folder", ampAlias, project, ampGlobal, nil},
		{"loaded by the session", farAlias, project, elsewhere, []string{ordinary, elsewhere}},
		{"single ordinary file", ordinary, project, "", nil},
		{"missing file", filepath.Join(root, "tmp", "missing"), project, "", nil},
		{"instruction itself", instruction, project, "", nil},
		// The release allows these; POSIX cannot prove more without a
		// listing of the file's names (pnpm and uv stores link files).
		{"ordinary hard-link pair", pairB, project, "", nil},
		{"ordinary pair with a loaded file", pairA, project, "", []string{instruction, elsewhere}},
		{"loaded name that is not an instruction file", pairB, project, "", []string{pairA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := InstructionAlias(tc.path, tc.cwd, home, tc.loaded); !sameInstructionPath(got, tc.want) {
				t.Fatalf("InstructionAlias(%q) = %q; want %q", tc.path, got, tc.want)
			}
		})
	}
	// An instruction file in no agent folder and not loaded: only Windows
	// can name the other link.
	got := InstructionAlias(farAlias, project, home, nil)
	if runtime.GOOS == "windows" {
		if !sameInstructionPath(got, elsewhere) {
			t.Fatalf("Windows far alias = %q; want %q", got, elsewhere)
		}
	} else if got != "" {
		t.Fatalf("POSIX far alias = %q; want none", got)
	}
}

// An agent's configured home holds its global instruction file.
func TestInstructionAliasConfiguredAgentHome(t *testing.T) {
	root := instructionIdentityRoot(t)
	config := filepath.Join(root, "claude-config")
	t.Setenv("CLAUDE_CONFIG_DIR", config)
	instruction := instructionIdentityFile(t, config, "CLAUDE.md")
	alias := instructionIdentityLink(t, instruction, filepath.Join(root, "tmp", "notes.txt"))
	if got := InstructionAlias(alias, filepath.Join(root, "project"), filepath.Join(root, "home"), nil); !sameInstructionPath(got, instruction) {
		t.Fatalf("alias of CLAUDE_CONFIG_DIR/CLAUDE.md = %q; want %q", got, instruction)
	}
}

func sameInstructionPath(got, want string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(got), filepath.Clean(want))
	}
	return got == want
}

func TestInstructionAliasThroughSymlinkElsewhere(t *testing.T) {
	root := instructionIdentityRoot(t)
	instruction := instructionIdentityFile(t, filepath.Join(root, "project"), "CLAUDE.md")
	link := filepath.Join(root, "tmp", "rules")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(instruction, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got := InstructionAlias(link, filepath.Join(root, "cwd"), filepath.Join(root, "home"), nil)
	if !sameInstructionPath(got, instruction) {
		t.Fatalf("symlink alias = %q; want %q", got, instruction)
	}
}

func instructionResolve(t *testing.T, cwd, tool string, input map[string]any) map[string]string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": tool, "tool_input": input,
	})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := Decode(Resolve(body))
	if !ok {
		t.Fatalf("client evidence for %s %v did not decode", tool, input)
	}
	return targets
}

// The managed hook client checks identity as the user, so a gateway that
// cannot read the user's home (ProtectHome) still learns the file.
func TestResolveReportsInstructionIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows gateway checks file identity itself")
	}
	root := instructionIdentityRoot(t)
	project := filepath.Join(root, "project")
	instruction := instructionIdentityFile(t, project, "CLAUDE.md")
	alias := instructionIdentityLink(t, instruction, filepath.Join(root, "tmp", "notes.txt"))
	far := instructionIdentityLink(t, instructionIdentityFile(t, filepath.Join(root, "far"), "SOUL.md"),
		filepath.Join(root, "tmp", "far.txt"))
	ordinary := instructionIdentityFile(t, filepath.Join(root, "tmp"), "plain.txt")
	for _, tc := range []struct {
		name, tool string
		input      map[string]any
		want       string
	}{
		{"shell append", "Bash", map[string]any{"command": "printf x >> " + alias}, instruction},
		{"shell relative", "Bash", map[string]any{"command": "printf x > ../tmp/notes.txt"}, instruction},
		{"native write", "Write", map[string]any{"file_path": alias, "content": "x"}, instruction},
		{"native edit", "Edit", map[string]any{"file_path": alias, "old_string": "instructions", "new_string": "x"}, instruction},
		{"tee", "Bash", map[string]any{"command": "echo x | tee -a " + alias}, instruction},
		{"hard link creation", "Bash", map[string]any{"command": "ln " + filepath.Join(project, "CLAUDE.md") + " " + filepath.Join(root, "tmp", "new")}, filepath.Join(project, "CLAUDE.md")},
		{"link of an alias", "Bash", map[string]any{"command": "ln " + alias + " " + filepath.Join(root, "tmp", "again")}, instruction},
		{"instruction file in no agent folder", "Bash", map[string]any{"command": "printf x >> " + far}, ""},
		{"cp into the link", "Bash", map[string]any{"command": "cp " + ordinary + " " + alias}, instruction},
		{"python open", "Bash", map[string]any{"command": "python3 -c \"open('" + alias + "', 'a').write('x')\""}, instruction},
		{"multi edit", "MultiEdit", map[string]any{"file_path": alias, "edits": []map[string]any{{"old_string": "instructions", "new_string": "x"}}}, instruction},
		{"ordinary file", "Bash", map[string]any{"command": "printf x >> " + ordinary}, ""},
		{"symbolic link creation", "Bash", map[string]any{"command": "ln -s " + instruction + " " + filepath.Join(root, "tmp", "sym")}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets := instructionResolve(t, project, tc.tool, tc.input)
			if got := targets[InstructionIdentityKey]; got != tc.want {
				t.Fatalf("identity = %q, want %q (targets %v)", got, tc.want, targets)
			}
		})
	}
}

// A file with several hard links is not an instruction file because of its
// link count: pnpm and uv stores hard-link package files into node_modules
// and .venv. Writing, editing or linking one again carries no identity fact,
// so the gateway does not block it as a protected file.
func TestResolveLeavesOrdinaryHardLinks(t *testing.T) {
	root := instructionIdentityRoot(t)
	project := filepath.Join(root, "project")
	instructionIdentityFile(t, project, "CLAUDE.md")
	stored := instructionIdentityFile(t, filepath.Join(root, "store", "v10", "files"), "00ab")
	installed := instructionIdentityLink(t, stored, filepath.Join(project, "node_modules", ".pnpm", "pkg@1.0.0", "index.js"))
	venv := instructionIdentityLink(t, stored, filepath.Join(project, ".venv", "lib", "site.py"))
	for _, tc := range []struct {
		name, tool string
		input      map[string]any
	}{
		{"native write", "Write", map[string]any{"file_path": installed, "content": "x"}},
		{"native edit", "Edit", map[string]any{"file_path": installed, "old_string": "instructions", "new_string": "x"}},
		{"multi edit", "MultiEdit", map[string]any{"file_path": venv, "edits": []map[string]any{{"old_string": "instructions", "new_string": "x"}}}},
		{"shell append", "Bash", map[string]any{"command": "printf x >> '" + installed + "'"}},
		{"shell relative", "Bash", map[string]any{"command": "printf x > .venv/lib/site.py"}},
		{"tee", "Bash", map[string]any{"command": "echo x | tee -a '" + venv + "'"}},
		{"hard link of it", "Bash", map[string]any{"command": "ln '" + installed + "' '" + filepath.Join(root, "tmp-copy") + "'"}},
		{"cp link of it", "Bash", map[string]any{"command": "cp -al '" + venv + "' '" + filepath.Join(root, "tmp-copy2") + "'"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets := instructionResolve(t, project, tc.tool, tc.input)
			if got, present := targets[InstructionIdentityKey]; present {
				t.Fatalf("identity = %q for an ordinary hard-linked file, want none (targets %v)", got, targets)
			}
		})
	}
}

func TestDecodeInstructionIdentity(t *testing.T) {
	encode := func(value string) string {
		data, _ := json.Marshal(map[string]string{CWDKey: "/repo", InstructionIdentityKey: value})
		return base64.RawURLEncoding.EncodeToString(data)
	}
	for _, tc := range []struct {
		value string
		ok    bool
	}{
		{InstructionIdentityUnknown, true},
		{filepath.Join(string(filepath.Separator)+"repo", "CLAUDE.md"), runtime.GOOS != "windows"},
		{"CLAUDE.md", false},
	} {
		if _, ok := Decode(encode(tc.value)); ok != tc.ok {
			t.Errorf("Decode(identity=%q) ok=%t, want %t", tc.value, ok, tc.ok)
		}
	}
	rest, _ := SplitOpaqueScopeFacts(map[string]string{CWDKey: "/repo", InstructionIdentityKey: "?"})
	if _, present := rest[InstructionIdentityKey]; present {
		t.Fatal("the authorized-keys proof must not see the instruction-identity fact as an operand")
	}
}

func TestInstructionLinkCreation(t *testing.T) {
	root := instructionIdentityRoot(t)
	project := filepath.Join(root, "project")
	instruction := instructionIdentityFile(t, project, "CLAUDE.md")
	alias := instructionIdentityLink(t, instruction, filepath.Join(root, "tmp", "notes.txt"))
	instructionIdentityFile(t, project, "plain.txt")
	shared := instructionIdentityFile(t, project, "shared.txt")
	instructionIdentityLink(t, shared, filepath.Join(root, "store", "shared.txt"))
	far := instructionIdentityFile(t, filepath.Join(root, "persona"), "SOUL.md")
	farAlias := instructionIdentityLink(t, far, filepath.Join(root, "tmp", "draft.txt"))
	home := filepath.Join(root, "home")
	for _, tc := range []struct {
		name, command, want string
		unknown             bool
	}{
		{"ln", "ln CLAUDE.md notes.txt", instruction, false},
		{"ln options", "ln -f -- CLAUDE.md /tmp/x", instruction, false},
		{"ln target directory", "ln -t /tmp CLAUDE.md", instruction, false},
		{"ln physical", "ln -P CLAUDE.md x", instruction, false},
		{"link", "link CLAUDE.md x", instruction, false},
		{"cp link", "cp -l CLAUDE.md x", instruction, false},
		{"cp long link", "cp --link CLAUDE.md x", instruction, false},
		{"cp archive link", "cp -al CLAUDE.md x", instruction, false},
		{"busybox", "busybox ln CLAUDE.md x", instruction, false},
		{"absolute", "ln '" + instruction + "' /tmp/x", instruction, false},
		{"alias source", "ln '" + alias + "' /tmp/x", instruction, false},
		{"in a chain", "true && ln CLAUDE.md x && printf y >> x", instruction, false},
		{"wrapped", "sudo ln CLAUDE.md x", "CLAUDE.md", false},
		{"find exec", "find . -name CLAUDE.md -exec ln {} /tmp/x \\;", "CLAUDE.md", false},
		{"python", `python3 -c "import os; os.link('CLAUDE.md', 'x')"`, "CLAUDE.md", false},
		{"pathlib", `python3 -c "from pathlib import Path; Path('x').hardlink_to('soul.md')"`, "SOUL.md", false},
		{"node", `node -e "require('fs').linkSync('AGENTS.md', 'x')"`, "AGENTS.md", false},
		{"powershell", `New-Item -ItemType HardLink -Path x -Target CLAUDE.md`, "CLAUDE.md", false},
		{"cmd mklink", `cmd /c mklink /H x CLAUDE.md`, "CLAUDE.md", false},
		{"fsutil", `fsutil hardlink create x openclaw.json`, "openclaw.json", false},
		{"dynamic source", `ln "$SRC" x`, "", true},
		{"dynamic interpreter", `python3 -c "import os,sys; os.link(sys.argv[1], 'x')" "$F"`, "", true},
		{"symbolic", "ln -s CLAUDE.md x", "", false},
		{"symbolic long", "ln --symbolic CLAUDE.md x", "", false},
		{"cp symbolic", "cp -s CLAUDE.md x", "", false},
		{"copy", "cp CLAUDE.md backup.md", "", false},
		{"ordinary hard link", "ln plain.txt plain2.txt", "", false},
		{"ordinary multiply linked source", "ln shared.txt shared2.txt", "", false},
		{"cp link of a multiply linked source", "cp -al shared.txt shared3.txt", "", false},
		{"data only", `echo "os.link(CLAUDE.md)"`, "", false},
		{"read", "cat CLAUDE.md", "", false},
		{"wrapped symbolic", "sudo ln -s /opt/x /usr/local/bin/x", "", false},
		{"wrapped copy", `bash -lc "cp a b" > out.txt`, "", false},
		{"wrapped dynamic", `xargs ln < list`, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, unknown := InstructionLinkCreation("Bash", tc.command, project, home, nil)
			if !sameInstructionPath(got, tc.want) || unknown != tc.unknown {
				t.Fatalf("InstructionLinkCreation(%q) = %q, unknown=%t; want %q, unknown=%t", tc.command, got, unknown, tc.want, tc.unknown)
			}
		})
	}
	if got, unknown := InstructionLinkCreation("apply_patch", "ln CLAUDE.md x", project, home, nil); got != "" || unknown {
		t.Fatalf("a patch envelope is not shell: %q, %t", got, unknown)
	}
	// The session's loaded files name a source that no agent folder holds.
	command := "ln '" + farAlias + "' again.txt"
	want := ""
	if runtime.GOOS == "windows" {
		want = far
	}
	if got, unknown := InstructionLinkCreation("Bash", command, project, home, nil); !sameInstructionPath(got, want) || unknown {
		t.Fatalf("link of an unloaded far alias = %q, unknown=%t; want %q", got, unknown, want)
	}
	if got, unknown := InstructionLinkCreation("Bash", command, project, home, []string{far}); !sameInstructionPath(got, far) || unknown {
		t.Fatalf("link of a loaded file's alias = %q, unknown=%t; want %q", got, unknown, far)
	}
}

// A runner (sh -c, env, eval, find -exec, xargs) hides ln's options; an
// instruction name in its text is enough to refuse it.
func TestInstructionLinkCreationThroughRunners(t *testing.T) {
	root := instructionIdentityRoot(t)
	project := filepath.Join(root, "project")
	instructionIdentityFile(t, project, "AGENTS.md")
	for _, command := range []string{
		"printf 'AGENTS.md\\n' | xargs -I{} ln {} /tmp/x",
		`find . -name AGENTS.md -execdir cp -l {} /tmp/x \;`,
		"sh -c 'ln AGENTS.md x'",
		"env ln AGENTS.md x",
		"eval 'ln AGENTS.md x'",
	} {
		if got, _ := InstructionLinkCreation("Bash", command, project, root, nil); got != "AGENTS.md" {
			t.Errorf("InstructionLinkCreation(%q) = %q, want AGENTS.md", command, got)
		}
	}
}
