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
// the link lives. Windows lists a file's names; POSIX cannot, so a hard link
// whose other names are outside the agent folders is reported unknown.
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

	for _, tc := range []struct {
		name, path, want string
		unknown          bool
	}{
		{"same directory", sameDir, instruction, false},
		{"other directory", otherDir, instruction, false},
		{"agent home folder", homeAlias, homeInstruction, false},
		{"single ordinary file", ordinary, "", false},
		{"missing file", filepath.Join(root, "tmp", "missing"), "", false},
		{"instruction itself", instruction, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, unknown := InstructionAlias(tc.path, project, home)
			if !sameInstructionPath(got, tc.want) || unknown != tc.unknown {
				t.Fatalf("InstructionAlias(%q) = %q, unknown=%t; want %q, unknown=%t", tc.path, got, unknown, tc.want, tc.unknown)
			}
		})
	}
	// Outside the agent folders only Windows can name the other link.
	got, unknown := InstructionAlias(farAlias, project, home)
	if runtime.GOOS == "windows" {
		if !sameInstructionPath(got, elsewhere) || unknown {
			t.Fatalf("Windows far alias = %q, unknown=%t; want %q", got, unknown, elsewhere)
		}
	} else if got != "" || !unknown {
		t.Fatalf("POSIX far alias = %q, unknown=%t; want unknown", got, unknown)
	}
	got, unknown = InstructionAlias(pairB, project, home)
	if got != "" || unknown != (runtime.GOOS != "windows") {
		t.Fatalf("ordinary hard-link pair = %q, unknown=%t", got, unknown)
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
	got, unknown := InstructionAlias(link, filepath.Join(root, "cwd"), filepath.Join(root, "home"))
	if !sameInstructionPath(got, instruction) || unknown {
		t.Fatalf("symlink alias = %q, unknown=%t; want %q", got, unknown, instruction)
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
		{"unlisted names", "Bash", map[string]any{"command": "printf x >> " + far}, InstructionIdentityUnknown},
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
		{"absolute", "ln " + instruction + " /tmp/x", instruction, false},
		{"alias source", "ln " + alias + " /tmp/x", instruction, false},
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
		{"data only", `echo "os.link(CLAUDE.md)"`, "", false},
		{"read", "cat CLAUDE.md", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, unknown := InstructionLinkCreation("Bash", tc.command, project, home)
			if !sameInstructionPath(got, tc.want) || unknown != tc.unknown {
				t.Fatalf("InstructionLinkCreation(%q) = %q, unknown=%t; want %q, unknown=%t", tc.command, got, unknown, tc.want, tc.unknown)
			}
		})
	}
	if got, unknown := InstructionLinkCreation("apply_patch", "ln CLAUDE.md x", project, home); got != "" || unknown {
		t.Fatalf("a patch envelope is not shell: %q, %t", got, unknown)
	}
}

func TestInstructionLinkCreationThroughRunners(t *testing.T) {
	root := instructionIdentityRoot(t)
	project := filepath.Join(root, "project")
	instructionIdentityFile(t, project, "AGENTS.md")
	for _, command := range []string{
		"xargs ln < list",
		"printf 'AGENTS.md\\n' | xargs -I{} ln {} /tmp/x",
		`find . -name AGENTS.md -execdir cp -l {} /tmp/x \;`,
		"sh -c 'ln AGENTS.md x'",
		"env ln AGENTS.md x",
		"eval 'ln AGENTS.md x'",
	} {
		got, unknown := InstructionLinkCreation("Bash", command, project, root)
		if got == "" && !unknown {
			t.Errorf("InstructionLinkCreation(%q) allowed a hard link it cannot read", command)
		}
	}
}
