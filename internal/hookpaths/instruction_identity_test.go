// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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

// instructionIdentitySymlink makes link a symbolic link to target and
// returns link itself (not the file it reaches).
func instructionIdentitySymlink(t *testing.T, target, link string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	return link
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
// the link lives. It is matched by file identity with the instruction files
// of the places agents load them from and the files the session loaded; any
// other file is ordinary, however many links it has, on every OS.
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
		// pnpm and uv stores hard-link package files: a link count proves
		// nothing about the file.
		{"ordinary hard-link pair", pairB, project, "", nil},
		{"ordinary pair with a loaded file", pairA, project, "", []string{instruction, elsewhere}},
		{"loaded name that is not an instruction file", pairB, project, "", []string{pairA}},
		// An instruction file in no load location that the session did not
		// load is not one of the call's instruction files, on any OS.
		{"instruction file in no load location", farAlias, project, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NewInstructionFiles(tc.cwd, home, tc.loaded).Alias(tc.path); !sameInstructionPath(got, tc.want) {
				t.Fatalf("Alias(%q) = %q; want %q", tc.path, got, tc.want)
			}
		})
	}
}

// GAP-0971: a symlinked instruction file is the file it reaches. Writing
// that physical file, which has one link and an ordinary name, writes the
// instruction file, whether the symlink is in a load location or the session
// loaded it. Its ordinary neighbors stay ordinary.
func TestInstructionAliasSymlinkedInstructionTarget(t *testing.T) {
	root := instructionIdentityRoot(t)
	project := filepath.Join(root, "project")
	home := filepath.Join(root, "home")
	shared := instructionIdentityFile(t, filepath.Join(root, "shared"), "instructions.txt")
	neighbor := instructionIdentityFile(t, filepath.Join(root, "shared"), "other.txt")
	projectLink := instructionIdentitySymlink(t, shared, filepath.Join(project, "CLAUDE.md"))
	dotfile := instructionIdentityFile(t, filepath.Join(root, "dotfiles"), "agents.txt")
	homeLink := instructionIdentitySymlink(t, dotfile, filepath.Join(home, ".codex", "AGENTS.md"))
	persona := instructionIdentityFile(t, filepath.Join(root, "persona-src"), "soul.txt")
	loadedLink := instructionIdentitySymlink(t, persona, filepath.Join(root, "persona", "SOUL.md"))
	sharedAlias := instructionIdentityLink(t, shared, filepath.Join(root, "tmp", "copy.txt"))
	subdir := filepath.Join(project, "src")
	if err := os.MkdirAll(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path, cwd, want string
		loaded                []string
	}{
		{"project symlink target", shared, project, projectLink, nil},
		{"from a subdirectory", shared, subdir, projectLink, nil},
		{"hard link of the target", sharedAlias, project, projectLink, nil},
		{"agent home symlink target", dotfile, project, homeLink, nil},
		{"loaded symlink target", persona, project, loadedLink, []string{loadedLink}},
		{"loaded symlink target, not loaded", persona, project, "", nil},
		{"ordinary neighbor", neighbor, project, "", nil},
		{"outside the project", shared, filepath.Join(root, "elsewhere"), "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NewInstructionFiles(tc.cwd, home, tc.loaded).Alias(tc.path); !sameInstructionPath(got, tc.want) {
				t.Fatalf("Alias(%q) = %q; want %q", tc.path, got, tc.want)
			}
		})
	}
}

// An agent's configured home holds its global instruction file.
func TestInstructionAliasConfiguredAgentHome(t *testing.T) {
	root := instructionIdentityRoot(t)
	config := filepath.Join(root, "claude-config")
	t.Setenv("CLAUDE_CONFIG_DIR", config)
	instruction := instructionIdentityFile(t, config, "CLAUDE.md")
	alias := instructionIdentityLink(t, instruction, filepath.Join(root, "tmp", "notes.txt"))
	if got := NewInstructionFiles(filepath.Join(root, "project"), filepath.Join(root, "home"), nil).Alias(alias); !sameInstructionPath(got, instruction) {
		t.Fatalf("alias of CLAUDE_CONFIG_DIR/CLAUDE.md = %q; want %q", got, instruction)
	}
}

func sameInstructionPath(got, want string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(got), filepath.Clean(want))
	}
	return got == want
}

// A symlink anywhere reaches the call's instruction file. One to an
// instruction-named file that is not one of the call's files is ordinary.
func TestInstructionAliasThroughSymlinkElsewhere(t *testing.T) {
	root := instructionIdentityRoot(t)
	instruction := instructionIdentityFile(t, filepath.Join(root, "project"), "CLAUDE.md")
	link := instructionIdentitySymlink(t, instruction, filepath.Join(root, "tmp", "rules"))
	for _, tc := range []struct{ cwd, want string }{
		{filepath.Join(root, "project"), instruction},
		{filepath.Join(root, "cwd"), ""},
	} {
		got := NewInstructionFiles(tc.cwd, filepath.Join(root, "home"), nil).Alias(link)
		if !sameInstructionPath(got, tc.want) {
			t.Fatalf("symlink alias from %s = %q; want %q", tc.cwd, got, tc.want)
		}
	}
}

// Action mode protects the call's instruction files and nothing else. An
// instruction-named file in no load location that the session did not load
// is ordinary, and so is every other name of it: a hard link or symlink in
// its own directory, in the project or anywhere else, and a case variant on
// a case-insensitive volume. The same names reach it once the session loads
// it or the agent works in its directory.
func TestInstructionAliasOnlyTheCallsInstructionFiles(t *testing.T) {
	root := instructionIdentityRoot(t)
	project := filepath.Join(root, "project")
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range InstructionFileNames {
		unrelated := filepath.Join(root, "unrelated-"+strings.ReplaceAll(name, ".", "-"))
		instruction := instructionIdentityFile(t, unrelated, name)
		for _, kind := range []struct {
			name string
			make func(t *testing.T) string
		}{
			{"same-directory hard link", func(t *testing.T) string {
				return instructionIdentityLink(t, instruction, filepath.Join(unrelated, "notes.txt"))
			}},
			{"hard link elsewhere", func(t *testing.T) string {
				return instructionIdentityLink(t, instruction, filepath.Join(root, "tmp", strings.ReplaceAll(name, ".", "-")+".txt"))
			}},
			{"same-directory symlink", func(t *testing.T) string {
				return instructionIdentitySymlink(t, instruction, filepath.Join(unrelated, "notes.link"))
			}},
			{"symlink in the project", func(t *testing.T) string {
				return instructionIdentitySymlink(t, instruction, filepath.Join(project, strings.ReplaceAll(name, ".", "-")+".link"))
			}},
			{"case variant", func(t *testing.T) string {
				variant := filepath.Join(unrelated, strings.ToLower(name))
				if runtime.GOOS == "windows" || variant == instruction {
					t.Skip("Windows judges a case variant by name; some names have none")
				}
				if other, err := os.Stat(variant); err != nil || !sameStat(t, instruction, other) {
					t.Skip("case-sensitive volume")
				}
				return variant
			}},
		} {
			t.Run(name+"/"+kind.name, func(t *testing.T) {
				alias := kind.make(t)
				if got := NewInstructionFiles(project, home, nil).Alias(alias); got != "" {
					t.Fatalf("Alias(%q) of an unloaded %s in no load location = %q; want none", alias, name, got)
				}
				if got := NewInstructionFiles(project, home, []string{instruction}).Alias(alias); !sameInstructionPath(got, instruction) {
					t.Fatalf("Alias(%q) of a loaded %s = %q; want %q", alias, name, got, instruction)
				}
				if got := NewInstructionFiles(unrelated, home, nil).Alias(alias); !sameInstructionPath(got, instruction) {
					t.Fatalf("Alias(%q) with the agent beside %s = %q; want %q", alias, name, got, instruction)
				}
			})
		}
	}
}

func sameStat(t *testing.T, path string, info os.FileInfo) bool {
	t.Helper()
	other, err := os.Stat(path)
	return err == nil && os.SameFile(info, other)
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
// cannot read the user's home (ProtectHome) still learns the file. Creating a
// link writes nothing.
func TestResolveReportsInstructionIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows gateway checks file identity itself")
	}
	root := instructionIdentityRoot(t)
	project := filepath.Join(root, "project")
	instruction := instructionIdentityFile(t, project, "CLAUDE.md")
	alias := instructionIdentityLink(t, instruction, filepath.Join(root, "tmp", "notes.txt"))
	farSoul := instructionIdentityFile(t, filepath.Join(root, "far"), "SOUL.md")
	far := instructionIdentityLink(t, farSoul, filepath.Join(root, "tmp", "far.txt"))
	beside := instructionIdentityLink(t, farSoul, filepath.Join(root, "far", "notes.txt"))
	ordinary := instructionIdentityFile(t, filepath.Join(root, "tmp"), "plain.txt")
	newName := filepath.Join(root, "tmp", "new")
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
		{"cp into the link", "Bash", map[string]any{"command": "cp " + ordinary + " " + alias}, instruction},
		{"python open", "Bash", map[string]any{"command": "python3 -c \"open('" + alias + "', 'a').write('x')\""}, instruction},
		{"multi edit", "MultiEdit", map[string]any{"file_path": alias, "edits": []map[string]any{{"old_string": "instructions", "new_string": "x"}}}, instruction},
		{"instruction file in no load location", "Bash", map[string]any{"command": "printf x >> " + far}, ""},
		{"beside an instruction file in no load location", "Write", map[string]any{"file_path": beside, "content": "x"}, ""},
		{"append beside an instruction file in no load location", "Bash", map[string]any{"command": "printf x >> " + beside}, ""},
		{"ordinary file", "Bash", map[string]any{"command": "printf x >> " + ordinary}, ""},
		{"hard link creation", "Bash", map[string]any{"command": "ln CLAUDE.md " + newName}, ""},
		{"symbolic link creation", "Bash", map[string]any{"command": "ln -s " + instruction + " " + newName}, ""},
		{"link of an alias", "Bash", map[string]any{"command": "ln " + alias + " " + newName}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets := instructionResolve(t, project, tc.tool, tc.input)
			if got := targets[InstructionIdentityKey]; got != tc.want {
				t.Fatalf("identity = %q, want %q (targets %v)", got, tc.want, targets)
			}
		})
	}
}

// GAP-0971 in the hook client: a write to the physical file a symlinked
// CLAUDE.md reaches carries that CLAUDE.md as its identity.
func TestResolveReportsSymlinkedInstructionTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows gateway checks file identity itself")
	}
	root := instructionIdentityRoot(t)
	project := filepath.Join(root, "project")
	shared := instructionIdentityFile(t, filepath.Join(root, "shared"), "instructions.txt")
	neighbor := instructionIdentityFile(t, filepath.Join(root, "shared"), "other.txt")
	link := instructionIdentitySymlink(t, shared, filepath.Join(project, "CLAUDE.md"))
	for _, tc := range []struct {
		name, tool string
		input      map[string]any
		want       string
	}{
		{"native write", "Write", map[string]any{"file_path": shared, "content": "x"}, link},
		{"native edit", "Edit", map[string]any{"file_path": shared, "old_string": "instructions", "new_string": "x"}, link},
		{"shell append", "Bash", map[string]any{"command": "printf x >> " + shared}, link},
		{"relative", "Bash", map[string]any{"command": "printf x > ../shared/instructions.txt"}, link},
		{"neighbor", "Write", map[string]any{"file_path": neighbor, "content": "x"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets := instructionResolve(t, project, tc.tool, tc.input)
			if got := targets[InstructionIdentityKey]; got != tc.want {
				t.Fatalf("identity = %q, want %q (targets %v)", got, tc.want, targets)
			}
		})
	}
}

func TestResolveReportsExistingStartupFileAndNotCreation(t *testing.T) {
	root := instructionIdentityRoot(t)
	project := filepath.Join(root, "project")
	file := instructionIdentityFile(t, project, "AGENTS.md")
	input := map[string]any{"file_path": file, "content": "updated"}
	if got := instructionResolve(t, project, "Write", input)[InstructionIdentityKey]; got != file {
		t.Fatalf("existing startup file identity = %q, want %q", got, file)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if got := instructionResolve(t, project, "Write", input)[InstructionIdentityKey]; got != "" {
		t.Fatalf("absent startup file had identity evidence %q", got)
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
		{"link then write", "Bash", map[string]any{"command": "ln '" + installed + "' '" + filepath.Join(root, "tmp-copy3") + "' && printf x >> '" + filepath.Join(root, "tmp-copy3") + "'"}},
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
		{filepath.Join(string(filepath.Separator)+"repo", "CLAUDE.md"), runtime.GOOS != "windows"},
		{"?", false},
		{"CLAUDE.md", false},
	} {
		if _, ok := Decode(encode(tc.value)); ok != tc.ok {
			t.Errorf("Decode(identity=%q) ok=%t, want %t", tc.value, ok, tc.ok)
		}
	}
	rest, _ := SplitOpaqueScopeFacts(map[string]string{CWDKey: "/repo", InstructionIdentityKey: "/repo/CLAUDE.md"})
	if _, present := rest[InstructionIdentityKey]; present {
		t.Fatal("the authorized-keys proof must not see the instruction-identity fact as an operand")
	}
}

// GAP-1065: a call that writes several instruction files under other names
// reports every one of them, once each, whatever their order.
func TestResolveReportsEveryInstructionAlias(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows gateway checks file identity itself")
	}
	root := instructionIdentityRoot(t)
	project := filepath.Join(root, "project")
	claude := instructionIdentityFile(t, project, "CLAUDE.md")
	soul := instructionIdentityFile(t, project, "SOUL.md")
	first := instructionIdentityLink(t, claude, filepath.Join(root, "tmp", "a.txt"))
	second := instructionIdentityLink(t, soul, filepath.Join(root, "tmp", "b.txt"))
	ordinary := instructionIdentityFile(t, filepath.Join(root, "tmp"), "plain.txt")
	both := []string{claude, soul}
	for _, tc := range []struct {
		name, command string
		want          []string
	}{
		{"two appends", "printf x >> " + first + "; printf y >> " + second, both},
		{"reversed", "printf y >> " + second + " && printf x >> " + first, both},
		{"tee", "echo x | tee -a " + first + " " + second, both},
		{"ordinary file between", "printf x >> " + first + "; printf x >> " + ordinary + "; printf y >> " + second, both},
		{"same alias twice", "printf x >> " + first + "; printf x >> " + first, []string{claude}},
		{"ordinary files only", "printf x >> " + ordinary, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets := instructionResolve(t, project, "Bash", map[string]any{"command": tc.command})
			got := InstructionIdentities(targets)
			slices.Sort(got)
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("identities = %q, want %q (targets %v)", got, want, targets)
			}
		})
	}
}

// GAP-1064: the hook client reads, as the user, the identity of a loaded
// instruction file and of every write target. A gateway behind ProtectHome
// matches the two, so a write to the file a loaded SOUL.md symlink reaches,
// under any name, is a write to SOUL.md.
func TestResolveReportsLoadedAndTargetIdentities(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows gateway checks file identity itself")
	}
	root := instructionIdentityRoot(t)
	project := filepath.Join(root, "project")
	persona := instructionIdentityFile(t, filepath.Join(root, "persona-src"), "soul.txt")
	neighbor := instructionIdentityFile(t, filepath.Join(root, "persona-src"), "other.txt")
	soul := instructionIdentitySymlink(t, persona, filepath.Join(root, "persona", "SOUL.md"))
	hard := instructionIdentityLink(t, persona, filepath.Join(root, "tmp", "hard.txt"))
	via := instructionIdentitySymlink(t, persona, filepath.Join(root, "tmp", "via.txt"))
	want := FileIdentity(persona)
	if want == "" || FileIdentity(soul) != want || FileIdentity(hard) != want {
		t.Fatalf("file identities: persona %q, SOUL.md %q, hard link %q", want, FileIdentity(soul), FileIdentity(hard))
	}
	load := func(path string) string {
		body, err := json.Marshal(map[string]any{
			"hook_event_name": "InstructionsLoaded", "session_id": "s", "cwd": project, "file_path": path,
		})
		if err != nil {
			t.Fatal(err)
		}
		return Resolve(body)
	}
	evidence, ok := Decode(load(soul))
	if !ok || evidence[LoadedIdentityPrefix+soul] != want || len(evidence) != 1 {
		t.Fatalf("InstructionsLoaded evidence = %v (ok %t), want %s -> %s", evidence, ok, soul, want)
	}
	for name, path := range map[string]string{
		"not an instruction name": persona,
		"missing file":            filepath.Join(root, "persona", "AGENTS.md"),
		"relative":                "SOUL.md",
	} {
		if got := load(path); got != "" {
			t.Errorf("InstructionsLoaded of a %s sent evidence %q", name, got)
		}
	}
	for _, tc := range []struct {
		name, tool string
		input      map[string]any
		want       bool
	}{
		{"native write", "Write", map[string]any{"file_path": persona, "content": "x"}, true},
		{"native edit", "Edit", map[string]any{"file_path": persona, "old_string": "instructions", "new_string": "x"}, true},
		{"shell append", "Bash", map[string]any{"command": "printf x >> " + persona}, true},
		{"hard link", "Write", map[string]any{"file_path": hard, "content": "x"}, true},
		{"through a symlink", "Bash", map[string]any{"command": "printf x >> " + via}, true},
		{"tee with a neighbor", "Bash", map[string]any{"command": "echo x | tee " + neighbor + " " + hard}, true},
		{"neighbor", "Write", map[string]any{"file_path": neighbor, "content": "x"}, false},
		{"new file", "Write", map[string]any{"file_path": filepath.Join(root, "tmp", "new.txt"), "content": "x"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets := instructionResolve(t, project, tc.tool, tc.input)
			if got := slices.Contains(FileIdentities(targets), want); got != tc.want {
				t.Fatalf("write-target identities %q contain the loaded file's %q: %t, want %t", FileIdentities(targets), want, got, tc.want)
			}
		})
	}
}

func TestDecodeClientIdentityFacts(t *testing.T) {
	encode := func(facts map[string]string) string {
		data, _ := json.Marshal(facts)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	posix := runtime.GOOS != "windows"
	for _, tc := range []struct {
		name  string
		facts map[string]string
		ok    bool
	}{
		{"two aliases", map[string]string{InstructionIdentityKey: "/repo/CLAUDE.md\x00/repo/SOUL.md"}, posix},
		{"relative alias", map[string]string{InstructionIdentityKey: "/repo/CLAUDE.md\x00SOUL.md"}, false},
		{"empty alias", map[string]string{InstructionIdentityKey: "/repo/CLAUDE.md\x00"}, false},
		{"target identities", map[string]string{FileIdentitiesKey: "fd01:2a,3:4"}, true},
		{"empty target identity", map[string]string{FileIdentitiesKey: "fd01:2a,"}, false},
		{"bad target identity", map[string]string{FileIdentitiesKey: "/etc/passwd"}, false},
		{"long target identity", map[string]string{FileIdentitiesKey: strings.Repeat("a", maxFileIdentityBytes+1)}, false},
		{"loaded identity", map[string]string{LoadedIdentityPrefix + "/repo/SOUL.md": "fd01:2a"}, posix},
		{"loaded relative", map[string]string{LoadedIdentityPrefix + "SOUL.md": "fd01:2a"}, false},
		{"loaded bad identity", map[string]string{LoadedIdentityPrefix + "/repo/SOUL.md": "x"}, false},
	} {
		if _, ok := Decode(encode(tc.facts)); ok != tc.ok {
			t.Errorf("%s: Decode ok=%t, want %t", tc.name, ok, tc.ok)
		}
	}
	rest, _ := SplitOpaqueScopeFacts(map[string]string{
		CWDKey: "/repo", "/repo/a": "/repo/a", FileIdentitiesKey: "1:2", LoadedIdentityPrefix + "/repo/SOUL.md": "1:2",
	})
	if len(rest) != 2 || rest["/repo/a"] != "/repo/a" {
		t.Fatalf("the authorized-keys proof must see only operands, got %v", rest)
	}
}

// An instruction-named file is protected only where agents load it from:
// a hard link of that name elsewhere to one of the call's instruction files
// is that file (Alias reports it), while the same name in a fixture
// directory is an ordinary file. Located finds a load location's directory
// through a symlinked spelling of it.
func TestInstructionAliasAndLocationOfInstructionNames(t *testing.T) {
	root := instructionIdentityRoot(t)
	project := filepath.Join(root, "project")
	home := filepath.Join(root, "home")
	instruction := instructionIdentityFile(t, project, "CLAUDE.md")
	fixture := instructionIdentityFile(t, filepath.Join(root, "fixtures"), "SOUL.md")
	named := instructionIdentityLink(t, instruction, filepath.Join(root, "linked", "CLAUDE.md"))
	workdir := instructionIdentitySymlink(t, project, filepath.Join(root, "workdir"))
	files := NewInstructionFiles(workdir, home, nil)
	if got := files.Alias(named); !sameInstructionPath(got, filepath.Join(workdir, "CLAUDE.md")) {
		t.Fatalf("Alias(%q) = %q, want the project's CLAUDE.md", named, got)
	}
	if got := NewInstructionFiles(project, home, nil).Alias(instruction); got != "" {
		t.Fatalf("Alias of the instruction file itself = %q, want none", got)
	}
	if got := files.Alias(fixture); got != "" {
		t.Fatalf("Alias(%q) = %q, want an ordinary file", fixture, got)
	}
	for _, tc := range []struct {
		name, path string
		loaded     []string
		want       bool
	}{
		{"working directory through its symlink", instruction, nil, true},
		{"new file in that directory", filepath.Join(project, "AGENTS.md"), nil, true},
		{"fixture directory", fixture, nil, false},
		{"fixture directory, loaded", fixture, []string{fixture}, true},
		{"ordinary name", filepath.Join(project, "notes.md"), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := NewInstructionFiles(workdir, home, tc.loaded).Located(tc.path); (got != "") != tc.want {
				t.Fatalf("Located(%q) = %q, want located=%t", tc.path, got, tc.want)
			}
		})
	}
}
