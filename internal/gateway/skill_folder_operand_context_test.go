// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type operandContextFixture struct {
	api              *APIServer
	ctx              context.Context
	home, held, proj string
}

func newOperandContextFixture(t *testing.T, denied string) operandContextFixture {
	t.Helper()
	store, logger := newNativeSkillRuntimeTestStore(t)
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := operandContextFixture{
		home: home,
		held: filepath.Join(home, ".claude", "skills", "held"),
		proj: filepath.Join(home, "proj"),
	}
	for _, dir := range []string{f.held, f.proj} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.held, "SKILL.md"), []byte("---\nname: held\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"notes.txt", "needle notes.txt"} {
		if err := os.WriteFile(filepath.Join(f.proj, name), []byte("ordinary"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: denied}}
	f.api = &APIServer{store: store, logger: logger, scannerCfg: cfg}
	f.ctx = withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "fixture", Home: home})
	return f
}

// inStrictTier selects the strict policy tier for the connector.
func (f operandContextFixture) inStrictTier(t *testing.T) {
	t.Helper()
	cfg := f.api.scannerCfg
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
}

func (f operandContextFixture) blocks(tool, cwd string, input map[string]interface{}) bool {
	d, matched := f.api.claudeCodeSkillAssetDecision(f.ctx, claudeCodeHookRequest{
		HookEventName: "PreToolUse", ToolName: tool, CWD: cwd, ToolInput: input,
	})
	return matched && d.Action == "block"
}

// A command name, a word of a program that does not read files and a text
// field that equal the name of a link in the working folder are not a read of
// that link; the same word as an operand of a program that reads files is.
func TestOrdinaryWordEqualToALinkNameIsNotBlocked(t *testing.T) {
	f := newOperandContextFixture(t, "held")
	for _, name := range []string{"echo", "needle"} {
		if err := os.Symlink(f.held, filepath.Join(f.proj, name)); err != nil {
			t.Skipf("link unavailable: %v", err)
		}
	}
	for name, c := range map[string]struct {
		tool  string
		input map[string]interface{}
	}{
		"echo":              {"Bash", map[string]interface{}{"command": "echo hello"}},
		"echo then runner":  {"Bash", map[string]interface{}{"command": "echo needle && sh -c true"}},
		"sudo option value": {"Bash", map[string]interface{}{"command": "sudo -u root echo hello"}},
		"git word":          {"Bash", map[string]interface{}{"command": "git log needle"}},
		"Grep pattern":      {"Grep", map[string]interface{}{"path": "notes.txt", "pattern": "needle"}},
		"typed Read":        {"Read", map[string]interface{}{"file_path": "needle notes.txt"}},
		"typed Grep path":   {"Grep", map[string]interface{}{"path": "needle notes.txt", "pattern": "ordinary"}},
		"Glob exact name":   {"Glob", map[string]interface{}{"pattern": "needle notes.txt"}},
	} {
		if f.blocks(c.tool, f.proj, c.input) {
			t.Errorf("%s: ordinary call blocked because the working folder has a link with that word as its name", name)
		}
	}
	for name, c := range map[string]struct {
		tool  string
		input map[string]interface{}
	}{
		"Read":          {"Read", map[string]interface{}{"file_path": "echo"}},
		"cat operand":   {"Bash", map[string]interface{}{"command": "cat needle"}},
		"slash":         {"Bash", map[string]interface{}{"command": "cat echo/SKILL.md"}},
		"Grep path":     {"Grep", map[string]interface{}{"path": "needle", "pattern": "x"}},
		"grep operand":  {"Bash", map[string]interface{}{"command": "grep needle notes.txt"}},
		"through xargs": {"Bash", map[string]interface{}{"command": "echo needle | xargs cat"}},
		"behind sudo":   {"Bash", map[string]interface{}{"command": "sudo -u root cat needle"}},
		"shell script":  {"Bash", map[string]interface{}{"command": "sh -c 'cat needle'"}},
	} {
		if !f.blocks(c.tool, f.proj, c.input) {
			t.Errorf("%s: read of a denied skill folder through a link allowed", name)
		}
	}
}

// A search that names no place looks through the working folder; one whose
// working folder is a denied skill folder, or a link to it, is refused.
func TestSearchFromADeniedSkillFolderIsBlocked(t *testing.T) {
	f := newOperandContextFixture(t, "held")
	link := filepath.Join(f.proj, "lnk-held")
	if err := os.Symlink(f.held, link); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	for name, c := range map[string]struct {
		tool, cwd string
		input     map[string]interface{}
		want      bool
	}{
		"Glob in the folder": {"Glob", f.held, map[string]interface{}{"pattern": "*"}, true},
		"Glob in the link":   {"Glob", link, map[string]interface{}{"pattern": "*"}, true},
		"Grep in the folder": {"Grep", f.held, map[string]interface{}{"pattern": "x"}, true},
		"explicit path":      {"Glob", f.proj, map[string]interface{}{"pattern": "*", "path": "lnk-held"}, true},
		"ls in the folder":   {"Bash", f.held, map[string]interface{}{"command": "ls"}, true},
		"Glob elsewhere":     {"Glob", f.proj, map[string]interface{}{"pattern": "*"}, false},
		"ls elsewhere":       {"Bash", f.proj, map[string]interface{}{"command": "ls"}, false},
	} {
		if got := f.blocks(c.tool, c.cwd, c.input); got != c.want {
			t.Errorf("%s: blocked = %t, want %t", name, got, c.want)
		}
	}
}

// The folder name a Read names is judged whole, with the spaces and tabs it
// holds, directly and through a link to it.
func TestReadOfADeniedFolderWithWhitespaceInItsNameIsBlocked(t *testing.T) {
	f := newOperandContextFixture(t, "listed-name")
	root := filepath.Join(f.home, ".claude", "skills")
	for i, row := range []struct{ name, folder string }{
		{"two spaces", "  "}, {"tab", "folder\tname"}, {"middle space", "folder name"},
	} {
		dir := filepath.Join(root, row.folder)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Skipf("folder unavailable: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: listed-name\n---\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(f.proj, "lnk "+row.name+string(rune(0x61+i)))
		if err := os.Symlink(dir, link); err != nil {
			t.Skipf("link unavailable: %v", err)
		}
		for what, path := range map[string]string{"direct": filepath.Join(dir, "SKILL.md"), "link": filepath.Join(link, "SKILL.md")} {
			if !f.blocks("Read", f.proj, map[string]interface{}{"file_path": path}) {
				t.Errorf("%s, %s: read of a denied declared-name folder allowed", row.name, what)
			}
		}
	}
	if f.blocks("Read", f.proj, map[string]interface{}{"file_path": filepath.Join(f.proj, "my notes", "a b.txt")}) {
		t.Error("ordinary path with spaces blocked")
	}
}

// A program that reads files reads the file an option names: a link to a
// denied skill given as the file of grep -f, rg -f, sed -f or awk -f is the
// skill, as it is for cat.
func TestFileTakingOptionOfASearchReadsTheLinkedSkill(t *testing.T) {
	f := newOperandContextFixture(t, "held")
	if err := os.Symlink(filepath.Join(f.held, "SKILL.md"), filepath.Join(f.proj, "rules")); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	for _, command := range []string{
		"cat rules", "grep -f rules notes.txt", "grep --file rules notes.txt", "grep --file=rules notes.txt",
		"grep --exclude-from rules notes.txt", "rg -f rules notes.txt", "rg --ignore-file rules notes.txt",
		"sed -f rules notes.txt", "awk -f rules notes.txt", "sudo -u root sed -f rules notes.txt",
	} {
		if !f.blocks("Bash", f.proj, map[string]interface{}{"command": command}) {
			t.Errorf("%q: read of a denied skill through a link allowed", command)
		}
	}
	for _, command := range []string{"echo rules", "printf rules", "git log rules", "grep -f notes.txt notes.txt", "sudo -u root echo rules"} {
		if f.blocks("Bash", f.proj, map[string]interface{}{"command": command}) {
			t.Errorf("%q: ordinary call blocked", command)
		}
	}
}

// The strict tier reads the slash-free word of any program that names an
// existing entry; the balanced tier allows the same ordinary command.
func TestStrictTierBlocksAWordThatNamesALinkToADeniedSkill(t *testing.T) {
	commands := []string{"echo needle", "git log needle", "sudo -u root echo needle"}
	for _, strict := range []bool{false, true} {
		f := newOperandContextFixture(t, "held")
		if err := os.Symlink(f.held, filepath.Join(f.proj, "needle")); err != nil {
			t.Skipf("link unavailable: %v", err)
		}
		if strict {
			f.inStrictTier(t)
		}
		for _, command := range commands {
			if got := f.blocks("Bash", f.proj, map[string]interface{}{"command": command}); got != strict {
				t.Errorf("strict=%t %q: blocked = %t, want %t", strict, command, got, strict)
			}
		}
		if f.blocks("Bash", f.proj, map[string]interface{}{"command": "echo hello"}) {
			t.Errorf("strict=%t: a word that names no entry was blocked", strict)
		}
		if f.blocks("Read", f.proj, map[string]interface{}{"file_path": "needle notes.txt"}) {
			t.Errorf("strict=%t: a typed path with a blank was blocked", strict)
		}
	}
}
