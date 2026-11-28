//go:build linux

package kit

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-0788: the kit looked only at .claude, .codex and .agents skill roots,
// so a skill copied into a Cursor, Copilot, Devin, Amp, Antigravity, OpenCode
// or Hermes folder in an actor was never attached or scanned. The roots now
// come from the one connector table the laptop uses.
func TestGAP0788ActorSkillRootsFollowTheConnectorTable(t *testing.T) {
	home, repo, codexHome := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)
	mk := func(dir string) string {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: x\n---\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	want := []string{
		mk(filepath.Join(home, ".claude", "skills", "a")),
		mk(filepath.Join(home, ".cursor", "skills", "b")),
		mk(filepath.Join(home, ".copilot", "skills", "c")),
		mk(filepath.Join(home, ".gemini", "config", "skills", "d")),
		mk(filepath.Join(home, ".hermes", "skills", "e")),
		mk(filepath.Join(home, ".config", "opencode", "skill", "f")),
		mk(filepath.Join(home, ".config", "devin", "skills", "g")),
		mk(filepath.Join(home, ".config", "amp", "plugins", "p", "skills", "h")),
		mk(filepath.Join(codexHome, "skills", "i")),
		mk(filepath.Join(repo, ".github", "skills", "j")),
		mk(filepath.Join(repo, ".devin", "skills", "k")),
		mk(filepath.Join(repo, ".agent", "skills", "l")),
		mk(filepath.Join(repo, ".opencode", "skills", "m")),
		mk(filepath.Join(repo, ".claude", "plugins", "p", "skills", "n")),
	}
	// A command folder holds single files; its subfolders are not skills.
	notWant := mk(filepath.Join(home, ".claude", "commands", "group"))

	listed := map[string]bool{}
	for _, f := range scanSkillFolders(skillRoots(home, repo)) {
		listed[f.Path] = true
	}
	for _, w := range want {
		if !listed[w] {
			t.Errorf("skill folder not listed: %s", w)
		}
	}
	if listed[notWant] {
		t.Errorf("command folder listed as a skill: %s", notWant)
	}
}
