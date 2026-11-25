//go:build linux

package kit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentpaths"
)

// GAP-1074: quarantineSkillFolder accepted only roots named skills, but the
// connector table also lists the singular OpenCode roots (.opencode/skill,
// ~/.config/opencode/skill, Config/skill). A refused folder there stayed in
// reach and every later PreToolUse of the actor was refused. Scan and
// quarantine now read the same table.
//
// The test walks every skill root of the table (plus a plugin skills folder
// of every plugins entry): the flagged folder is moved to
// <root>/../.defenseclaw-quarantine, the clean one stays, and nothing is
// left in reach (the hook refuses the actor's next call while any is).
func TestGAP1074EveryTableSkillRootQuarantinesTheFlaggedFolder(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	for _, env := range []string{"CODEX_HOME", "HERMES_HOME", "OPENCODE_CONFIG_DIR", "CLAUDE_CONFIG_DIR"} {
		t.Setenv(env, t.TempDir())
	}
	var roots []string
	seen := map[string]bool{}
	for _, e := range agentpaths.ActorEntries() {
		if e.Base == agentpaths.Abs || e.Kind == agentpaths.Commands {
			continue
		}
		for _, dir := range actorDirs(e, home, repo) {
			if e.Kind == agentpaths.Plugins {
				dir = filepath.Join(dir, "p", "skills")
			}
			if !seen[dir] {
				seen[dir] = true
				roots = append(roots, dir)
			}
		}
	}
	if len(roots) < 20 {
		t.Fatalf("only %d roots in the table", len(roots))
	}
	for _, root := range roots {
		writeSkill(t, root, "bad", "x")
		writeSkill(t, root, "good", "y")
	}
	listed := map[string]string{}
	for _, f := range scanSkillFolders(skillRoots(home, repo)) {
		listed[f.Path] = f.FP
	}
	var ans skillAnswer
	for _, root := range roots {
		bad := filepath.Join(root, "bad")
		if _, ok := listed[bad]; !ok {
			t.Fatalf("scan did not list %s", bad)
		}
		ans.Quarantine = append(ans.Quarantine, struct {
			Path   string `json:"path"`
			Reason string `json:"reason"`
		}{Path: bad, Reason: "test"})
	}
	body, _ := json.Marshal(map[string]any{"substrate_quarantine": ans.Quarantine})
	moved := applySkillAnswer(home, body, listed, nil, time.Now())
	if len(moved) != len(roots) {
		t.Errorf("moved %d of %d flagged folders", len(moved), len(roots))
	}
	for _, root := range roots {
		if _, err := os.Stat(filepath.Join(root, "bad")); err == nil {
			t.Errorf("flagged folder still in reach: %s", root)
		}
		if _, err := os.Stat(filepath.Join(root, "good", "SKILL.md")); err != nil {
			t.Errorf("clean folder disturbed: %s", root)
		}
		if ents, _ := os.ReadDir(filepath.Join(filepath.Dir(root), quarantineDirName)); len(ents) == 0 {
			t.Errorf("nothing in the quarantine folder beside %s", root)
		}
	}
	if stuck := skillsStillInReach(body, listed); len(stuck) != 0 {
		t.Errorf("the actor would be refused on the next call: %v", stuck)
	}
}
