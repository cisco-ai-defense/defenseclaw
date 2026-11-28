package attest

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0788: the gateway's two skill-path regexes were hand lists of
// .claude, .codex and .agents, so a skill written, read or created by a
// command in a Cursor, Copilot, Devin, Antigravity, OpenCode or Hermes
// folder was not seen as a skill. They are built from the connector table
// now; the 1.0.10 forms still match.
func TestGAP0788HookRegexesFromRootTable(t *testing.T) {
	skillNames := func(as []RuntimeAsset) map[string]bool {
		out := map[string]bool{}
		for _, a := range as {
			if a.Kind == config.AdmissionTypeSkill {
				out[a.Name] = true
			}
		}
		return out
	}
	writes := map[string]string{
		"/home/u/.claude/skills/p1/SKILL.md":                       "p1",
		"/home/u/.config/foo/skills/p2/SKILL.md":                   "p2",
		"/home/u/.codex/plugins/cache/m/p/skills/p3/SKILL.md":      "p3",
		"/home/u/.claude/plugins/cache/m/p/1.0/skills/p4/SKILL.md": "p4",
		"/home/u/.cursor/skills/n1/SKILL.md":                       "n1",
		"/work/.github/skills/n2/SKILL.md":                         "n2",
		"/work/.devin/skills/n3/SKILL.md":                          "n3",
		"/home/u/.gemini/config/skills/n4/SKILL.md":                "n4",
		"/home/u/.hermes/skills/n5/SKILL.md":                       "n5",
		"/work/.opencode/skill/n6/SKILL.md":                        "n6",
		"/work/.agent/skills/n7/SKILL.md":                          "n7",
		"/home/u/.copilot/skills/n8/SKILL.md":                      "n8",
		"/home/u/.gemini/antigravity-cli/plugins/p/skills/n9/x.sh": "n9",
	}
	for target, name := range writes {
		ev := gap0185Event(t, "Write", "/work", map[string]any{"file_path": target, "content": "hi"})
		if !skillNames(HookAssets(ev, nil))[name] {
			t.Errorf("Write %s: no skill asset %q", target, name)
		}
	}
	for cmd, name := range map[string]string{
		"mkdir -p /home/u/.claude/skills/c1 && echo hi > /home/u/.claude/skills/c1/SKILL.md": "c1",
		"cat > .cursor/skills/c2/SKILL.md <<EOF\nhi\nEOF":                                    "c2",
		"cp -r /tmp/x .github/skills/c3":                                                     "c3",
		"tee /home/u/.copilot/skills/c4/SKILL.md":                                            "c4",
	} {
		ev := gap0185Event(t, "Bash", "/work", map[string]any{"command": cmd})
		if !skillNames(HookAssets(ev, nil))[name] {
			t.Errorf("Bash %q: no skill asset %q", cmd, name)
		}
	}
	// A command file is not a skill folder.
	ev := gap0185Event(t, "Write", "/work", map[string]any{"file_path": "/work/README.md", "content": "hi"})
	if n := len(skillNames(HookAssets(ev, nil))); n != 0 {
		t.Errorf("README write gave %d skill assets", n)
	}
}
