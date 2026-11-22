// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-0574: in git mode a directory link at a path git ignores
// (.kiro/settings, .kiro, out/.kiro/settings) was not recorded at all, so a
// link that makes .kiro/settings/mcp.json appear got no flag and the review
// was not sensitive. The sentinel walk now records such links with their
// target and the review classifies them as it does tracked links.
func TestGAP0574IgnoredDirectoryLinkIsFlaggedInGitMode(t *testing.T) {
	mcp := `{"mcpServers":{"x":{"command":"sh","args":["-c","id"]}}}`
	hook := `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"id"}]}]}}`
	for _, c := range []struct {
		name, gi string
		files    map[string]string
		links    [][2]string
		want     string // the label that must get a high flag; "" none
	}{
		{name: "H01 ignored .kiro/settings -> ../kc", gi: ".kiro/settings\n", files: map[string]string{".kiro/steering/x.md": "x\n", "kc/mcp.json": mcp}, links: [][2]string{{".kiro/settings", "../kc"}}, want: ".kiro/settings"},
		{name: "H03 ignored .kiro -> k", gi: ".kiro\n", files: map[string]string{"k/settings/mcp.json": mcp}, links: [][2]string{{".kiro", "k"}}, want: ".kiro"},
		{name: "H05 ignored out/, out/.kiro/settings -> ../kc", gi: "out/\n", files: map[string]string{"out/.kiro/steering/x.md": "x\n", "out/kc/mcp.json": mcp}, links: [][2]string{{"out/.kiro/settings", "../kc"}}, want: "out/.kiro/settings"},
		{name: "U+017F fold, ignored .kiro/ſettings -> ../kc", gi: ".kiro/\n", files: map[string]string{"kc/mcp.json": mcp}, links: [][2]string{{".kiro/ſettings", "../kc"}}, want: ".kiro/ſettings"},
		{name: "H02 control: ignored file link .claude/settings.json", gi: ".claude/\n", files: map[string]string{"cfg.json": hook, ".claude/commands/x.md": "x\n"}, links: [][2]string{{".claude/settings.json", "../cfg.json"}}, want: ".claude/settings.json"},
		{name: "control: an ignored plain link lib -> src", gi: "lib\n", files: map[string]string{"src/a.txt": "x\n"}, links: [][2]string{{"lib", "src"}}, want: ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.initRepo()
			writeFile(t, e.project, ".gitignore", c.gi)
			e.commit("ignore")
			writeFile(t, e.project, "keep/keep.txt", "x\n")
			mustSnapshot(t, e, "s1")
			for p, b := range c.files {
				writeFile(t, e.project, p, b)
			}
			for _, l := range c.links {
				p := filepath.Join(e.project, filepath.FromSlash(l[0]))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(l[1], p); err != nil {
					t.Fatal(err)
				}
			}
			rep, err := Review(bg, ReviewOptions{DataDir: e.data, Name: "s1", Scanners: []ContentScanner{},
				SensitiveGlobs: []string{"**/.claude/**", "CLAUDE.local.md", "opencode.json", ".mcp.json"}})
			if err != nil {
				t.Fatal(err)
			}
			high := map[string]bool{}
			for _, f := range rep.Flags {
				if f.Severity.rank() >= SeverityHigh.rank() {
					high[f.Label] = true
				}
			}
			if c.want == "" {
				if len(high) > 0 {
					t.Errorf("high flags %v for a link no rule reaches", high)
				}
				return
			}
			if !high[c.want] {
				t.Errorf("no high flag on %s (flags %+v, sensitive %v)", c.want, rep.Flags, rep.Sensitive())
			}
		})
	}
}

// An ignored rule link that was there at the snapshot and did not change
// is not flagged again.
func TestGAP0574UnchangedIgnoredLinkIsNotFlagged(t *testing.T) {
	e := newEnv(t)
	e.initRepo()
	writeFile(t, e.project, ".gitignore", ".kiro/settings\n")
	writeFile(t, e.project, "kc/mcp.json", "{}\n")
	e.commit("ignore")
	if err := os.MkdirAll(filepath.Join(e.project, ".kiro"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../kc", filepath.Join(e.project, ".kiro", "settings")); err != nil {
		t.Fatal(err)
	}
	mustSnapshot(t, e, "s1")
	writeFile(t, e.project, "keep/keep.txt", "x\n")
	rep, err := Review(bg, ReviewOptions{DataDir: e.data, Name: "s1", Scanners: []ContentScanner{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Flags {
		if f.Label == ".kiro/settings" {
			t.Errorf("unchanged link flagged: %+v", f)
		}
	}
}
