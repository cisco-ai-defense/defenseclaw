// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
)

// GAP-0701: Copilot CLI reports a skill use as a skill tool call whose
// arguments arrive as a string. The hook reads the folder of that skill, as
// the user, so a gateway that reads nothing in the profile can judge a skill
// created while it was stopped on its first use after the restart.
func TestHookAssetFactsCopilotSkillCarriesItsText(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{"HOME", "USERPROFILE"} {
		t.Setenv(name, home)
	}
	saved := hookAgentCommandLine
	t.Cleanup(func() { hookAgentCommandLine = saved })
	hookAgentCommandLine = func() ([]string, string, error) { return nil, "", agentprocess.ErrNoAgent }
	stubHookAgentWorkingDirectory(t, "")
	write := func(path, text string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, ".copilot", "skills", "np10-crit-cp", "SKILL.md"), "# np10\ncopilot skill text\n")
	project := t.TempDir()
	write(filepath.Join(project, ".github", "skills", "proj-skill", "SKILL.md"), "# proj\nproject skill text\n")
	payload := func(tool string, args any, asString bool) []byte {
		t.Helper()
		raw, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		var field any = json.RawMessage(raw)
		if asString {
			field = string(raw)
		}
		out, err := json.Marshal(map[string]any{"toolName": tool, "toolArgs": field, "cwd": project})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, asString := range []bool{true, false} {
		facts, ok := assetfacts.Decode(hookAssetFacts("copilot", payload("skill", map[string]string{"skill": "np10-crit-cp"}, asString)))
		contents := facts.ContentsFor(assetfacts.ContentSkill, "np10-crit-cp")
		if !ok || len(facts.SkillDirs) != 1 || len(contents) != 1 || len(contents[0].Files) != 1 || contents[0].Files[0].Text != "# np10\ncopilot skill text\n" {
			t.Fatalf("copilot skill facts (args as string=%v) = %+v ok=%v, want the SKILL.md text", asString, facts, ok)
		}
	}
	facts, _ := assetfacts.Decode(hookAssetFacts("copilot", payload("skill", map[string]string{"skill": "proj-skill"}, true)))
	if c := facts.ContentsFor(assetfacts.ContentSkill, "proj-skill"); len(c) != 1 {
		t.Fatalf("project skill facts = %+v, want the project skill text", facts)
	}
	// Twins that read nothing: an ordinary tool, a skill that does not exist,
	// and no MCP lookup for Copilot.
	for _, raw := range [][]byte{
		payload("bash", map[string]string{"command": "ls"}, true),
		payload("skill", map[string]string{"skill": "missing"}, true),
		payload("mcp__notes__count_words", map[string]string{}, true),
	} {
		if got, _ := assetfacts.Decode(hookAssetFacts("copilot", raw)); len(got.Contents) != 0 || got.MCP != nil {
			t.Fatalf("facts for %s = %+v, want nothing read", raw, got)
		}
	}
}
