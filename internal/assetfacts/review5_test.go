// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0686 review 5: the pins are what a claim keeps when its definition does
// not fit; they survive another pass of the codec, and a claim without a
// definition or pins keeps none (so a gateway cannot rule a rule out on it).
func TestMCPPinsSurviveTheBoundsAndAnotherPass(t *testing.T) {
	long := "https://example.invalid/mcp?value=" + strings.Repeat("a", 1100)
	digest := strings.Repeat("ab", 32)
	facts, ok := Decode(Encode(Facts{MCP: &MCPServer{Name: "notes", URL: long, ProjectScope: true, Digest: digest}}))
	if !ok || facts.MCP == nil || facts.MCP.URL != "" || facts.MCP.Pins == nil || facts.MCP.Pins.URL != PinSum(long) {
		t.Fatalf("long URL claim = %+v, want the pins of the URL and not the URL", facts.MCP)
	}
	again, _ := Decode(Encode(facts))
	if again.MCP == nil || again.MCP.Pins == nil || again.MCP.Pins.URL != PinSum(long) {
		t.Fatalf("second pass lost the pins: %+v", again.MCP)
	}
	args := make([]string, 40)
	for i := range args {
		args[i] = "a" + strings.Repeat("b", i)
	}
	facts, _ = Decode(Encode(Facts{MCP: &MCPServer{Name: "notes", Command: `C:\tools\node.exe`, Args: args, Relocated: true, Digest: digest}}))
	pins := facts.MCP.Pins
	if pins == nil || pins.ArgCount != 40 || len(pins.Args) != 40 || pins.Args[1] != PinArgSum(args[1]) {
		t.Fatalf("40 arguments claim = %+v, want 40 argument pins and the count", pins)
	}
	bare, _ := Decode(Encode(Facts{MCP: &MCPServer{Name: "notes", ProjectScope: true, Digest: digest}}))
	if bare.MCP == nil || bare.MCP.Pins != nil {
		t.Fatalf("claim without a definition or pins = %+v, want no pins", bare.MCP)
	}
	forged, _ := Decode(Encode(Facts{MCP: &MCPServer{Name: "notes", ProjectScope: true, Digest: digest, Pins: &MCPPins{URL: "not-a-digest", ArgCount: -3}}}))
	if forged.MCP == nil || forged.MCP.Pins == nil || forged.MCP.Pins.URL != "" || forged.MCP.Pins.ArgCount != 0 {
		t.Fatalf("pins that are not digests were kept: %+v", forged.MCP)
	}
}

// GAP-0699, GAP-0701 review 5: a content is never dropped for not fitting. A
// folder path past the bound loses the path and keeps the text; an asset past
// the count bound keeps a truncated content with no text, once per name.
func TestContentIsNeverDroppedForNotFitting(t *testing.T) {
	long := filepath.Join(t.TempDir(), strings.Repeat("a", 1100), "deep")
	facts, _ := Decode(Encode(Facts{Contents: []Content{{
		Kind: ContentSkill, Name: "deep", Dir: long, Files: []ContentFile{{Rel: "SKILL.md", Text: "# deep\n"}},
	}}}))
	got := facts.ContentsFor(ContentSkill, "deep")
	if len(got) != 1 || got[0].Dir != "" || len(got[0].Files) != 1 || got[0].Truncated {
		t.Fatalf("long-path skill = %+v, want its text kept and no path", got)
	}
	var many []Content
	for _, name := range []string{"a", "b", "c", "d", "d", "e"} {
		many = append(many, Content{Kind: ContentPlugin, Name: name, Dir: filepath.Join(t.TempDir(), name), Files: []ContentFile{{Rel: "plugin.json", Text: "{}"}}})
	}
	facts, _ = Decode(Encode(Facts{Contents: many}))
	for name, want := range map[string]bool{"a": false, "b": false, "c": false, "d": true, "e": true} {
		got := facts.ContentsFor(ContentPlugin, name)
		if len(got) != 1 || got[0].Truncated != want || (want && len(got[0].Files) != 0) {
			t.Errorf("plugin %q past the count bound = %+v, want one content, truncated=%v", name, got, want)
		}
	}
}

// GAP-0701 review 5: Copilot takes skills from .agents/skills and from the
// folders its environment names; a tool call selects a skill under every
// spelling the gateway recognises.
func TestCopilotSkillRootsAndSkillNameSpellings(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	cwd := filepath.Join(t.TempDir(), "work")
	// The working folder is the repository root, so a relative root is below it only.
	if err := os.MkdirAll(filepath.Join(cwd, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	custom := filepath.Join(t.TempDir(), "skills")
	t.Setenv("COPILOT_SKILLS_DIRS", custom+", ~/shared , rel/skills,"+custom)
	t.Setenv("COPILOT_HOME", filepath.Join(t.TempDir(), "copilot-home"))
	roots := SkillRoots("copilot", home, cwd)
	if !containsRoot(roots, filepath.Join(home, ".agents", "skills")) || !containsRoot(roots, filepath.Join(cwd, ".agents", "skills")) {
		t.Errorf("copilot skill roots = %v, want the user and project .agents/skills", roots)
	}
	env := EnvSkillRoots("copilot", home, cwd)
	for _, want := range []string{filepath.Join(os.Getenv("COPILOT_HOME"), "skills"), custom, filepath.Join(home, "shared"), filepath.Join(cwd, "rel", "skills")} {
		if !containsRoot(env, want) {
			t.Errorf("environment skill roots = %v, missing %s", env, want)
		}
	}
	if len(env) != 4 || EnvSkillRoots("claudecode", home, cwd) != nil {
		t.Errorf("environment skill roots = %v (claudecode %v), want 4 for copilot and none for others", env, EnvSkillRoots("claudecode", home, cwd))
	}
	for name, input := range map[string]map[string]any{
		"skill":              {"skill": "direct"},
		"skill_name":         {"skill_name": "direct"},
		"skillName":          {"skillName": "direct"},
		"skill_key":          {"skill_key": "direct"},
		"nested object":      {"skill": map[string]any{"name": "direct"}},
		"skill_info":         {"skill_info": map[string]any{"id": "direct"}},
		"path of SKILL.md":   {"skill_path": filepath.Join("x", "skills", "direct", "SKILL.md")},
		"quoted and at-sign": {"skill": `"@direct"`},
	} {
		if got := SkillNameFromInput(input); got != "direct" {
			t.Errorf("%s: skill = %q, want direct", name, got)
		}
	}
	if got := SkillNameFromInput(map[string]any{"command": "ls", "name": "direct"}); got != "" {
		t.Errorf("a tool call that selects no skill = %q", got)
	}
}

func containsRoot(roots []string, want string) bool {
	for _, root := range roots {
		if root == filepath.Clean(want) {
			return true
		}
	}
	return false
}
