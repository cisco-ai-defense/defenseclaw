// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
// the size budget keeps a truncated content with no text, once per name.
func TestContentIsNeverDroppedForNotFitting(t *testing.T) {
	long := filepath.Join(t.TempDir(), strings.Repeat("a", 1100), "deep")
	facts, _ := Decode(Encode(Facts{Contents: []Content{{
		Kind: ContentSkill, Name: "deep", Dir: long, Files: []ContentFile{{Rel: "SKILL.md", Text: "# deep\n"}},
	}}}))
	got := facts.ContentsFor(ContentSkill, "deep")
	if len(got) != 1 || got[0].Dir != "" || len(got[0].Files) != 1 || got[0].Truncated {
		t.Fatalf("long-path skill = %+v, want its text kept and no path", got)
	}
	// Names and folders this long exhaust the size budget after a few
	// hundred contents: each keeps its text while the budget lasts, and one
	// past it is a truncated content with no text, once per name.
	dir := filepath.Join(t.TempDir(), strings.Repeat("a", 900))
	perContent := 200 + 3 + len(clean(dir, maxFieldBytes)) + contentFraming + len(`"{}"`)
	var many []Content
	for i := 0; i < maxContentTotal/perContent+20; i++ {
		many = append(many, Content{Kind: ContentPlugin, Name: fmt.Sprintf("%s%03d", strings.Repeat("n", 200), i), Dir: dir, Files: []ContentFile{{Rel: "plugin.json", Text: "{}"}}})
	}
	many = append(many, many[len(many)-1])
	facts, _ = Decode(Encode(Facts{Contents: many}))
	kept, stubs := 0, 0
	for _, content := range facts.Contents {
		switch {
		case !content.Truncated && len(content.Files) == 1:
			kept++
		case content.Truncated && len(content.Files) == 0:
			stubs++
		default:
			t.Errorf("content %q = %+v, want its text or a truncated content without text", content.Name[len(content.Name)-3:], content)
		}
	}
	if kept < maxContentTotal/perContent-2 || stubs == 0 || kept+stubs != len(many)-1 {
		t.Errorf("kept %d with text and %d truncated of %d (one a repeat), want none dropped and the repeat stubbed once", kept, stubs, len(many)-1)
	}
	last := many[len(many)-1].Name
	if got := facts.ContentsFor(ContentPlugin, last); len(got) != 1 || !got[0].Truncated {
		t.Errorf("last plugin = %+v, want one truncated content", got)
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
	env := EnvSkillRoots("copilot", home, cwd, nil)
	for _, want := range []string{filepath.Join(os.Getenv("COPILOT_HOME"), "skills"), custom, filepath.Join(home, "shared"), filepath.Join(cwd, "rel", "skills")} {
		if !containsRoot(env, want) {
			t.Errorf("environment skill roots = %v, missing %s", env, want)
		}
	}
	if len(env) != 4 || EnvSkillRoots("claudecode", home, cwd, nil) != nil {
		t.Errorf("environment skill roots = %v (claudecode %v), want 4 for copilot and none for others", env, EnvSkillRoots("claudecode", home, cwd, nil))
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

// A relative COPILOT_SKILLS_DIRS entry is rooted at the folder the agent runs
// in, and only there, whatever the event folder is (the same, below, above,
// beside, unrelated or absent): a skill of any other folder is not loaded, so
// it never decides the selection. Without the agent folder the roots are the
// event folder and the outermost repository root.
func TestLaunchWorkspacesPreferTheAgentFolder(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	module := filepath.Join(root, "module")
	sub := filepath.Join(module, "sub")
	unrelated := t.TempDir()
	for name, tc := range map[string]struct {
		cwd, launch string
		want        []string
	}{
		"event folder":        {sub, sub, []string{sub}},
		"intermediate folder": {sub, module, []string{module}},
		"repository root":     {sub, root, []string{root}},
		"unrelated folder":    {sub, unrelated, []string{unrelated}},
		"folder below":        {module, sub, []string{sub}},
		"event folder absent": {"", module, []string{module}},
		"relative event":      {"sub", module, []string{module}},
		"relative":            {sub, "module", []string{sub, root}},
		"unreported":          {sub, "", []string{sub, root}},
		"nothing known":       {"", "", nil},
	} {
		if got := launchWorkspaces(t.TempDir(), tc.cwd, tc.launch); !slices.Equal(got, tc.want) {
			t.Errorf("%s: launchWorkspaces = %v, want %v", name, got, tc.want)
		}
	}
}
