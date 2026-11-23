// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attest

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// cleanSkillScanner answers what skill-scanner 2.3.2 gives a clean skill
// (the scanner image on E1, B5.4): one INFO manifest note, nothing else.
type cleanSkillScanner struct{}

func (cleanSkillScanner) Name() string               { return "skill-scanner" }
func (cleanSkillScanner) Version() string            { return "2.3.2" }
func (cleanSkillScanner) SupportedTargets() []string { return []string{"skill"} }
func (cleanSkillScanner) Scan(_ context.Context, target string) (*scanner.ScanResult, error) {
	return &scanner.ScanResult{Scanner: "skill-scanner", Target: target, Findings: []scanner.Finding{{
		ID: "f1", RuleID: "MANIFEST_MISSING_LICENSE", Severity: scanner.SeverityInfo, Title: "no license in the manifest"}}}, nil
}

// B5.4 OpenCode condition (i): a clean OpenCode skill written into each
// folder OpenCode loads gives no alert and no block. Green at rel a64bfdb931
// (those folders were not skill folders there, so nothing is decided) and
// at the head (each is now a skill folder, scanned, and allowed).
func TestOpenCodeCleanSkillNoNewAlertVsRel(t *testing.T) {
	rt := NewRuntimeScanner(&config.Config{})
	rt.Skill = cleanSkillScanner{}
	clean := "---\nname: tables\ndescription: Formats a markdown table.\n---\nFormat the table the user gives you as markdown.\n"
	for _, dir := range []string{
		"/home/u/.config/opencode/skill", "/home/u/.config/opencode/skills",
		"/work/.opencode/skill", "/work/.opencode/skills",
		"/home/u/.opencode/skill", "/home/u/.opencode/skills",
		"/work/.claude/skills", "/work/.agents/skills",
		"/home/u/.claude/skills", "/home/u/.agents/skills",
	} {
		ev := gap0185Event(t, "Write", "/work", map[string]any{"file_path": dir + "/tables/SKILL.md", "content": clean})
		for _, a := range HookAssets(ev, []AttachedFile{{Role: RoleSkillFile, Path: dir + "/tables/SKILL.md", Content: []byte(clean)}}) {
			d, err := rt.Scan(context.Background(), a)
			if err != nil || d.Action != "allow" {
				t.Errorf("%s: clean skill %s: action=%q reason=%q err=%v", dir, a.Name, d.Action, d.Reason, err)
			}
		}
	}
}
