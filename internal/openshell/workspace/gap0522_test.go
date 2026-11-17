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
//
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"strings"
	"testing"
)

// GAP-0522: agent settings in a subfolder (an agent started there loads
// them) and the hook and MCP files of Kiro, Copilot CLI and OpenCode are
// flagged too. GAP-0523: a symbolic link named like a run-code file or
// folder (.mcp.json, .bashrc, .claude) is flagged as that file, not only as
// an info-level link, wherever inside the project it points.
func TestGAP0522And0523NestedSettingsAndNamedLinksAreFlagged(t *testing.T) {
	noContent := func(TreeChange, bool) ([]byte, bool) { return nil, false }
	files := []string{"pkg/.claude/settings.json", "pkg/.codex/config.toml", "pkg/.claude/hooks/x.sh", ".kiro/hooks/x.kiro.hook",
		".kiro/settings/mcp.json", ".github/hooks/x.json", "opencode.json", "apps/web/.cursor/mcp.json"}
	var changes []TreeChange
	for _, p := range files {
		changes = append(changes, TreeChange{Path: p, Status: "A", NewMode: "100644"})
	}
	links := map[string]string{".mcp.json": "tools/servers.json", ".claude": "cfg", ".bashrc": "misc/rc"}
	for p := range links {
		changes = append(changes, TreeChange{Path: p, Status: "A", NewMode: modeSymlink})
	}
	content := func(c TreeChange, after bool) ([]byte, bool) {
		if t, ok := links[c.Path]; ok && after {
			return []byte(t), true
		}
		return noContent(c, after)
	}
	high := map[string]bool{}
	for _, f := range classifyChanges(changes, content, nil) {
		if f.Severity == SeverityHigh {
			high[f.Path] = true
		}
	}
	for _, p := range append(files, ".mcp.json", ".claude", ".bashrc") {
		if !high[p] {
			t.Errorf("%s has no high flag", p)
		}
	}
	rep := &ReviewReport{Flags: classifyChanges([]TreeChange{{Path: ".claude", Status: "A", NewMode: modeSymlink}}, content, nil)}
	if !rep.Sensitive() {
		t.Error("a pull that adds only a .claude link inside the folder is not sensitive")
	}
	for _, f := range classifyChanges([]TreeChange{{Path: "docs/link", Status: "A", NewMode: modeSymlink}}, func(TreeChange, bool) ([]byte, bool) { return []byte("../README.md"), true }, nil) {
		if f.Severity == SeverityHigh && !strings.Contains(f.Detail, "outside") {
			t.Errorf("an ordinary link inside the folder got a high flag: %+v", f)
		}
	}
}
