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

package gateway

import (
	"encoding/json"
	"testing"
)

// GAP-0983: the use gate names a folder only by what the kit's PreToolUse
// pass carries (Claude Code Skill by name, Read file_path, NotebookRead
// notebook_path, and the paths the kit resolved). The command and "path"
// key matches were never reached (removed, not wired): a folder the pass
// refuses is moved by the kit before the call runs, and while one is held
// every call is refused.
func TestB511UseGateMatchesOnlyWiredRoutes(t *testing.T) {
	dir := "/home/agent/.claude/skills/evil"
	call := func(tool string, input map[string]any, paths ...SubstratePathFact) substrateEnvelope {
		p, _ := json.Marshal(map[string]any{"tool_name": tool, "tool_input": input})
		return substrateEnvelope{Payload: p, Facts: &SubstrateFacts{Paths: paths}}
	}
	for name, c := range map[string]struct {
		env  substrateEnvelope
		want string
	}{
		"skill-by-folder-name": {call("Skill", map[string]any{"skill": "evil"}), dir},
		"skill-plugin-prefix":  {call("Skill", map[string]any{"skill": "tools:evil"}), dir},
		"read-file-path":       {call("Read", map[string]any{"file_path": dir + "/SKILL.md"}), dir},
		"notebook-path":        {call("NotebookRead", map[string]any{"notebook_path": dir + "/n.ipynb"}), dir},
		"read-resolved":        {call("Read", map[string]any{"file_path": "SKILL.md"}, SubstratePathFact{Abs: "/work/SKILL.md", Resolved: dir + "/SKILL.md"}), dir},
		"bash-command":         {call("Bash", map[string]any{"command": "cat skills/evil/SKILL.md"}), ""},
		"path-key":             {call("Grep", map[string]any{"pattern": "x", "path": dir}), ""},
		"other-folder":         {call("Read", map[string]any{"file_path": "/home/agent/notes.md"}), ""},
	} {
		if got := skillUsedFolder(c.env, []string{dir}); got != c.want {
			t.Errorf("%s: skillUsedFolder = %q, want %q", name, got, c.want)
		}
	}
}
