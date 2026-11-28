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

//go:build linux

package kit

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// B5.4 use gate: a Claude Code Skill tool call runs the skill folder pass
// before the call goes on (re-digest), so a folder swapped after its scan is
// a new fingerprint and is sent again, and a folder that arrived since the
// last pass is decided before the skill loads.
func TestB54SkillToolRunsTheFolderPass(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	writeSkill(t, filepath.Join(home, ".claude", "skills"), "late", "x")
	payload := `{"hook_event_name":"PreToolUse","tool_name":"Skill","tool_input":{"skill":"late"},"cwd":"` + repo + `"}`
	var env HookEnvelope
	var out, errb bytes.Buffer
	RunHook(context.Background(), HookOptions{Connector: "claudecode", Config: testConfig("https://gw"), Home: home,
		Stdin: strings.NewReader(payload), Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" },
		Send: func(_ context.Context, r Request) (Response, string, error) {
			json.Unmarshal(r.Body, &env)
			return Response{Status: 200, Body: []byte(`{}`)}, "", nil
		}})
	if env.Facts == nil || len(env.Facts.Skills) != 1 || !env.Facts.Skills[0].Attached {
		t.Fatalf("the Skill tool call did not send the folder: %+v", env.Facts)
	}
	// Another tool's PreToolUse does not run the pass (hook path cost).
	env = HookEnvelope{}
	payload = `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"true"},"cwd":"` + repo + `"}`
	RunHook(context.Background(), HookOptions{Connector: "claudecode", Config: testConfig("https://gw"), Home: home,
		Stdin: strings.NewReader(payload), Stdout: &out, Stderr: &errb, Getenv: func(string) string { return "" },
		Send: func(_ context.Context, r Request) (Response, string, error) {
			json.Unmarshal(r.Body, &env)
			return Response{Status: 200, Body: []byte(`{}`)}, "", nil
		}})
	if env.Facts != nil && len(env.Facts.Skills) > 0 {
		t.Fatalf("a Bash PreToolUse ran the skill pass: %+v", env.Facts.Skills)
	}
}
