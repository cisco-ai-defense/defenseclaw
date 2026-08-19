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

package actionfacts

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestActiveAgentFilesAreBoundedTrustedContext(t *testing.T) {
	t.Parallel()

	provided := []string{
		"/repo/./AGENTS.md",
		"/repo/AGENTS.md",
		`C:\Users\fixture\MEMORY.md`,
	}
	facts := Analyze(Input{
		Tool:                      "shell",
		Command:                   "printf updated > /repo/AGENTS.md",
		CWD:                       "/repo",
		ActiveAgentFiles:          provided,
		ActiveAgentFilesUncertain: true,
	})
	want := []string{"/repo/AGENTS.md", "C:/Users/fixture/MEMORY.md"}
	if !facts.Authoritative() || !facts.ActiveAgentFilesUncertain ||
		!slices.Equal(facts.ActiveAgentFiles, want) {
		t.Fatalf("active files = %#v, want %#v; facts=%#v", facts.ActiveAgentFiles, want, facts)
	}

	provided[0] = "/attacker/MEMORY.md"
	if !slices.Equal(facts.ActiveAgentFiles, want) {
		t.Fatalf("facts retained caller-owned slice: %#v", facts.ActiveAgentFiles)
	}

	projected := facts.EnforcementProjection()
	if !projected.ActiveAgentFilesUncertain {
		t.Fatal("enforcement projection lost active-file uncertainty")
	}
	facts.ActiveAgentFiles[0] = "/mutated/AGENTS.md"
	if !slices.Equal(projected.ActiveAgentFiles, want) {
		t.Fatalf("projection retained source-owned slice: %#v", projected.ActiveAgentFiles)
	}

	untrustedArgs := Analyze(Input{
		Tool: "opaque",
		Args: json.RawMessage(
			`{"active_agent_files":["/attacker/AGENTS.md"],"path":"/repo/AGENTS.md"}`,
		),
	})
	if len(untrustedArgs.ActiveAgentFiles) != 0 {
		t.Fatalf("args supplied active-file context: %#v", untrustedArgs)
	}
}

func TestActiveAgentFilesRejectUnboundedOrInexactContext(t *testing.T) {
	t.Parallel()

	for _, invalid := range []string{
		"",
		"AGENTS.md",
		"/",
		"$HOME/AGENTS.md",
		" /repo/AGENTS.md",
		`C:\`,
	} {
		facts := Analyze(Input{
			Argv:             []string{"true"},
			ActiveAgentFiles: []string{invalid},
		})
		if facts.Parse.Status != StatusInvalid || len(facts.ActiveAgentFiles) != 0 {
			t.Fatalf("invalid path %q = %#v", invalid, facts)
		}
	}

	oversized := Analyze(Input{
		Argv: []string{"true"},
		ActiveAgentFiles: []string{
			"/repo/" + strings.Repeat("a", maxScalarBytes) + "/AGENTS.md",
		},
	})
	if oversized.Parse.Status != StatusLimitExceeded ||
		len(oversized.ActiveAgentFiles) != 0 {
		t.Fatalf("oversized context = %#v", oversized)
	}

	tooMany := make([]string, maxActiveAgentFiles+1)
	for index := range tooMany {
		tooMany[index] = "/repo/agents/" + strings.Repeat("a", index+1) + "/AGENTS.md"
	}
	limited := Analyze(Input{Argv: []string{"true"}, ActiveAgentFiles: tooMany})
	if limited.Parse.Status != StatusLimitExceeded ||
		len(limited.ActiveAgentFiles) != 0 {
		t.Fatalf("unbounded context = %#v", limited)
	}
}
