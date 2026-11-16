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

import "testing"

// The dot builtin is the program "." and reads its file into the current
// shell like source: the action is as opaque as the source spelling, with the
// file as a read operand (rel-1-0-9:GAP-0981). A name that ends in a dot below
// a folder is no program.
func TestDotBuiltinIsAnOpaqueSourceLikeTheWordSource(t *testing.T) {
	t.Parallel()

	if got := commandProgram("."); got != "." {
		t.Fatalf(`commandProgram(".") = %q, want "."`, got)
	}
	for _, executable := range []string{"dir/.", "/usr/bin/.", "/"} {
		if got := commandProgram(executable); got != "" {
			t.Errorf("commandProgram(%q) = %q, want no program", executable, got)
		}
	}
	for _, spelling := range []string{"source", "."} {
		facts := Analyze(Input{Tool: "exec", Command: spelling + " ./chain/hop001/run.sh", CWD: "/repo"})
		if facts.Parse.Status != StatusPartial || !containsIssue(facts.Parse.Issues, IssueOpaqueArtifact) {
			t.Errorf("%s: status %v issues %v, want a partial parse with an opaque artifact", spelling, facts.Parse.Status, facts.Parse.Issues)
		}
		if len(facts.Commands) != 1 || facts.Commands[0].Program != spelling {
			t.Errorf("%s: commands %#v", spelling, facts.Commands)
		}
	}
}
