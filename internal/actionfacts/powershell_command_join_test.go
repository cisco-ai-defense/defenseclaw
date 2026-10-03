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

// GAP-2079: PowerShell joins the arguments after -Command into the body, so
// an unquoted body is parsed like the quoted one.
func TestAnalyzePowerShellCommandJoinsUnquotedBody(t *testing.T) {
	facts := Analyze(Input{
		Tool:        "shell",
		Command:     "pwsh -NoProfile -Command echo a b > C:/Users/alice/x.txt",
		DialectHint: DialectPOSIX,
	})
	if !facts.Authoritative() || len(facts.Commands) != 2 {
		t.Fatalf("facts = %+v", facts.Parse)
	}
	child := facts.Commands[1]
	if child.ParentCommandID != facts.Commands[0].ID ||
		!equalStrings(child.Argv, []string{"echo", "a", "b"}) {
		t.Fatalf("child = %+v", child)
	}

	empty := Analyze(Input{
		Tool:        "shell",
		Command:     "pwsh -NoProfile -Command echo \x27\x27",
		DialectHint: DialectPOSIX,
	})
	if empty.Authoritative() {
		t.Fatalf("an empty -Command argument must stay opaque: %+v", empty.Parse)
	}
}
