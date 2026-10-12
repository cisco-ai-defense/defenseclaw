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

// GAP-0175: the file writes an agent produces on Windows carry -NoNewline,
// -InputObject or -Append. Raw PowerShell left them partial while the
// structured binder bound them, so CEL block rules fell back to
// detection-only and a CRITICAL match was allowed. They are authoritative
// now, with the write's target and kind.
func TestPowerShellContentWritesAreAuthoritative(t *testing.T) {
	t.Parallel()
	const target = `C:\work\note.txt`
	for _, test := range []struct {
		command   string
		operation OperationKind
		access    PathAccess
	}{
		{`Set-Content -Path C:\work\note.txt -Value dccert-block-marker -NoNewline`, OperationWrite, PathAccessWrite},
		{`Add-Content -Path C:\work\note.txt -Value dccert-block-marker -NoNewline`, OperationAppend, PathAccessAppend},
		{`Out-File -FilePath C:\work\note.txt -InputObject dccert-block-marker -Encoding utf8`, OperationWrite, PathAccessWrite},
		{`Out-File -FilePath C:\work\note.txt -InputObject dccert-block-marker -Append -NoClobber`, OperationAppend, PathAccessAppend},
	} {
		facts := Analyze(Input{Tool: "shell", Command: test.command, DialectHint: DialectPowerShell})
		if !facts.Authoritative() || len(facts.Commands) != 1 ||
			!commandHasOperation(facts.Commands[0], test.operation) || !factsHavePath(facts, test.access, target) {
			t.Errorf("%s: parse %s %v, facts %#v", test.command, facts.Parse.Status, facts.Parse.Issues, facts)
		}
		if test.access == PathAccessAppend && factsHavePath(facts, PathAccessWrite, target) {
			t.Errorf("%s: an append also reads as an overwrite: %#v", test.command, facts.Paths)
		}
	}
}
