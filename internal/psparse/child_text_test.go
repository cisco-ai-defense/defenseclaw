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

package psparse

import "testing"

// rel-1-0-10:GAP-1226: the -Command script a child reads alike is read; any
// other expansion is not.
func TestHostCommandChildTextReadsOnlyWhatTheChildReadsAlike(t *testing.T) {
	cases := []struct {
		source, want string
		ok           bool
	}{
		{`powershell -c "Copy-Item $HOME\.ssh\id_rsa C:\t"`, `Copy-Item $HOME\.ssh\id_rsa C:\t`, true},
		{`pwsh -NoProfile -Command "type $env:USERPROFILE\.netrc"`, `type $env:USERPROFILE\.netrc`, true},
		{`powershell -c "Copy-Item $x C:\t"`, "", false},
		{`powershell -c "Copy-Item $(gci) C:\t"`, "", false},
		{`powershell -c "Copy-Item ${HOME}\a C:\t"`, "", false},
		{"powershell -c \"Copy-Item `$HOME\\a C:\\t\"", "", false},
		{`powershell -c "Copy-Item $HOMEDIR\a C:\t"`, "", false},
		{`powershell -c "Copy-Item $HOME\a C:\t" extra`, "", false},
		{`powershell -c:"Copy-Item $HOME\a C:\t"`, "", false},
		{`powershell -c "Copy-Item ""$HOME\a"" C:\t"`, "", false},
	}
	for _, c := range cases {
		script, _ := Parse(c.source, Options{Dialect: DialectUnknown})
		var command *Command
		if script != nil && len(script.Statements) == 1 {
			command, _ = script.Statements[0].(*Command)
			if p, isPipeline := script.Statements[0].(*Pipeline); isPipeline && len(p.Elements) == 1 {
				command, _ = p.Elements[0].(*Command)
			}
		}
		if command == nil {
			t.Fatalf("%s: no command", c.source)
		}
		got, ok := HostCommandChildText(command)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: %q %v, want %q %v", c.source, got, ok, c.want, c.ok)
		}
	}
}

// rel-1-0-10:GAP-0998: a loop is read as its header and body statements.
func TestArgumentCommandReadingReadsALoopAsItsStatements(t *testing.T) {
	for source, want := range map[string]string{
		`foreach ($i in 1) { Copy-Item $HOME\a C:\t }`: `Copy-Item $HOME\a C:\t`,
		`while ($true) { Remove-Item x; break }`:       "Remove-Item x\nbreak",
	} {
		got, changed, cut := ArgumentCommandReading(source)
		if !changed || cut.Any() || got != want {
			t.Errorf("%s: %q changed=%v cut=%v, want %q", source, got, changed, cut.Any(), want)
		}
	}
	if got, changed, _ := ArgumentCommandReading(`function f { Remove-Item x }`); changed {
		t.Errorf("a function body is not run where it stands: %q", got)
	}
}
