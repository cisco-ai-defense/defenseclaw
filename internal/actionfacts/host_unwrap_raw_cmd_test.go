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

func TestRawCMDLauncherLine(t *testing.T) {
	for _, test := range []struct {
		name, source, want string
		ok                 bool
	}{
		{"plain line keeps backslashes", `cmd /c dir C:\work\src`, `dir C:\work\src`, true},
		{"exe name and switches", `CMD.EXE /d /s /c dir C:\work`, `dir C:\work`, true},
		{"double quotes around the line", `cmd /c "dir C:\work"`, `dir C:\work`, true},
		{"single quotes around the line", `cmd /c 'dir C:\work'`, `dir C:\work`, true},
		{"keep-open switch", `cmd /k dir`, `dir`, true},
		{"quote inside the line stays", `cmd /c dir "C:\my dir"`, `dir "C:\my dir"`, true},
		{"unknown switch before /c", `cmd /x /c dir`, ``, false},
		{"no switch", `cmd dir`, ``, false},
		{"empty line", `cmd /c`, ``, false},
		{"empty quoted line", `cmd /c ""`, ``, false},
		{"not a cmd launcher", `echo cmd /c dir`, ``, false},
		{"other program", `cmdline /c dir`, ``, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, dialect, ok := rawCMDLauncherLine(test.source)
			if ok != test.ok || got != test.want || ok && dialect != DialectCMD {
				t.Fatalf("rawCMDLauncherLine(%q) = %q, %v, %v; want %q, %v", test.source, got, dialect, ok, test.want, test.ok)
			}
		})
	}
}

func TestPowerShellOnlyGrammar(t *testing.T) {
	for _, test := range []struct {
		source string
		want   bool
	}{
		{`& { git status }`, true},
		{`Set-Location C:\work; git status`, true},
		{`git status ; Write-Output done`, false},
		{`mkdir -p /tmp/w && cd /tmp/w && cat > lib.ps1 <<'EOF'` + "\n" + `New-Item -ItemType Directory x` + "\n" + `EOF`, false},
		{`pwsh -NoProfile -Command "New-Item -ItemType Directory C:\x | Out-Null"; scp -q a.ps1 host:C:/x/`, false},
		{`Get-ChildItem | Select-Object Name`, true},
		{`ls -la /tmp`, false},
		{`docker-compose up -d`, false},
		{`git config --get user.name`, false},
		{`echo done; sleep 1`, false},
		{`pip install set-tools`, false},
	} {
		if got := powerShellOnlyGrammar(test.source); got != test.want {
			t.Errorf("powerShellOnlyGrammar(%q) = %v, want %v", test.source, got, test.want)
		}
	}
}
