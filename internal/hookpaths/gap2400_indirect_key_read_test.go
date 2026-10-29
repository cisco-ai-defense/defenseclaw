// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

func TestGAP2400LiteralPrivateKeyReadBindings(t *testing.T) {
	for _, env := range []struct{ name, home, cwd string }{
		{"windows", `C:\Users\u`, `C:\Users\u\project`},
		{"posix", `/home/u`, `/home/u/project`},
	} {
		key := "~/.ssh/" + "id_ed25519"
		glob := "~/.ssh/" + "id_*"
		project := "~/project/" + "notes*"
		for _, tc := range []struct {
			name, command string
			want          bool
		}{
			{"powershell glob piped to content reader", "Get-ChildItem " + glob + " | Get-Content", true},
			{"powershell glob piped to foreach reader", "Get-ChildItem " + glob + " | ForEach-Object { Get-Content $_ }", true},
			{"powershell foreach variable bound to glob", "foreach ($f in Get-ChildItem " + glob + ") { Get-Content $f }", true},
			{"powershell literal assignment used by reader", "$p = " + key + "; Get-Content $p", true},
			{"powershell literal home assignment used by reader", "$p = \"$HOME/.ssh/" + "id_ed25519\"; Get-Content $p", true},
			{"powershell join path literal parts used by reader", "Get-Content -Path (Join-Path $HOME '.ssh/" + "id_ed25519')", true},
			{"powershell join path assigned then read", "$p = Join-Path $HOME '.ssh/" + "id_ed25519'; Get-Content $p", true},
			{"powershell filesystem drive root used by reader", "New-PSDrive -Name K -PSProvider FileSystem -Root $HOME; Get-Content K:/.ssh/" + "id_ed25519", true},
			{"powershell filesystem drive root used by provider read", "New-PSDrive -Name K -PSProvider FileSystem -Root $HOME; ${K:/.ssh/" + "id_ed25519}", true},
			{"posix listing piped to xargs reader", "ls " + glob + " | xargs cat", true},
			{"posix listing piped to xargs n1 reader", "ls " + glob + " | xargs -n1 cat", true},
			{"posix literal assignment used by reader", "p=" + key + "; cat \"$p\"", true},
			{"ssh directory listing", "ls ~/.ssh", false},
			{"powershell ssh directory listing", "Get-ChildItem ~/.ssh", false},
			{"powershell key glob listing without reader", "Get-ChildItem " + glob, false},
			{"powershell key glob piped to text formatter", "Get-ChildItem " + glob + " | Out-String", false},
			{"piped key names with explicit project reader path", "Get-ChildItem " + glob + " | Get-Content ~/project/notes.txt", false},
			{"public key read", "Get-Content " + key + ".pub", false},
			{"public key glob piped to content reader", "Get-ChildItem " + glob + ".pub | Get-Content", false},
			{"known hosts read", "Get-Content ~/.ssh/" + "known_hosts", false},
			{"config read", "cat ~/.ssh/" + "config", false},
			{"project glob piped to content reader", "Get-ChildItem " + project + " | Get-Content", false},
			{"project glob piped to xargs reader", "ls " + project + " | xargs cat", false},
			{"project literal assignment used by reader", "$p = ~/project/notes.txt; Get-Content $p", false},
			{"project join path literal parts used by reader", "Get-Content -Path (Join-Path $HOME 'project/notes.txt')", false},
			{"project filesystem drive root used by reader", "New-PSDrive -Name K -PSProvider FileSystem -Root ~/project; Get-Content K:/notes.txt", false},
			{"runtime concatenation evaluated later", "$p = $a + $b; Get-Content $p", false},
			{"quoted command text evaluated later", "Invoke-Expression 'Get-Content " + key + "'", false},
		} {
			t.Run(env.name+"/"+tc.name, func(t *testing.T) {
				if got := ActionPrivateKeyRead(tc.command, env.cwd, env.home); got != tc.want {
					t.Errorf("ActionPrivateKeyRead(%q) = %t, want %t", tc.command, got, tc.want)
				}
			})
		}
	}
}

func TestGAP2400WindowsPowerShellBackslashBindings(t *testing.T) {
	home, cwd := `C:\Users\u`, `C:\Users\u\project`
	for _, tc := range []struct{ name, command string }{
		{"glob piped into reader", "Get-ChildItem ~\\.ssh\\" + "id_* | Get-Content"},
		{"join path into reader", "Get-Content -Path (Join-Path $HOME '.ssh\\" + "id_ed25519')"},
		{"drive path into reader", "New-PSDrive -Name K -PSProvider FileSystem -Root $HOME; Get-Content K:\\.ssh\\" + "id_ed25519"},
		{"provider path read", "New-PSDrive -Name K -PSProvider FileSystem -Root $HOME; ${K:\\.ssh\\" + "id_ed25519}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !ActionPrivateKeyRead(tc.command, cwd, home) {
				t.Errorf("ActionPrivateKeyRead(%q) = false, want true", tc.command)
			}
		})
	}
}
