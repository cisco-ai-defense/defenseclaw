// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestGAP2400BarePipelineReaderDialect(t *testing.T) {
	home, cwd := `C:\Users\u`, `C:\Users\u\project`
	glob := "~/.ssh/" + "id_*"
	for _, tc := range []struct {
		name, consumer    string
		powershell, posix bool
	}{
		{"B26 cat", "cat", true, false},
		{"type", "type", true, false},
		{"head", "head", false, false},
		{"tail", "tail", false, false},
		{"base64", "base64", false, false},
		{"Get-Content Raw", "Get-Content -Raw", true, true},
	} {
		command := "ls " + glob + " | " + tc.consumer
		for _, shell := range []struct {
			name    string
			dialect actionfacts.Dialect
			want    bool
		}{
			{"powershell", actionfacts.DialectPowerShell, tc.powershell},
			{"bash", actionfacts.DialectPOSIX, tc.posix},
		} {
			t.Run(tc.name+"/"+shell.name, func(t *testing.T) {
				if got := ActionPrivateKeyReadWithDialect(command, cwd, home, shell.dialect); got != shell.want {
					t.Errorf("ActionPrivateKeyReadWithDialect(%q, %q) = %t, want %t", command, shell.dialect, got, shell.want)
				}
			})
		}
	}
}

func TestGAP2400PowerShellTypeOnPOSIXHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a POSIX home needs POSIX path semantics; a Windows host always has a Windows home")
	}
	command := `$k = "$HOME\.ssh\` + "id_ed25519" + `"; type $k`
	if !ActionPrivateKeyReadWithDialect(command, "/home/u/project", "/home/u", actionfacts.DialectPowerShell) {
		t.Errorf("PowerShell type did not read assigned private key path: %q", command)
	}
}

func TestGAP2400LiteralPrivateKeyReadBindings(t *testing.T) {
	for _, env := range []struct{ name, home, cwd string }{
		{"windows", `C:\Users\u`, `C:\Users\u\project`},
		{"posix", `/home/u`, `/home/u/project`},
	} {
		if env.name == "posix" && runtime.GOOS == "windows" {
			// A POSIX home needs POSIX path semantics; a Windows host always
			// has a Windows home (the windows rows run there).
			continue
		}
		key := "~/.ssh/" + "id_ed25519"
		glob := "~/.ssh/" + "id_*"
		project := "~/project/" + "notes*"
		posix := env.name == "posix"
		for _, tc := range []struct {
			name, command string
			want          bool
		}{
			{"powershell glob piped to content reader", "Get-ChildItem " + glob + " | Get-Content", true},
			{"M02 trailing gc", "gci " + glob + " | gc", true},
			{"M18 variable then type", "$k = \"$HOME\\.ssh\\" + "id_ed25519\"; type $k", !posix},
			{"M20 xargs head", "ls $HOME/.ssh/" + "id_* | xargs head", true},
			{"Get-Content Raw pipeline", "Get-ChildItem " + glob + " | Get-Content -Raw", true},
			{"gc encoding pipeline", "gci " + glob + " | gc -Encoding utf8", true},
			{"explicit project path with Raw", "Get-ChildItem " + glob + " | Get-Content -Raw -Path ~/project/notes.txt", false},
			{"B26 POSIX listing piped to cat", "ls " + glob + " | cat", !posix},
			{"bare head receives listing text", "ls " + glob + " | head", false},
			{"bare tail receives listing text", "ls " + glob + " | tail", false},
			{"bare base64 receives listing text", "ls " + glob + " | base64", false},
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
