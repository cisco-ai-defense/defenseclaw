// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"
	"testing"
)

// The positional Windows PowerShell 5.1 form consumes -wd but runs the body
// in its original cwd (native TST-16012). pwsh 7 treats the positional text
// as a script filename and runs no body. No shell text is executed here.
func TestGAP1557PositionalWorkingDirectoryByHostEdition(t *testing.T) {
	const home = `C:\Users\fixture`
	const cwd = home + `\project`
	const requested = home + `\.defenseclaw`
	const body = "Set-Content -Path config.yaml -Value marker"
	rows := []struct {
		name string
		argv []string
		want string
	}{
		{"powershell short option", []string{"powershell.exe", "-NoProfile", "-wd", requested, body}, cwd + `\config.yaml`},
		{"powershell full option", []string{"powershell.exe", "-NoProfile", "-WorkingDirectory", requested, body}, cwd + `\config.yaml`},
		{"pwsh positional", []string{"pwsh.exe", "-NoProfile", "-wd", requested, body}, ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			res := Extract(Call{Surface: SurfaceArgv, Tool: "shell", Argv: row.argv},
				Options{Flavor: FlavorWindows, Dialect: DialectPowerShell, Home: home, CWD: cwd})
			var writes []string
			for _, e := range res.Effects {
				if e.Kind == KindWrite || e.Kind == KindAppend {
					writes = append(writes, e.Target.Path)
				}
			}
			if row.want == "" {
				if len(writes) != 0 {
					t.Fatalf("unexpected positional write: %d writes", len(writes))
				}
				return
			}
			if len(writes) != 1 || !strings.EqualFold(writes[0], row.want) {
				t.Fatalf("writes %v, want only %s", writes, row.want)
			}
		})
	}
}

// An unqualified powershell host on a non-Windows flavor has an unknown
// edition. The 5.1 writing reading is stronger than pwsh 7 no-write, so the
// projection keeps the original-cwd write without executing either host.
func TestGAP1557UnknownEditionTakesWritingReading(t *testing.T) {
	const home = "/home/fixture"
	const cwd = home + "/project"
	res := Extract(Call{Surface: SurfaceArgv, Tool: "shell", Argv: []string{
		"powershell", "-wd", home + "/requested", "Set-Content -Path notes.txt -Value marker",
	}}, Options{Flavor: FlavorPOSIX, Dialect: DialectPowerShell, Home: home, CWD: cwd})
	var writes []string
	for _, effect := range res.Effects {
		if effect.Kind == KindWrite || effect.Kind == KindAppend {
			writes = append(writes, effect.Target.Path)
		}
	}
	if len(writes) != 1 || writes[0] != cwd+"/notes.txt" {
		t.Fatalf("unknown-edition write count=%d; want original-cwd placement", len(writes))
	}
}
