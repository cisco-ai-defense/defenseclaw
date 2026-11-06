// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func gap236BalancedAction(t *testing.T, command, cwd, home, connector string, dialect actionfacts.Dialect, managed bool) string {
	t.Helper()
	args, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	input := actionfacts.Input{Tool: "Bash", Args: args, Command: command, CWD: cwd,
		ActiveHome: home, DialectHint: dialect}
	findings := dispatchTrustedAction(context.Background(), trustedActionRequest{
		Input: input, LegacyText: string(args), Connector: connector,
		EnforcementCapable: true, ProtectedHomeHook: managed,
	})
	return buildVerdict(findings, "tool_call").Action
}

func TestGAP0236BalancedAssignedHereStringPrint(t *testing.T) {
	const home = `C:\Users\review`
	for _, row := range []struct{ name, command, want string }{
		{"assigned print", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t", "allow"},
		{"multiple displays", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t; Write-Host $t", "allow"},
		{"display pipeline", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t | Out-String", "allow"},
		{"direct print twin", "Write-Output @'\n.ssh/authorized_k*\n'@", "allow"},
		{"writer twin", "$t = @'\n.ssh/authorized_k*\n'@; Add-Content -Path $t -Value k", "block"},
		{"named file twin", "$t = @'\n.ssh/authorized_keys\n'@; Write-Output $t", "block"},
		{"redirect twin", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t > .ssh/authorized_keys", "block"},
	} {
		for _, connector := range []string{"codex", "claudecode"} {
			for _, managed := range []bool{false, true} {
				for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPowerShell} {
					t.Run(row.name+"/"+connector+"/"+string(dialect)+"/"+map[bool]string{false: "user", true: "managed"}[managed], func(t *testing.T) {
						if got := gap236BalancedAction(t, row.command, home, home, connector, dialect, managed); got != row.want {
							t.Errorf("verdict %s, want %s", got, row.want)
						}
					})
				}
			}
		}
	}
}

func TestGAP0496BalancedBashHomeListing(t *testing.T) {
	const home = `C:\Users\review`
	for _, row := range []struct{ name, command, want string }{
		{"single quoted listing", `bash -c 'ls -d */* | head -3'`, "allow"},
		{"extra spacing", `bash  -c 'ls -d */* | head -3'`, "allow"},
		{"tab separator", "bash\t-c 'ls -d */* | head -3'", "allow"},
		{"env launch", `env bash -c 'ls -d */* | head -3'`, "allow"},
		{"single quoted discard", `bash -c 'ls -d */* 2>/dev/null | head -3'`, "allow"},
		{"reader variant", `bash -c 'ls */* | head -4'`, "allow"},
		{"program case variant", `BASH -c 'ls -d */* | head -3'`, "allow"},
		{"double quoted twin", `bash -c "ls -d */* | head -3"`, "allow"},
		{"double quoted discard", `bash -c "ls -d */* 2>/dev/null | head -3"`, "allow"},
		{"writer twin", `bash -c 'echo fixture >> .ssh/authorized_keys'`, "block"},
		{"named writer twin", `bash -c 'echo fixture >> ~/.ssh/authorized_keys'`, "block"},
	} {
		for _, connector := range []string{"codex", "claudecode"} {
			for _, managed := range []bool{false, true} {
				t.Run(row.name+"/"+connector+"/"+map[bool]string{false: "user", true: "managed"}[managed], func(t *testing.T) {
					if got := gap236BalancedAction(t, row.command, home, home, connector, actionfacts.DialectPOSIX, managed); got != row.want {
						t.Errorf("verdict %s, want %s", got, row.want)
					}
				})
			}
		}
	}
}

func TestGAP0548BalancedQuotedOptionAndSwitches(t *testing.T) {
	const home = `C:\Users\review`
	const cwd = home + `\project`
	for _, row := range []struct{ name, command, want string }{
		{"quoted option source", `t="-t $HOME/.ssh"; cp "$t" a.txt`, "allow"},
		{"ordinary option", `t="-t $HOME/build"; cp $t a.txt`, "allow"},
		{"unquoted protected option", `t="-t $HOME/.ssh"; cp $t a.txt`, "block"},
		{"direct protected destination", `cp -t "$HOME/.ssh" a.txt`, "block"},
		{"Copy-Item Recurse", `Copy-Item -Recurse -Path .\src -Destination .\build`, "allow"},
		{"Copy-Item Container", `Copy-Item -Container -Path .\src -Destination .\build`, "allow"},
		{"Copy-Item protected destination", `Copy-Item -Recurse -Path .\src -Destination $HOME\.ssh\authorized_keys`, "block"},
	} {
		for _, connector := range []string{"codex", "claudecode"} {
			t.Run(row.name+"/"+connector, func(t *testing.T) {
				if got := gap236BalancedAction(t, row.command, cwd, home, connector, "", false); got != row.want {
					t.Errorf("verdict %s, want %s", got, row.want)
				}
			})
		}
	}
}

func TestGAP236PossiblePrefixKeepsNamedWrite(t *testing.T) {
	const home = `C:\Users\review`
	for _, row := range []struct {
		name, command, cwd string
		dialect            actionfacts.Dialect
	}{
		{"listing", `ls */*; cd .ssh; echo k >> authorized_keys`, home, actionfacts.DialectPOSIX},
		{"project glob", `cp *.txt build/; cd ../.ssh; echo k >> authorized_keys`, home + `\project`, actionfacts.DialectPOSIX},
		{"config copy", `cp ~/.defenseclaw/conf*.yaml project/copy.yaml; cd .ssh; echo k >> authorized_keys`, home, actionfacts.DialectPOSIX},
		{"copy switch redirect", `Copy-Item -Recurse -Path .\src -Destination .\build; cd .ssh; echo k >> authorized_keys`, home, actionfacts.DialectPowerShell},
		{"copy switch writer", `Copy-Item -Recurse -Path .\src -Destination .\build; cd .ssh; Set-Content authorized_keys k`, home, actionfacts.DialectPowerShell},
		{"text print", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t; cd .ssh; echo k >> authorized_keys", home, actionfacts.DialectPowerShell},
		{"known value", `t=authorized_keys; cd .ssh; cp a "$t"`, home, actionfacts.DialectPOSIX},
		{"quoted child writer", `bash -c 'ls -d */* | head "-3"; cd .ssh; echo k >> authorized_keys'`, home, actionfacts.DialectPOSIX},
	} {
		for _, connector := range []string{"codex", "claudecode"} {
			t.Run(row.name+"/"+connector, func(t *testing.T) {
				if got := gap236BalancedAction(t, row.command, row.cwd, home, connector, row.dialect, false); got != "block" {
					t.Errorf("verdict %s, want block", got)
				}
			})
		}
	}
}

func TestGAP0496QuotedHeadReadOnlyListing(t *testing.T) {
	const home = `C:\Users\review`
	for _, command := range []string{
		`bash -c 'ls -d */* | head "-3"'`,
		`bash -c 'ls -d */* | head -n "3"'`,
		`env bash -c 'ls -d */* | head "-3"'`,
	} {
		for _, connector := range []string{"codex", "claudecode"} {
			t.Run(command+"/"+connector, func(t *testing.T) {
				if got := gap236BalancedAction(t, command, home, home, connector, actionfacts.DialectPOSIX, false); got != "allow" {
					t.Errorf("verdict %s, want allow", got)
				}
			})
		}
	}
}
