// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// Possible mentions and named writer targets retain their separate grades
// even when ordinary work precedes the writer in the same call.
func TestGAP236Round7ReaderGradeAndWriterRole(t *testing.T) {
	const home = `C:\Users\review`
	project := home + `\project`
	rows := []struct {
		name, command, cwd, want string
		grade                    hookpaths.Grade
		dialect                  actionfacts.Dialect
	}{
		{"listing then project write", `ls */*; echo ok > project/report.txt`, home, "allow", hookpaths.GradePossible, actionfacts.DialectPOSIX},
		{"project write then listing", `echo ok > project/report.txt; ls */*`, home, "allow", hookpaths.GradePossible, actionfacts.DialectPOSIX},
		{"project copy then listing", `cp *.txt build/; ls */*`, project, "allow", hookpaths.GradePossible, actionfacts.DialectPOSIX},
		{"known pattern after display", `$t="$HOME/.ssh/authorized_k*"; Write-Output ready; Set-Content -Path $t -Value k`, home, "block", hookpaths.GradeNamed, actionfacts.DialectPowerShell},
		{"known pattern attached", `$t="$HOME/.ssh/authorized_k*"; Set-Content -Path:$t -Value k`, home, "block", hookpaths.GradeNamed, actionfacts.DialectPowerShell},
		{"known pattern in branch", `$t="$HOME/.ssh/authorized_k*"; if ($true) { Set-Content -Path $t -Value k }`, home, "block", hookpaths.GradeNamed, actionfacts.DialectPowerShell},
		{"known pattern in scriptblock", `$t="$HOME/.ssh/authorized_k*"; & { Set-Content -Path $t -Value k }`, home, "block", hookpaths.GradeNamed, actionfacts.DialectPowerShell},
		{"ordinary pattern in branch", `$t="project/report*"; if ($true) { Set-Content -Path $t -Value k }`, home, "allow", hookpaths.GradeNone, actionfacts.DialectPowerShell},
		{"copy destination pattern", `Copy-Item payload "$HOME/.ssh/authorized_k*"`, project, "block", hookpaths.GradeNamed, actionfacts.DialectPowerShell},
		{"copy known destination pattern", `$t="$HOME/.ssh/authorized_k*"; Copy-Item payload -Destination:$t`, project, "block", hookpaths.GradeNamed, actionfacts.DialectPowerShell},
		{"copy known destination with extra switch", `$t="$HOME/.ssh/authorized_k*"; Copy-Item -Verbose -Path payload -Destination:$t`, project, "block", hookpaths.GradeNamed, actionfacts.DialectPowerShell},
		{"copy known destination in branch", `$t="$HOME/.ssh/authorized_k*"; if ($true) { Copy-Item payload -Destination:$t }`, project, "block", hookpaths.GradeNamed, actionfacts.DialectPowerShell},
		{"copy ordinary destination with extra switch", `$t="project/report*"; Copy-Item -Verbose -Path payload -Destination:$t`, project, "allow", hookpaths.GradePossible, actionfacts.DialectPowerShell},
		{"copy source pattern", `Copy-Item "$HOME/.ssh/authorized_k*" project/report.txt`, project, "allow", hookpaths.GradePossible, actionfacts.DialectPowerShell},
		{"comment after ordinary writer", `Set-Content notes.txt x # see ~/.ssh/authorized_keys`, project, "allow", hookpaths.GradePossible, actionfacts.DialectPowerShell},
		{"comment before named writer", "# see ~/.ssh/authorized_keys\nSet-Content ~/.ssh/authorized_keys x", project, "block", hookpaths.GradeNamed, actionfacts.DialectPowerShell},
		{"content writer words as output", `Write-Output 'Set-Content -Path $HOME/.ssh/authorized_k*'`, project, "allow", hookpaths.GradeNone, actionfacts.DialectPowerShell},
		{"copy writer words as output", `Write-Output 'Copy-Item payload $HOME/.ssh/authorized_k*'`, project, "allow", hookpaths.GradeNone, actionfacts.DialectPowerShell},
		{"listing then named writer", `ls */*; echo k >> .ssh/authorized_keys`, home, "block", hookpaths.GradeNamed, actionfacts.DialectPOSIX},
		{"read protected directory", `Get-ChildItem C:\Users\review\.ssh`, project, "allow", hookpaths.GradeNone, actionfacts.DialectPowerShell},
		{"navigate protected directory", `Push-Location C:\Users\review\.ssh; Get-ChildItem; Pop-Location`, project, "allow", hookpaths.GradeNone, actionfacts.DialectPowerShell},
		{"read protected key", `Get-Content $HOME\.ssh\authorized_keys`, project, "allow", hookpaths.GradeNone, actionfacts.DialectPowerShell},
		{"check protected directory", "# Inspect folder\nTest-Path ~\\.ssh", project, "allow", hookpaths.GradePossible, actionfacts.DialectPowerShell},
		{"list protected directory with comment", `Get-ChildItem ~\.ssh # list only`, project, "allow", hookpaths.GradeNone, actionfacts.DialectPowerShell},
		{"read then named writer", `Get-Content $HOME\.ssh\authorized_keys; Set-Content -Path $HOME\.ssh\authorized_keys -Value k`, project, "block", hookpaths.GradeNamed, actionfacts.DialectPowerShell},
	}
	for _, row := range rows {
		for _, connector := range []string{"codex", "claudecode"} {
			t.Run(row.name+"/"+connector, func(t *testing.T) {
				request := trustedActionRequest{Input: actionfacts.Input{
					Command: row.command, CWD: row.cwd, ActiveHome: home, DialectHint: row.dialect,
				}, targetMemo: hookpaths.NewTargetMemo()}
				if got := sshKeyMentionGrade(request); got != row.grade {
					t.Errorf("grade = %s, want %s", got, row.grade)
				}
				if got := gap236Round5Action(t, row.command, row.cwd, home, connector, row.dialect); got != row.want {
					t.Errorf("verdict = %s, want %s", got, row.want)
				}
			})
		}
	}
}
