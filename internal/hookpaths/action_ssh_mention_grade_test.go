// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func testActionCommandMaxGrade(command, cwd, home string) Grade {
	memo := NewTargetMemo()
	grade := GradeNone
	for _, dialect := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX, actionfacts.DialectPowerShell} {
		grade = grade.Max(memo.ActionCommandGradeWithDialectAndGlobFacts(command, cwd, home, dialect, nil))
	}
	return grade
}

func TestSSHKeyMentionGradeRoles(t *testing.T) {
	const home = `C:\Users\review`
	for _, row := range []struct{ name, command, want string }{
		{"display pipeline", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t | Out-String", PossibleTargetDecision},
		{"display direct", "Write-Output @'\n.ssh/authorized_k*\n'@", PossibleTargetDecision},
		{"writer consumes text", "$t = @'\n.ssh/authorized_k*\n'@; Add-Content -Path $t -Value k", ProtectedTargetDecision},
		{"writer consumes ordinary pattern", "$t = @'\nproject/report*\n'@; Add-Content -Path $t -Value k", ""},
		{"read-only Bash", `bash  -c 'ls -d */* | head -3'`, PossibleTargetDecision},
		{"read-only Bash quoted option", `bash -c 'ls -d */* | head "-3"'`, PossibleTargetDecision},
		{"read-only Bash quoted number", `bash -c 'ls -d */* | head -n "3"'`, PossibleTargetDecision},
		{"read-only Bash discard", `bash -c "ls -d */* 2>/dev/null | head -3"`, PossibleTargetDecision},
		{"read-only listing", `ls -d */* | head -3`, PossibleTargetDecision},
		{"known file", `echo k >> .ssh/authorized_keys`, ProtectedTargetDecision},
		{"quoted copy option", `t="-t $HOME/.ssh"; cp "$t" a.txt`, PossibleTargetDecision},
		{"split copy destination", `t="-t $HOME/.ssh"; cp $t a.txt`, ProtectedTargetDecision},
		{"direct copy destination", `cp -t "$HOME/.ssh" a.txt`, ProtectedTargetDecision},
		{"project glob", `cp *.txt build/`, PossibleTargetDecision},
		{"Copy-Item option", `Copy-Item -Recurse -Path .\src -Destination .\build`, PossibleTargetDecision},
		{"possible then named directory write", `ls */*; cd .ssh; echo k >> authorized_keys`, ProtectedTargetDecision},
		{"possible copy then named directory write", `Copy-Item -Recurse -Path .\src -Destination .\build; cd .ssh; Set-Content authorized_keys k`, ProtectedTargetDecision},
		{"possible text then named directory write", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t; cd .ssh; echo k >> authorized_keys", ProtectedTargetDecision},
		{"known POSIX value after directory change", `t=authorized_keys; cd .ssh; cp a "$t"`, ProtectedTargetDecision},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := testActionCommandMaxGrade(row.command, home, home); got.String() != row.want {
				t.Errorf("grade = %q, want %q", got, row.want)
			}
		})
	}
}
