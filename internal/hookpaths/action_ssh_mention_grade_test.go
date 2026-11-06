// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

func TestSSHKeyMentionGradeRoles(t *testing.T) {
	const home = `C:\Users\review`
	for _, row := range []struct{ name, command, want string }{
		{"display pipeline", "$t = @'\n.ssh/authorized_k*\n'@; Write-Output $t | Out-String", PossibleTargetDecision},
		{"display direct", "Write-Output @'\n.ssh/authorized_k*\n'@", PossibleTargetDecision},
		{"writer consumes text", "$t = @'\n.ssh/authorized_k*\n'@; Add-Content -Path $t -Value k", ProtectedTargetDecision},
		{"read-only Bash", `bash  -c 'ls -d */* | head -3'`, PossibleTargetDecision},
		{"read-only Bash discard", `bash -c "ls -d */* 2>/dev/null | head -3"`, PossibleTargetDecision},
		{"read-only listing", `ls -d */* | head -3`, PossibleTargetDecision},
		{"known file", `echo k >> .ssh/authorized_keys`, ProtectedTargetDecision},
		{"quoted copy option", `t="-t $HOME/.ssh"; cp "$t" a.txt`, PossibleTargetDecision},
		{"split copy destination", `t="-t $HOME/.ssh"; cp $t a.txt`, ProtectedTargetDecision},
		{"direct copy destination", `cp -t "$HOME/.ssh" a.txt`, ProtectedTargetDecision},
		{"project glob", `cp *.txt build/`, PossibleTargetDecision},
		{"Copy-Item option", `Copy-Item -Recurse -Path .\src -Destination .\build`, PossibleTargetDecision},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := SSHKeyMentionGrade(row.command, home, home); got != row.want {
				t.Errorf("grade = %q, want %q", got, row.want)
			}
		})
	}
}
