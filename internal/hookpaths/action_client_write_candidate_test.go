// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

func TestActionClientWriteCandidate(t *testing.T) {
	for _, row := range []struct {
		command string
		want    bool
	}{
		{"format source.go", false},
		{"terraform plan", false},
		{"npm run build 2>&1", false},
		{"go test ./... > build/test.log 2>&1", true},
		{"echo x >& build/out.log", true},
		{"rm -f sshlink/authorized_keys", true},
		{"pwsh -c \"Set-Content -Path keylink -Value k\"", true},
	} {
		if got := actionClientWriteCandidate(row.command); got != row.want {
			t.Errorf("%q: candidate %v, want %v", row.command, got, row.want)
		}
	}
}

func TestActionClientDeadValueProofDeclinesChangedShellExpansion(t *testing.T) {
	for _, row := range []struct {
		name, command string
		want          bool
	}{
		{"ordinary-redirect", `f=keylink; f=a.txt; echo m >> "$f"`, true},
		{"quoted-install", `f=keylink; f=a.txt; install b.txt "$f"`, true},
		{"quoted-rsync", `f=keylink; f=a.txt; rsync b.txt "$f"`, true},
		{"rebound-home", `HOME=/tmp/project; f=~/keylink; echo m >> "$f"`, false},
		{"directory-stack-tilde", `f=~+/keylink; echo m >> "$f"`, false},
		{"unquoted-install", `f=keylink; f=a.txt; install b.txt $f`, false},
		{"unquoted-rsync", `f=keylink; f=a.txt; rsync b.txt $f`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := actionClientProvedSafeVariableTargets(row.command, "/tmp/project", "/tmp/home"); got != row.want {
				t.Errorf("proof %v, want %v for %q", got, row.want, row.command)
			}
		})
	}
}
