// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"
)

// GAP-2090 (review RV4-2, regression of the GAP-1473 printed-tilde rule):
// git runs a configuration value as shell code (an alias, the pager), so a
// quoted ~ path in such a value is a protected target in action mode. A git
// command that keeps its words as text (a commit message, a log search)
// still reads a quoted ~ as text (GAP-1473).
func TestActionWindowsGitConfigValueIsNotText(t *testing.T) {
	const home, cwd = `C:\Users\u`, `C:\Users\u\proj`
	for _, tc := range []struct {
		name, command, want string
	}{
		{"alias value runs", "git -c 'alias.x=!cp k.pub ~/.ssh/authorized_keys' x", "protected-target"},
		{"double-quoted alias value runs", "git -c \"alias.x=!cp k.pub ~/.ssh/authorized_keys\" x", "protected-target"},
		{"pager value runs", "git -c 'core.pager=cp k.pub ~/.ssh/authorized_keys' log", "protected-target"},
		{"saved alias runs later", "git config --global alias.x '!cp k.pub ~/.ssh/authorized_keys'", "protected-target"},
		{"rebase exec runs", "git rebase --exec 'cp k.pub ~/.ssh/authorized_keys' HEAD~1", "protected-target"},
		{"RV5-2 pager glob value runs", "git -c 'core.pager=cp k.pub ~/.ssh/authorized_k*' log", "protected-target"},
		{"RV5-2 alias glob value runs", "git -c 'alias.x=!sed -i s/x/y/ C:/Users/u/.ssh/authorized_k*' x", "protected-target"},
		{"RV5-2 home pager glob value runs", "git -c \"core.pager=sed -i s/x/y/ $HOME\\.ssh\\authorized_k*\" log", "protected-target"},
		{"RV5-2 saved pager glob runs later", "git config --global core.pager 'sed -i s/x/y/ C:/Users/u/.ssh/authorized_k*'", "protected-target"},
		{"RV5-4 -C before a message", "git -C proj commit -m 'Document ~/.ssh/authorized_keys'", ""},
		{"RV5-4 --no-pager before a log search", "git --no-pager log --grep '~/.ssh/authorized_keys'", ""},
		{"RV5-4 -C before -c still runs", "git -C proj -c 'core.pager=cp k.pub ~/.ssh/authorized_keys' log", "protected-target"},
		{"GAP-1473 -c identity before a message", "git -c user.name=vd -c user.email=vd@example.test commit -m 'Document ~/.ssh/authorized_keys'", ""},
		{"GAP-1473 -c identity then alias still runs", "git -c user.name=vd -c 'alias.x=!cp k.pub ~/.ssh/authorized_keys' x", "protected-target"},
		{"GAP-1473 git message", "git commit -m 'Document ~/.ssh/authorized_keys'", ""},
		{"GAP-1473 git log search", "git log --grep '~/.ssh/authorized_keys'", ""},
		{"GAP-1473 printed quoted tilde path", "Write-Output '~/.ssh/authorized_keys'", ""},
		// git stash push reverts the files its pathspec selects, and git
		// expands a pathspec glob itself (RV6-2). Run from the home.
		{"RV6-2 stash pathspec glob from home", "git stash push -- '.ssh/authorized_k*'", "protected-target@home"},
		{"RV6-2 -C stash pathspec glob from home", "git -C proj stash push -- '.ssh/authorized_k*'", "protected-target@home"},
		{"RV6-2 stash pathspec glob without --", "git stash push -m wip '.ssh/authorized_k*'", "protected-target@home"},
		{"RV6-2 stash literal pathspec from home", "git stash push -- '.ssh/authorized_keys'", "protected-target@home"},
		{"RV6-2 stash message stays text", "git stash push -m 'Document ~/.ssh/authorized_keys'", "@home"},
		{"RV6-2 stash list stays text", "git stash list --grep '*.md'", "@home"},
		{"RV6-2 stash project pathspec", "git stash push -- 'src/*.go'", "@home"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, want := cwd, tc.want
			if strings.HasSuffix(want, "@home") {
				dir, want = home, strings.TrimSuffix(want, "@home")
			}
			if got := ActionCommandDecision(tc.command, dir, home); got != want {
				t.Fatalf("ActionCommandDecision(%q) = %q, want %q", tc.command, got, want)
			}
		})
	}
}
