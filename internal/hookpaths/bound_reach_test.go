// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// GAP-0534 and GAP-0677: a call the readers did not finish keeps the
// over-limit block when its text may name a protected target, directly,
// split by quotes or escapes, or through a known value; an ordinary target
// does not.
func TestBoundCallMayNameProtected(t *testing.T) {
	const home = "/home/alice"
	project := home + "/project"
	for _, row := range []struct {
		command, cwd string
		named        bool
	}{
		{`rm -rf ~/.defenseclaw`, project, true},
		{`rm -rf ~/.defense"claw"`, project, true},
		{`d=.defense; e=claw; rm -rf ~/$d$e`, project, true},
		{`Remove-Item -Recurse -Force ~/.ssh/authorized_keys`, project, true},
		{`rm -rf ~/.s\sh`, project, true},
		{`rm ~/.claude/settings.json`, project, true},
		{`rm ~/.codex/hooks.json`, project, true},
		{`rm ./CLAUDE.md AGENTS.md`, project, true},
		{`echo x >> ~/.bashrc`, project, true},
		{`rm -rf ~/.config/opencode`, project, true},
		{`rm /etc/sudoers`, project, true},
		{`Remove-Item -Recurse -Force ~`, project, true},
		{`Remove-Item -Recurse -Force $HOME`, project, true},
		{`rm -rf "${HOME}/"`, project, true},
		{`Remove-Item -Recurse $env:USERPROFILE`, project, true},
		{`p=~; rm -rf "$p"`, project, true},
		{`{"command":"Remove-Item -Recurse -Force $HOME"}`, project, true},
		{`& { Remove-Item -Recurse -Force ~}`, project, true},
		{`rm -rf ~/$name`, project, true},
		{`rm -rf ~/.*`, project, true},
		{`rm -rf ~/project/..`, project, true},
		{`rm -rf ../..`, project, true},
		{`rm -rf ~/..`, project, true},
		{`rm -rf ~bob`, project, true},
		{`rm -rf /home/alice`, project, true},
		{`rm -rf /home`, project, true},
		{`rm -rf /`, project, true},
		{`rm -rf *`, home, true},
		{`rm -rf .`, home, true},

		{`rm -rf ~/project/output`, project, false},
		{`Write-Output $(.\a[1]<#x#>); Remove-Item -Recurse -Force ~/project/output`, project, false},
		{"0`@A>`; Remove-Item -Recurse -Force output", project, false},
		{`rm -rf /tmp/x`, project, false},
		{`rm -rf /home/alice/project/output`, project, false},
		{`rm -rf $HOME/project/output`, project, false},
		{`rm -rf *`, project, false},
		{`ssh host sh -c printf %s a b`, project, false},
	} {
		if got := BoundCallMayNameProtected(row.command, row.cwd, home); got != row.named {
			t.Errorf("BoundCallMayNameProtected(%q, cwd %s) = %v, want %v", row.command, row.cwd, got, row.named)
		}
	}
}
