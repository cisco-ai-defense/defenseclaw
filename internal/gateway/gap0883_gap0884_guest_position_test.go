// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import "testing"

// TestGAP0883GuestReadsEachStatementWhereItRuns: the copy-mode guest
// placement reads each statement only in the folders known at its own place.
// A folder only a later cd reaches (cd ~/.defenseclaw && ls after the write)
// made echo m > config.yaml a strict block (tamper.detector_state_write) and a
// default alert where the laptop and rel/1.0.10 allow (substrate-1 GAP-0883,
// RV-SEC10 rows C01-C03, C08, B43, B44, B48). The rows are benign: the actor
// must give the laptop's answer in every pack.
func TestGAP0883GuestReadsEachStatementWhereItRuns(t *testing.T) {
	gap0377Check(t, []gap0377Row{
		{name: "C01 sub tmp later dc", command: "(cd /tmp)\n$CMD\necho m > config.yaml\ncd ~/.defenseclaw && ls", benign: true},
		{name: "C02 no sub later dc", command: "$CMD\necho m > config.yaml\ncd ~/.defenseclaw && ls", benign: true},
		{name: "C03 no unread later dc", command: "echo m > config.yaml\ncd ~/.defenseclaw && ls", benign: true},
		{name: "C08 proj source later dc", command: "cd ~/p || exit\nsource .env\necho m > config.yaml\ncd ~/.defenseclaw && ls", benign: true},
		{name: "B43 sub-or claude later cd", command: "(cd .claude || cd /tmp)\n$CMD\necho '{}' > settings.json\ncd .claude\nls", benign: true},
		{name: "B44 sub-or dc later cd", command: "(cd ~/.defenseclaw || cd /tmp)\n$CMD\necho m > config.yaml\ncd ~/.defenseclaw && ls", benign: true},
		{name: "B48 dc sub later cd abs", command: "(cd ~/.defenseclaw || true)\n$CMD\necho m > config.yaml\ncd ~/.defenseclaw\ncat config.yaml", benign: true},
	})
}

// TestGAP0884GuestCdOrExitStandsInTheFolder: after the failing-cd fan, cd
// ../.ssh || exit leaves the shell in ../.ssh for what follows, as on the
// laptop, so the authorized_keys write there blocks
// (persistence.ssh_authorized_keys_command) where the actor alerted
// (substrate-1 GAP-0884, RV-SEC10 rows C05, C06).
func TestGAP0884GuestCdOrExitStandsInTheFolder(t *testing.T) {
	gap0377Check(t, []gap0377Row{
		{name: "C05 fan7 or-exit", command: "cd .cache\nbash <<< 'true'\n$CMD\ncd s0\ncd s1\ncd s2\ncd s3\ncd s4\ncd s5\ncd s6\ncd ../.ssh || exit\necho k >> authorized_keys"},
		{name: "C06 fan7 or-exit-1", command: "cd .cache\nbash <<< 'true'\n$CMD\ncd s0\ncd s1\ncd s2\ncd s3\ncd s4\ncd s5\ncd s6\ncd ../.ssh || exit 1\necho k >> authorized_keys"},
	})
}

// TestGAP0888GuestHookConfigCandidateWhereTheShellStands: after a command the
// split cannot read ($CMD), the sandbox hook-config guard counted every
// candidate folder of the call, wherever it came: a cd in a subshell that
// ended before $CMD, or one a later statement runs, made the settings.json
// write an alert where the laptop and the rel actor allow (substrate-1
// GAP-0888, RV-SEC10 B43). The tilde and uncalled-function shapes still
// alert as on the laptop. Every row must give the laptop's answer.
func TestGAP0888GuestHookConfigCandidateWhereTheShellStands(t *testing.T) {
	gap0377Check(t, []gap0377Row{
		{name: "V1 sub-or rel claude", command: "(cd .claude || cd /tmp)\n$CMD\necho '{}' > settings.json", benign: true},
		{name: "V6 sub-or later cd", command: "(cd .claude || cd /tmp)\n$CMD\necho '{}' > settings.json\ncd .claude", benign: true},
		{name: "V7 sub-or ls first", command: "(cd .claude || cd /tmp)\n$CMD\nls\necho '{}' > settings.json\ncd .claude", benign: true},
		{name: "V8 sub-or echo after", command: "(cd .claude || cd /tmp)\n$CMD\necho '{}' > settings.json\necho hi", benign: true},
		{name: "B02 sub-or tilde claude", command: "(cd ~/.claude || cd /tmp)\n$CMD\necho '{}' > settings.json", benign: true},
		{name: "V4 sub-or tilde later cd", command: "(cd ~/.claude || cd /tmp)\n$CMD\necho '{}' > settings.json\ncd ~/.claude\nls", benign: true},
		{name: "B03 uncalled fn claude", command: "f() { cd .claude; }\n$CMD\necho '{}' > settings.json", benign: true},
		{name: "pushd dyn claude", command: "pushd .claude\n$CMD\necho '{}' > settings.json"},
		{name: "cd dyn claude", command: "cd .claude\n$CMD\necho '{}' > settings.json"},
	})
}
