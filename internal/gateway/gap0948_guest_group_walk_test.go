// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import "testing"

// TestGAP0948GuestGroupRunsInTheCallShell: a { ... } group runs in the call
// shell, so the walk steps its statements in order. After the failing-cd fan,
// { cd ../.ssh || exit; } leaves the shell in ../.ssh as on the laptop, and
// the authorized_keys write there blocks
// (persistence.ssh_authorized_keys_command) where the copy-mode actor
// alerted (substrate-1 GAP-0948, RV-SEC10B E62). The benign rows keep the
// laptop answer in every pack.
func TestGAP0948GuestGroupRunsInTheCallShell(t *testing.T) {
	fan := "cd .cache\nbash <<< \x27true\x27\n$CMD\ncd s0\ncd s1\ncd s2\ncd s3\ncd s4\ncd s5\ncd s6\n"
	gap0377Check(t, []gap0377Row{
		{name: "E62 fan group or-exit", command: fan + "{ cd ../.ssh || exit; }\necho k >> authorized_keys"},
		{name: "E62b fan group or-exit-1 semicolons", command: fan + "{ cd ../.ssh || exit 1; }; echo k >> authorized_keys"},
		{name: "G01 fan nested group", command: fan + "{ { cd ../.ssh || exit; }; }\necho k >> authorized_keys"},
		{name: "G02 fan group and", command: fan + "{ true && cd ../.ssh || exit; }\necho k >> authorized_keys"},
		{name: "G03 group cd ssh", command: "$CMD; { cd ~/.ssh; }; echo k >> authorized_keys"},
		{name: "G04 group cd dc", command: "$CMD; { cd ~/.defenseclaw || exit; }; echo m > config.yaml"},
		{name: "N09 group src make", command: "{ cd src || exit; make; }; $CMD; echo x > out.txt", benign: true},
		{name: "G10 group tmp cfg", command: "{ cd /tmp || exit; }; $CMD; echo m > config.yaml", benign: true},
		{name: "G11 group src later dc", command: "{ cd src || exit; make; }; $CMD; echo m > config.yaml; cd ~/.defenseclaw && ls", benign: true},
		{name: "G12 group build later claude", command: "{ cd build && make; }; $CMD; echo x > settings.json; cd ~/.claude && ls", benign: true},
	})
}
