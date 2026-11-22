// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"testing"
)

// A write the link walk holds only because it cannot read every link
// operation of the call, whose every written name reaches the DefenseClaw
// state tree, is named by its target: the state rule, never the SSH keys
// rule (rel-1-0-10:GAP-1568). The keys target is still a MAYBE (a link step
// went unread), so the row keeps its 1.0.10 block (DET111 ruling
// 2026-11-22T03:20Z). A link into ~/.ssh, or a call that also writes outside
// the state tree, keeps the keys rule.
func TestGAP1568LinkHeldStateWriteNamesTheStateRule(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	stateOnly := []string{gap0747StateRule, "!" + gap0747SSHKeysRule}
	judgeHomeStateRuleRows(t, []homeStateRuleRow{
		{"ln -s HOMEDIR/.defenseclaw hc; mv a.txt hc/config.yaml", stateOnly},
		{"env -C ~ ln -s .defenseclaw hc; cp a.txt ~/hc/config.yaml", stateOnly},
		{"env -C ~ ln -s .defenseclaw/hooks hk; cp a.txt ~/hk/x.sh", stateOnly},
		{"env -C ~ ln -sf project/a.txt .defenseclaw/config.yaml", stateOnly},
		{"ln -s ~/.ssh sd; cp a.txt sd/authorized_keys", []string{gap0747SSHKeysRule}},
		{"env -C ~ ln -s .ssh sd; cp a.txt ~/sd/authorized_keys", []string{gap0747SSHKeysRule}},
		{"env -C ~ ln -s .ssh hc; cp a.txt ~/hc/config.yaml", []string{gap0747SSHKeysRule}},
		{"ln -s HOMEDIR/.defenseclaw hc; mv a.txt hc/config.yaml; cp a.txt ~/.ssh/authorized_keys", []string{gap0747SSHKeysRule}},
		{"env -C ~ ln -s .defenseclaw hc; env -C ~ ln -s .ssh sd; cp a.txt ~/hc/config.yaml ~/sd/authorized_keys", []string{gap0747SSHKeysRule}},
	})
}
