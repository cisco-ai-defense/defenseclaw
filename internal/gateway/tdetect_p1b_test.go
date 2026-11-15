// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestAccountPowerAndHistoryRulesFiveTiers: the Phase-1 tune side classes
// "account change", "shutdown" and "history clearing" of rel-1-0-10 T-DETECT.
// A call that makes a local account or sets a password from a script, takes the
// host down, or switches the shell history off is a finding in every tier: an
// alert (MEDIUM findings, power and history, are recorded and allowed in the
// permissive pack, as in rel), and a block where the pack blocks enforceable findings (strict,
// managed-strict). Reads of the same names, a group change (the privileged-group
// rule keeps those), ordinary history settings and text that only names the
// commands stay allowed. Letters: default, strict, permissive, managed,
// managed-strict.
func TestAccountPowerAndHistoryRulesFiveTiers(t *testing.T) {
	tdetectRunRows(t, []tdetectRow{
		{"td-acct-useradd", `useradd evil_user`, "LBLLB"},
		{"td-acct-useradd-sudo", `sudo useradd -m -s /bin/bash art`, "LBLLB"},
		{"td-acct-useradd-system", `useradd -M -N -r -s /bin/bash -c evil_account evil_user`, "LBLLB"},
		{"td-acct-adduser", `adduser bob`, "LBLLB"},
		{"td-acct-chpasswd", `echo "root:pw" | chpasswd`, "LBLLB"},
		{"td-acct-usermod-password", `usermod --password x bob`, "LBLLB"},
		{"td-acct-usermod-p", `usermod -p x bob`, "LBLLB"},
		{"td-acct-dscl", `dscl . -create /Users/evil`, "LBLLB"},
		{"td-acct-net-user", `net user evil Passw0rd /add`, "LBLLB"},
		{"td-acct-in-shell", `sh -c 'useradd evil_user'`, "LBLLB"},
		{"td-acct-usermod-group", `usermod -aG adm proctor`, "AAAAA"},
		{"td-acct-id", `id alice`, "AAAAA"},
		{"td-acct-getent", `getent passwd bob`, "AAAAA"},
		{"td-acct-passwd-status", `passwd -S bob`, "AAAAA"},
		{"td-acct-text", `echo useradd evil_user`, "AAAAA"},
		{"td-acct-grep", `grep -rn useradd scripts/`, "AAAAA"},
		{"td-acct-net-view", `net user`, "AAAAA"},

		{"td-power-shutdown", `shutdown -h now`, "LBALB"},
		{"td-power-sudo-poweroff", `sudo poweroff`, "LBALB"},
		{"td-power-reboot", `reboot`, "LBALB"},
		{"td-power-systemctl", `systemctl poweroff`, "LBALB"},
		{"td-power-init", `init 0`, "LBALB"},
		{"td-power-shutdown-r", `sudo shutdown -r +5`, "LBALB"},
		{"td-power-in-shell", `bash -c 'reboot'`, "LBALB"},
		{"td-power-systemctl-status", `systemctl status ssh`, "AAAAA"},
		{"td-power-restart-service", `sudo systemctl restart nginx`, "AAAAA"},
		{"td-power-grep", `grep -rn reboot docs/`, "AAAAA"},
		{"td-power-git-log", `git log --grep=reboot --oneline`, "AAAAA"},
		{"td-power-text", `echo "shutdown -h now" > notes.txt`, "AAAAA"},

		{"td-hist-histsize", `export HISTSIZE=0`, "LBALB"},
		{"td-hist-histfile", `export HISTFILE=/dev/null`, "LBALB"},
		{"td-hist-set-off", `set +o history`, "LBALB"},
		{"td-hist-filesize", `export HISTFILESIZE=0`, "LBALB"},
		{"td-hist-size-ok", `export HISTSIZE=1000`, "AAAAA"},
		{"td-hist-control", `export HISTCONTROL=ignoreboth`, "AAAAA"},
		{"td-hist-set-e", `set -e`, "AAAAA"},
		{"td-hist-text", `echo 'export HISTSIZE=0' >> notes.txt`, "AAAAA"},
	})
}
