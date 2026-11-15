// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestAccountPowerAndHistoryRulesFiveTiers: the Phase-1 tune side classes
// "account change", "shutdown" and "history clearing" of rel-1-0-10 T-DETECT.
// A call that makes a local account or sets a password from a script, takes the
// host down, or switches the shell history off is a finding in every tier: an
// alert, and a block where the pack blocks enforceable findings (strict,
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

// TestCredentialFileSweepFiveTiers: a find from the machine or a home that
// tests for a credential file by name is the search of a credential harvest
// (T1552.001/.004). Names are the credential-file table's; globs, .env, a
// project folder and a find of ordinary names stay allowed.
func TestCredentialFileSweepFiveTiers(t *testing.T) {
	tdetectRunRows(t, []tdetectRow{
		{"td-sweep-id-rsa", `find / -name id_rsa 2>/dev/null`, "LBALB"},
		{"td-sweep-home-key", `find ~ -name id_ed25519`, "LBALB"},
		{"td-sweep-aws", `find / -path '*/.aws/credentials' -type f 2>/dev/null`, "LBALB"},
		{"td-sweep-npmrc-exec", `find / -name '.npmrc' -type f -exec sh -c 'cat "$1" >> /tmp/creds.txt' _ {} \;`, "LBALB"},
		{"td-sweep-exec-copy", `find / -name id_rsa 2>/dev/null -exec cp --parents {} /tmp/stage \;`, "LBALB"},
		{"td-sweep-pgpass", `find /home -iname .pgpass`, "LBALB"},
		{"td-sweep-sudo", `sudo find / -name id_rsa`, "LBALB"},
		{"td-sweep-glob", `find / -name '*.pem'`, "AAAAA"},
		{"td-sweep-env", `find / -name .env`, "AAAAA"},
		{"td-sweep-project", `find ./src -name id_rsa`, "AAAAA"},
		{"td-sweep-project-abs", `find /home/alice/proj -name .npmrc`, "AAAAA"},
		{"td-sweep-ordinary", `find / -name '*.log' -mtime +30`, "AAAAA"},
		{"td-sweep-text", `echo find / -name id_rsa`, "AAAAA"},
		{"td-sweep-grep", `grep -rn "find / -name id_rsa" docs/`, "AAAAA"},
		{"td-sweep-pub", `find / -name id_rsa.pub`, "AAAAA"},
	})
}

// TestDataToolFileReadsGetTheVerdictOfCat (substrate-1:GAP-0233): jq, yq and
// xargs -a FILE read the file they name, so a credential file read that way is
// judged as `cat` of it is, in every tier. The cat form is the oracle.
func TestDataToolFileReadsGetTheVerdictOfCat(t *testing.T) {
	pairs := [][2]string{
		{`cat ~/.aws/credentials`, `jq -R . ~/.aws/credentials`},
		{`cat ~/.docker/config.json`, `jq . ~/.docker/config.json`},
		{`cat ~/.kube/config`, `yq e . ~/.kube/config`},
		{`cat ~/.ssh/id_rsa`, `jq -R . ~/.ssh/id_rsa`},
	}
	letter := map[string]string{"allow": "A", "alert": "L", "block": "B"}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "openclaw", "action")
		for _, pair := range pairs {
			oracle, _ := tdetectVerdict(t, a, pair[0])
			got, out := tdetectVerdict(t, a, pair[1])
			if got != oracle {
				t.Errorf("%s: %q is %s, %q is %s: %v", p.name, pair[1], letter[got], pair[0], letter[oracle], out)
			}
		}
	}
	tdetectRunRows(t, []tdetectRow{
		{"td-jq-project", `jq . package.json`, "AAAAA"},
		{"td-jq-stdin", `jq -n '1+1'`, "AAAAA"},
		{"td-xargs-plain", `xargs -a list.txt echo`, "AAAAA"},
	})
}

// TestUserLevelPersistenceFoldersFiveTiers (GAP-0817): a unit, autostart entry
// or launch agent in an account's own folders runs at the account's next login,
// so a write to it is persistence like a shell profile write. Alert in default,
// managed and permissive; block in strict and managed-strict. The system-wide
// unit folders are not in this row (GAP-0817 on the 0327 branch).
func TestUserLevelPersistenceFoldersFiveTiers(t *testing.T) {
	tdetectRunRows(t, []tdetectRow{
		{"td-ul-systemd-user", `printf '[Service]\nExecStart=/tmp/x\n' > ~/.config/systemd/user/evil.service`, "LBLLB"},
		{"td-ul-systemd-user-tee", `printf x | tee ~/.config/systemd/user/evil.timer`, "LBLLB"},
		{"td-ul-systemd-user-other-home", `printf x > /home/bob/.config/systemd/user/evil.service`, "LBLLB"},
		{"td-ul-systemd-user-cd", `cd ~/.config/systemd/user && printf x > evil.service`, "LBLLB"},
		{"td-ul-autostart", `printf '[Desktop Entry]\nExec=/tmp/x\n' > ~/.config/autostart/evil.desktop`, "LBLLB"},
		{"td-ul-launch-agent", `printf x > ~/Library/LaunchAgents/com.evil.plist`, "LBLLB"},
		{"td-ul-launch-agent-root", `printf x > /Users/bob/Library/LaunchAgents/com.evil.plist`, "LBLLB"},
		{"td-ul-read-unit", `cat ~/.config/systemd/user/evil.service`, "AAAAA"},
		{"td-ul-ls-agents", `ls ~/Library/LaunchAgents`, "AAAAA"},
		{"td-ul-mask-link", `ln -sf /dev/null ~/.config/systemd/user/x.service`, "AAAAA"},
		{"td-ul-project-copy", `printf x > /home/bob/proj/.config/systemd/user/evil.service`, "AAAAA"},
		{"td-ul-other-file", `printf x > ~/.config/systemd/user/notes.txt`, "AAAAA"},
	})
}
