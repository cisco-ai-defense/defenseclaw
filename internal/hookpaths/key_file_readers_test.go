// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// rel-1-0-10:GAP-0018: a call that only prints, checksums, compares or lists
// the protected key file, with or without a sudo or env wrapper, writes
// nothing and is not an authorized-keys mutation; every writer, a shell behind
// the wrapper and an output option stay one.
func TestKeyFileReadersAreNotWrites(t *testing.T) {
	_, home, cwd := globFactsFixture(t, false)
	key := home + "/.ssh/authorized_keys"
	for _, command := range []string{
		`echo ` + home + `/.ssh/authorized_keys`,
		`printf '%s\n' ` + key,
		`sha256sum ` + key,
		`sudo sha256sum ` + key,
		`sudo -n shasum -a 256 ` + key + ` /etc/hostname`,
		`md5sum ` + key + ` | cut -c1-8`,
		`sudo ls ` + key + ` 2>&1 | cut -c1-80`,
		`sudo stat -c "%n %a" ` + key,
		`sudo lsattr ` + key,
		`env LC_ALL=C cmp ` + key + ` /tmp/x`,
		`sudo cmp /var/lib/a.json /root/b.json; sudo ls ` + key,
		`timeout 5 diff ` + key + ` /tmp/y`,
		`sudo -u builder cat ` + key,
		`sudo -n ls ` + home + `/.ssh 2>&1 | head -2`,
	} {
		if got := posixShellDecision(command, cwd, home); got != "" {
			t.Errorf("%s: decision = %q, want allow", command, got)
		}
	}
	for _, command := range []string{
		`echo x >> ` + key,
		`printf x | tee -a ` + key,
		`sudo sh -c "echo k >> ` + key + `"`,
		`sudo cp /tmp/k ` + key,
		`sudo tee ` + key,
		`sudo sha256sum ` + key + ` > ` + key,
		`env sh -c 'echo k >> ` + key + `'`,
		`sudo dd of=` + key + ` if=/tmp/k`,
		`sudo -u builder rm ` + key,
		`sudo sort -o ` + key + ` /tmp/k`,
		`sudo chattr -i ` + key,
		`timeout 5 mv /tmp/k ` + key,
	} {
		if got := posixShellDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("%s: decision = %q, want protected-target", command, got)
		}
	}
}
