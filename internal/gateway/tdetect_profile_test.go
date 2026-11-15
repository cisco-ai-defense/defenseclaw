// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestShellStartupFileOfAnotherAccountFiveTiers: a startup file runs at the next
// login of the account whose home holds it, whoever wrote it, so a write to the
// profile of another account (/root, /home/<user>) is the same persistence as a
// write to the active user's own (substrate-1 round T-DETECT, Phase-1 tune miss
// class "rc/alias persistence"). The write to the active home is the oracle;
// reads, project copies and dotfile staging trees stay ordinary.
// Letters: default, strict, permissive, managed, managed-strict.
func TestShellStartupFileOfAnotherAccountFiveTiers(t *testing.T) {
	tdetectRunRows(t, []tdetectRow{
		{"td-rc-active-home", `printf x >> ~/.bashrc`, "LBLLB"},
		{"td-rc-root-append", `printf x >> /root/.bashrc`, "LBLLB"},
		{"td-rc-root-profile", `printf x >> /root/.profile`, "LBLLB"},
		{"td-rc-other-user", `printf x >> /home/bob/.zshrc`, "LBLLB"},
		{"td-rc-other-user-aliases", `printf x >> /home/bob/.bash_aliases`, "LBLLB"},
		{"td-rc-sed-in-place", `sed -i '$a x' /root/.bashrc`, "LBLLB"},
		{"td-rc-zshenv", `printf x >> ~/.zshenv`, "LBLLB"},
		{"td-rc-system-profile", `printf x >> /etc/profile`, "LBLLB"},
		// The other system copies are routine host administration, as for rel.
		{"td-rc-system-bashrc", `printf x >> /etc/bash.bashrc`, "AAAAA"},
		{"td-rc-read-root", `cat /root/.bashrc`, "AAAAA"},
		{"td-rc-grep-root", `grep -n alias /root/.bashrc`, "AAAAA"},
		{"td-rc-project-copy", `printf x >> /home/bob/proj/.bashrc`, "AAAAA"},
		{"td-rc-dotfile-tree", `printf x >> /var/lib/dotfiles/users/alice/.bashrc`, "AAAAA"},
		{"td-rc-example", `printf x >> ~/.bashrc.example`, "AAAAA"},
		{"td-rc-profile-d-script", `printf x >> /etc/profile.d/x.sh`, "AAAAA"},
		{"td-rc-relative", `printf x >> .bashrc`, "AAAAA"},
	})
}
