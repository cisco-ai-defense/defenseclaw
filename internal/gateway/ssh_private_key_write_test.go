// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// GAP-1666: a write to the active user's SSH private key is an SSH
// directory finding; a read stays PATH-SSH-KEY's and ssh-keygen is quiet.
func TestSSHPrivateKeyWriteIsSSHDirectoryFinding(t *testing.T) {
	const connector = "ssh-private-key-write"
	installToolCallCorpusProfileConnector(t, connector, "default")
	tests := []struct {
		command string
		want    bool
	}{
		{"touch /home/alice/.ssh/id_ed25519", true},
		{"echo dccert-block-marker >> /home/alice/.ssh/id_ed25519", true},
		{"echo dccert-block-marker > ~/.ssh/id_rsa", true},
		{"echo dccert-block-marker >> ~/.ssh/id_ed25519", true},
		{"touch ~/.ssh/id_ed25519", true},
		{"sed -i s/a/b/ /home/alice/.ssh/id_ed25519", true},
		{"rm /home/alice/.ssh/id_ecdsa", true},
		{"head -c 0 /home/alice/.ssh/id_ed25519", false},
		{`ssh-keygen -t ed25519 -N "" -f /home/alice/.ssh/id_ed25519`, false},
		{"touch /home/alice/project/id_ed25519", false},
		// GAP-1832: $HOME targets and tee operands in a pipeline alert as the
		// absolute forms do.
		{`echo dccert-block-marker >> "$HOME/.ssh/id_rsa"`, true},
		{"echo dccert-block-marker >> $HOME/.ssh/id_ed25519", true},
		{`echo dccert-block-marker > "${HOME}/.ssh/id_ed25519"`, true},
		{"touch $HOME/.ssh/id_ed25519", true},
		{"printf dccert-block-marker | tee -a ~/.ssh/id_rsa", true},
		{"printf dccert-block-marker | tee ~/.ssh/id_ed25519", true},
		{`printf dccert-block-marker | tee "$HOME/.ssh/id_ed25519"`, true},
		{"printf dccert-block-marker | tee ~/project/notes.txt", false},
		{`echo dccert-block-marker > "$HOME/project/id_ed25519"`, false},
		// GAP-1716: mkdir in the same action, and sed -i forms with -e or
		// the BSD suffix operand.
		{"mkdir -p ~/.ssh && touch ~/.ssh/id_ed25519", true},
		{"mkdir -p /home/alice/.ssh && touch /home/alice/.ssh/id_ed25519", true},
		{`sed -i "" -e s/a/b/ ~/.ssh/id_ed25519`, true},
		{"sed -i -e s/a/b/ /home/alice/.ssh/id_ed25519", true},
		{"mkdir -p ~/.ssh", false},
	}
	for _, test := range tests {
		input := sensitivePathShellInput(test.command)
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:              input,
			LegacyText:         input.Command,
			Connector:          connector,
			EnforcementCapable: true,
		})
		finding := findingWithID(findings, "PATH-SSH-DIR")
		if got := finding != nil; got != test.want {
			t.Errorf("%s: PATH-SSH-DIR = %t, want %t; findings=%v", test.command, got, test.want, FindingStrings(findings))
		}
		// A detection-only finding never reaches the alerts.
		if finding != nil && finding.enforcement == findingEnforcementDetectionOnly {
			t.Errorf("%s: PATH-SSH-DIR is detection-only", test.command)
		}
	}
}
