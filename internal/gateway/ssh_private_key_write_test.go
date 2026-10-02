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
	}
	for _, test := range tests {
		input := sensitivePathShellInput(test.command)
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:              input,
			LegacyText:         input.Command,
			Connector:          connector,
			EnforcementCapable: true,
		})
		if got := findingWithID(findings, "PATH-SSH-DIR") != nil; got != test.want {
			t.Errorf("%s: PATH-SSH-DIR = %t, want %t; findings=%v", test.command, got, test.want, FindingStrings(findings))
		}
	}
}
