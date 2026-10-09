// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

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

// GAP-0912: under a Windows home every ~, $HOME, $env:USERPROFILE and
// %USERPROFILE% form of an SSH path was partial with no finding, so an
// authorized_keys append ran and a private key read left no alert, while the
// same commands under a POSIX home and the spelled-out Windows paths were
// judged. They are now judged as the spelled-out paths are.
func TestWindowsHomeSSHPathsAreJudgedLikeSpelledOutPaths(t *testing.T) {
	const connector = "windows-home-ssh-paths"
	installToolCallCorpusProfileConnector(t, connector, "default")
	const (
		authorizedKeys = "persistence.ssh_authorized_keys_command"
		privateKey     = "PATH-SSH-KEY"
	)
	tests := []struct {
		tool, command, rule string
		block               bool
	}{
		{"Bash", "echo k >> ~/.ssh/authorized_keys", authorizedKeys, true},
		{"Bash", `echo k >> "$HOME/.ssh/authorized_keys"`, authorizedKeys, true},
		{"Bash", "cat ~/.ssh/id_rsa", privateKey, false},
		{"powershell", `Add-Content -Path $HOME\.ssh\authorized_keys -Value k`, authorizedKeys, true},
		{"powershell", `echo k >> "$env:USERPROFILE\.ssh\authorized_keys"`, authorizedKeys, true},
		{"powershell", `Get-Content ~\.ssh\id_rsa`, privateKey, false},
		{"cmd", `type %USERPROFILE%\.ssh\id_rsa`, privateKey, false},
		{"powershell", `Get-Content $HOME\project\notes.txt`, "", false},
		{"Bash", "cat ~/project/notes.txt", "", false},
	}
	for _, test := range tests {
		args := []byte(`{"command":` + strconv.Quote(test.command) + `}`)
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:              actionfacts.Input{Tool: test.tool, Args: args, CWD: `C:\Users\alice\project`, ActiveHome: `C:\Users\alice`},
			LegacyText:         string(args),
			Connector:          connector,
			EnforcementCapable: true,
		})
		if test.rule == "" {
			if len(findings) != 0 {
				t.Errorf("%s %q: findings=%v, want none", test.tool, test.command, FindingStrings(findings))
			}
			continue
		}
		finding := findingWithID(findings, test.rule)
		switch {
		case finding == nil:
			t.Errorf("%s %q: no %s; findings=%v", test.tool, test.command, test.rule, FindingStrings(findings))
		case finding.contributesToEnforcement() != test.block:
			t.Errorf("%s %q: %s blocks = %t, want %t", test.tool, test.command, test.rule, !test.block, test.block)
		case !test.block && finding.enforcement != findingEnforcementAlertOnly:
			t.Errorf("%s %q: %s is not an alert", test.tool, test.command, test.rule)
		}
	}
}
