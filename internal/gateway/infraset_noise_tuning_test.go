// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestInfraSetAtomicNoisePosture(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		activeHome string
		present    []string
		absent     []string
		strictOnly bool
	}{
		{
			name: "generic sudoers mutation", command: `printf configured > /etc/sudoers.d/opsbot`,
			present: []string{"PATH-ETC-SUDOERS"}, strictOnly: true,
		},
		{
			name:    "exact unrestricted sudoers grant",
			command: `printf '%s\n' 'opsbot ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/opsbot`,
			present: []string{"privilege.sudoers_unrestricted_nopasswd"},
		},
		{
			name: "targeted shadow account check", command: `grep -q '^opsbot:' /etc/shadow`,
			absent: []string{"PATH-ETC-SHADOW"},
		},
		{
			name: "full shadow read", command: `cat /etc/shadow`,
			present: []string{"PATH-ETC-SHADOW"},
		},
		{
			name: "shadow mutation", command: `sed -i 's/^opsbot:/disabled:/' /etc/shadow`,
			present: []string{"PATH-ETC-SHADOW"},
		},
		{
			name: "ordinary ssh identity use", command: `ssh -i /home/alice/.ssh/id_ed25519 server.example`,
			activeHome: "/home/alice", absent: []string{"PATH-SSH-KEY"},
		},
		{
			name: "ssh private key content read", command: `cat /home/alice/.ssh/id_ed25519`,
			activeHome: "/home/alice", present: []string{"PATH-SSH-KEY"},
		},
		{
			name: "ordinary ssh metadata mutation", command: `touch /home/alice/.ssh/known_hosts`,
			activeHome: "/home/alice", absent: []string{"PATH-SSH-DIR"},
		},
		{
			name: "authorized keys mutation", command: `printf '%s\n' 'ssh-ed25519 AAAAfixture' >> /home/alice/.ssh/authorized_keys`,
			activeHome: "/home/alice", present: []string{"persistence.ssh_authorized_keys_command"},
		},
		{
			name: "ordinary sudo command", command: `sudo apt-get update`,
			absent: []string{"CMD-SUDO"},
		},
		{
			name: "sudo privilege discovery", command: `sudo -l`,
			present: []string{"CMD-SUDO"}, strictOnly: true,
		},
		{
			name: "sudo elevated shell", command: `sudo -u root /bin/bash`,
			present: []string{"CMD-SUDO"}, strictOnly: true,
		},
		{
			name: "crontab install", command: `crontab /tmp/jobs`,
			present: []string{"CMD-CRONTAB"}, strictOnly: true,
		},
	}

	for _, profile := range []string{"default", "permissive", "strict"} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			const connector = "infraset-noise"
			installToolCallCorpusProfileConnector(t, connector, profile)
			for _, test := range tests {
				test := test
				t.Run(test.name, func(t *testing.T) {
					input := actionfacts.Input{
						Tool: "shell", Command: test.command, CWD: "/repo",
						ActiveHome: test.activeHome, DialectHint: actionfacts.DialectPOSIX,
					}
					ids := findingIDs(dispatchTrustedAction(t.Context(), trustedActionRequest{
						Input: input, LegacyText: test.command, Connector: connector,
						EnforcementCapable: true,
					}))
					for _, ruleID := range test.present {
						want := !test.strictOnly || profile == "strict"
						if got := slices.Contains(ids, ruleID); got != want {
							t.Fatalf("%s present=%t, want %t; findings=%v", ruleID, got, want, ids)
						}
					}
					for _, ruleID := range test.absent {
						if slices.Contains(ids, ruleID) {
							t.Fatalf("unexpected %s finding: %v", ruleID, ids)
						}
					}
				})
			}
		})
	}
}

func TestBalancedMKFSRemainsVisibleAndNonblocking(t *testing.T) {
	const connector = "infraset-mkfs"
	installToolCallCorpusProfileConnector(t, connector, "default")
	input := actionfacts.Input{
		Tool: "shell", Command: `mkfs.ext4 /dev/sda`, CWD: "/repo",
		DialectHint: actionfacts.DialectPOSIX,
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: input.Command, Connector: connector,
		EnforcementCapable: true,
	})
	matched := findingWithID(findings, "CMD-MKFS")
	if matched == nil {
		t.Fatalf("CMD-MKFS finding missing: %+v", findings)
	}
	if matched.Severity != "HIGH" {
		t.Fatalf("balanced CMD-MKFS severity=%q, want HIGH alert posture", matched.Severity)
	}
	if matched.contributesToEnforcement() {
		t.Fatalf("balanced CMD-MKFS unexpectedly contributes to enforcement: %+v", matched)
	}
}

func TestBuiltInProfilesRetainDestructiveEvidenceWithoutUniversalBlocking(t *testing.T) {
	tests := []struct {
		name, command, ruleID string
	}{
		{"filesystem format", "mkfs.ext4 /dev/sda", "CMD-MKFS"},
		{"device wipe", "blkdiscard /dev/sdb", "CMD-DEVICE-WIPE"},
		{"access control weakening", "chmod 0777 /etc/sudoers", "CMD-CHMOD-WORLD"},
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		for _, test := range tests {
			t.Run(profile+"/"+test.name, func(t *testing.T) {
				connector := "destructive-evidence-" + profile
				installToolCallCorpusProfileConnector(t, connector, profile)
				input := actionfacts.Input{Tool: "shell", Command: test.command, CWD: "/repo"}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: test.command, Connector: connector,
					EnforcementCapable: true,
				})
				matched := findingWithID(findings, test.ruleID)
				if matched == nil {
					if test.ruleID == "CMD-CHMOD-WORLD" && profile != "strict" {
						return
					}
					t.Fatalf("%s finding missing: %+v", test.ruleID, findings)
				}
				if matched.contributesToEnforcement() {
					t.Fatalf("%s unexpectedly contributes to enforcement: %+v", test.ruleID, matched)
				}
			})
		}
	}
}

func TestStrictRoutineCommandPrecision(t *testing.T) {
	const connector = "strict-routine-command-precision"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	for _, command := range []string{
		"nc -lvp 5432",
		"git init /tmp/repo && git -C /tmp/repo remote add origin https://example.invalid/repo.git",
		"curl https://api.invalid/data | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
		"kubectl -n production exec pod/api -- curl -fsS http://127.0.0.1:8080/healthz",
		"rg -n history internal/gateway && git -C project status",
	} {
		input := actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo"}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: command, Connector: connector,
			EnforcementCapable: true,
		})
		for _, noisyID := range []string{
			"CMD-NETCAT-LISTEN", "source.git_remote_tamper", "CMD-PIPE-CURL",
			"lateral.workload_exec", "integrity.history_tamper",
		} {
			if findingWithID(findings, noisyID) != nil {
				t.Fatalf("command %q emitted %s: %+v", command, noisyID, findings)
			}
		}
	}
}

func TestNetcatListenerUsesExposureTaxonomy(t *testing.T) {
	rulePack := mustLoadRulePack(t, filepath.Join(guardrailPoliciesRoot(t), "strict"))
	for _, file := range rulePack.RuleFiles {
		for _, rule := range file.Rules {
			if rule.ID != "CMD-NETCAT-LISTEN" {
				continue
			}
			if rule.Title != "Netcat network-listener exposure" ||
				!slices.Contains(rule.Tags, "listener") || slices.Contains(rule.Tags, "reverse-shell") {
				t.Fatalf("unexpected listener taxonomy: %+v", rule)
			}
			return
		}
	}
	t.Fatal("CMD-NETCAT-LISTEN missing")
}

// TestHomeSpelledAuthorizedKeysWriteBlocks pins GAP-0892/0894/0896 on the
// default pack. A lone `echo k >> ~/.ssh/authorized_keys` lost its blocking
// finding because the tilde rewrite gave the path fact its "~" spelling back
// but not the redirect target, so the owner no longer tied the redirect to
// the path; every spelling and writer must block alike, and reads stay quiet.
func TestHomeSpelledAuthorizedKeysWriteBlocks(t *testing.T) {
	const connector = "home-spelled-authorized-keys"
	installToolCallCorpusProfileConnector(t, connector, "default")
	const rule = "persistence.ssh_authorized_keys_command"
	tests := []struct {
		name, command, cwd, home string
		write                    bool
	}{
		{"redirect", `echo dccert-block-marker >> ~/.ssh/authorized_keys`, "", "", true},
		{"home variable", `echo dccert-block-marker >> "$HOME/.ssh/authorized_keys"`, "", "", true},
		{"absolute", `echo dccert-block-marker >> /home/alice/.ssh/authorized_keys`, "", "", true},
		{"quoted suffix", `echo dccert-block-marker >> ~/".ssh/authorized_keys"`, "", "", true},
		{"mkdir and redirect", `mkdir -p ~/.ssh && echo dccert-block-marker >> ~/.ssh/authorized_keys`, "", "", true},
		{"tee", `echo dccert-block-marker | tee -a ~/.ssh/authorized_keys`, "", "", true},
		{"install", `install -m 600 marker.pub ~/.ssh/authorized_keys`, "", "", true},
		{"copy to second keys file", `cp marker.pub ~/.ssh/authorized_keys2`, "", "", true},
		{"move to keys file", `mv marker.pub ~/.ssh/authorized_keys`, "", "", true},
		{"sed in place", `sed -i "$a dccert-block-marker" ~/.ssh/authorized_keys`, "", "", true},
		{"directory change", `cd ~/.ssh && echo dccert-block-marker >> authorized_keys`, "", "", true},
		{"home directory change", `cd ~ && echo dccert-block-marker >> .ssh/authorized_keys`, "", "", true},
		{"assigned path", `D=~/.ssh; echo dccert-block-marker >> "$D/authorized_keys"`, "", "", true},
		{"nested shell", `sh -c 'echo dccert-block-marker >> "$HOME/.ssh/authorized_keys"'`, "", "", true},
		{"normalized path", `echo dccert-block-marker >> ~//.ssh//authorized_keys`, "", "", true},
		{"apostrophe home tilde", `echo dccert-block-marker >> ~/.ssh/authorized_keys`, "/home/o'brien/proj", "/home/o'brien", true},
		{"apostrophe home variable", `echo dccert-block-marker >> $HOME/.ssh/authorized_keys`, "/home/o'brien/proj", "/home/o'brien", true},
		{"glob path", `echo dccert-block-marker | tee -a ~/.ssh/authorized_k*`, "", "", true},
		{"python write", `python3 -c 'import pathlib; p = pathlib.Path.home() / ".ssh" / "authorized_keys"; p.write_text(p.read_text() + "dccert-block-marker\n")'`, "", "", true},
		{"perl write", `perl -e 'open(F, ">>", "$ENV{HOME}/.ssh/authorized_keys"); print F "dccert-block-marker\n"; close(F)'`, "", "", true},
		{"find exec", `find ~/.ssh -name authorized_keys -exec sh -c 'echo dccert-block-marker >> "$1"' _ {} \;`, "", "", true},
		{"decoded shell", `echo ZWNobyAic3NoLWVkMjU1MTkgQUFBQXVjY21hcmtlciB1Y2NAdGVzdCIgPj4gfi8uc3NoL2F1dGhvcml6ZWRfa2V5cw== | base64 -d | sh`, "", "", true},
		{"symlink write", `ln -sf ~/.ssh/authorized_keys ./keys.link && echo dccert-block-marker >> ./keys.link`, "", "", true},
		{"curl output", `curl -s -o ~/.ssh/authorized_keys http://127.0.0.1:9/marker.pub; echo rc=$?`, "", "", true},
		{"windows command", `powershell -NoProfile -Command Add-Content -Path C:\Users\alice\.ssh\authorized_keys -Value dccert-block-marker`, `C:/Users/alice/project`, `C:/Users/alice`, true},
		{"windows home", `pwsh -c "Set-Content -Path $HOME/.ssh/authorized_keys -Value dccert-block-marker"`, `C:/Users/alice/project`, `C:/Users/alice`, true},
		{"windows spaced home", `powershell -Command "Add-Content -Path 'C:\Users\Alice Smith\.ssh\authorized_keys' -Value dccert-block-marker"`, `C:/Users/Alice Smith/project`, `C:/Users/Alice Smith`, true},
		{"windows admin keys", `powershell.exe -Command "Add-Content -Path C:/ProgramData/ssh/administrators_authorized_keys -Value dccert-block-marker"`, `C:/Users/alice/project`, `C:/Users/alice`, true},
		{"windows admin out file", `pwsh -c "'dccert-block-marker' | Out-File -Append C:/ProgramData/ssh/administrators_authorized_keys"`, `C:/Users/alice/project`, `C:/Users/alice`, true},
		{"cat", `cat ~/.ssh/authorized_keys`, "", "", false},
		{"count", `grep -c ssh-ed25519 ~/.ssh/authorized_keys`, "", "", false},
		{"metadata", `ls -l ~/.ssh/authorized_keys`, "", "", false},
		{"diff", `diff ~/.ssh/authorized_keys marker.pub | head -5`, "", "", false},
		{"line count", `wc -l ~/.ssh/authorized_keys`, "", "", false},
		{"local copy", `cp ~/.ssh/authorized_keys /var/tmp/authorized-keys-copy.txt`, "", "", false},
		{"mention", `echo "check ~/.ssh/authorized_keys" > notes.txt`, "", "", false},
	}
	for _, test := range tests {
		cwd, home := test.cwd, test.home
		if cwd == "" {
			cwd = "/repo"
		}
		if home == "" {
			home = "/home/alice"
		}
		args := []byte(`{"command":` + strconv.Quote(test.command) + `}`)
		input := actionfacts.Input{
			Tool: "Bash", Args: args, CWD: cwd,
			ActiveHome: home, DialectHint: actionfacts.DialectPOSIX,
		}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: string(args), Connector: connector,
			EnforcementCapable: true,
		})
		if !test.write {
			if len(findings) != 0 {
				t.Errorf("%s: unexpected findings %v", test.name, findingIDs(findings))
			}
			continue
		}
		enforced := 0
		for _, finding := range findings {
			if finding.contributesToEnforcement() {
				enforced++
				if finding.RuleID != rule {
					t.Errorf("%s: unexpected enforced rule %s", test.name, finding.RuleID)
				}
			}
		}
		if enforced != 1 {
			t.Errorf("%s: findings %v, want one enforced %s", test.name, findingIDs(findings), rule)
		}
	}
}
