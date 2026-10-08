// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"slices"
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
	tests := []struct {
		command, rule string
		enforced      bool
	}{
		{`echo k >> ~/.ssh/authorized_keys`, "persistence.ssh_authorized_keys_command", true},
		{`echo "ssh-ed25519 AAAAfixture m@t" >> ~/.ssh/authorized_keys`, "persistence.ssh_authorized_keys_command", true},
		{`echo k >> "$HOME/.ssh/authorized_keys"`, "persistence.ssh_authorized_keys_command", true},
		{`echo k >> /home/alice/.ssh/authorized_keys`, "persistence.ssh_authorized_keys_command", true},
		{`echo k >> ~/".ssh/authorized_keys"`, "persistence.ssh_authorized_keys_command", true},
		{`mkdir -p ~/.ssh && echo k >> ~/.ssh/authorized_keys`, "persistence.ssh_authorized_keys_command", true},
		{`echo k > ~/.ssh/authorized_keys`, "persistence.ssh_authorized_keys_command", true},
		{`echo k | tee -a ~/.ssh/authorized_keys`, "persistence.ssh_authorized_keys_command", true},
		{`cat ~/.ssh/authorized_keys`, "", false},
		{`grep -c ssh-ed25519 ~/.ssh/authorized_keys`, "", false},
		{`echo k >> ~/notes.txt`, "", false},
	}
	for _, test := range tests {
		input := actionfacts.Input{
			Tool: "bash", Command: test.command, CWD: "/repo",
			ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX,
		}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: test.command, Connector: connector,
			EnforcementCapable: true,
		})
		if test.rule == "" {
			if len(findings) != 0 {
				t.Errorf("%q: unexpected findings %v", test.command, findingIDs(findings))
			}
			continue
		}
		if len(findings) != 1 || findings[0].RuleID != test.rule ||
			findings[0].contributesToEnforcement() != test.enforced {
			t.Errorf("%q: findings %v, want only %s enforced=%t", test.command, findingIDs(findings), test.rule, test.enforced)
		}
	}
}
