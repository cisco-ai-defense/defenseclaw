// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

var reconImpactExpressionsForTest = map[string]string{
	"CMD-RM-RF":                             semanticRecursiveDeleteExpression,
	"CMD-SUDO":                              semanticSudoDiscoveryElevationExpression,
	"CMD-CHMOD-WORLD":                       semanticAccessControlExpression,
	"CMD-DD-IF":                             semanticDDDiskWriteExpression,
	"CMD-MKFS":                              semanticFilesystemWipeExpression,
	"recon.network_sweep":                   semanticNetworkSweepExpression,
	"privilege.container_host_escape":       semanticContainerHostEscapeExpression,
	"impact.cryptomining_launch":            semanticCryptominingExpression,
	"impact.mass_process_termination":       semanticMassProcessTerminationExpression,
	"persistence.privileged_account_change": semanticPrivilegedAccountExpression,
}

func TestSemanticReconImpactExpressionsCompile(t *testing.T) {
	t.Parallel()

	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	for ruleID, expression := range reconImpactExpressionsForTest {
		ruleID, expression := ruleID, expression
		t.Run(ruleID, func(t *testing.T) {
			if _, code := compiler.Compile(expression); code != semantic.CompileOK {
				t.Fatalf("compile code = %q", code)
			}
		})
	}
}

func TestGeneratedDefaultSemanticRulesUseRegisteredOwners(t *testing.T) {
	t.Parallel()

	generation := snapshotRulePackGeneration("")
	if generation == nil {
		t.Fatal("default rule generation is unavailable")
	}
	compiled := make(map[string]compiledSemanticRule, len(generation.semanticRules))
	for _, candidate := range generation.semanticRules {
		compiled[candidate.rule.ID] = candidate
	}
	for _, owners := range []map[string]semanticOwner{
		semanticReconImpactOwners,
		semanticIntegrityPersistenceOwners,
	} {
		for ruleID := range owners {
			candidate, ok := compiled[ruleID]
			if !ok {
				t.Fatalf("default semantic rule %q is missing", ruleID)
			}
			if candidate.owner.prerequisite == nil {
				t.Fatalf("default semantic rule %q compiled before owner registration", ruleID)
			}
		}
	}
}

func TestSemanticReconImpactPrerequisiteBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		ruleID string
		input  actionfacts.Input
		want   bool
		status actionfacts.ParseStatus
	}{
		{
			name:   "recursive delete root",
			ruleID: "CMD-RM-RF",
			input:  reconImpactCommand("rm -rf /"),
			want:   true,
		},
		{
			name:   "recursive delete active home",
			ruleID: "CMD-RM-RF",
			input:  reconImpactCommand("rm --recursive --force /home/alice"),
			want:   true,
		},
		{
			name:   "recursive delete scoped tree",
			ruleID: "CMD-RM-RF",
			input:  reconImpactCommand("rm -rf /tmp/build-output"),
		},
		{
			name:   "recursive delete preview",
			ruleID: "CMD-RM-RF",
			input: actionfacts.Input{
				Tool:        "powershell",
				Argv:        []string{"Remove-Item", "-Recurse", "-Force", "-Path", `C:\Users\Alice`, "-WhatIf"},
				ActiveHome:  `C:\Users\Alice`,
				DialectHint: actionfacts.DialectPowerShell,
			},
		},
		{
			name:   "sudo discovery",
			ruleID: "CMD-SUDO",
			input:  reconImpactCommand("sudo -l"),
			want:   true,
		},
		{
			name:   "sudo elevated shell",
			ruleID: "CMD-SUDO",
			input:  reconImpactCommand("sudo -u root /bin/bash"),
			want:   true,
		},
		{
			name:   "sudo host option elevated shell",
			ruleID: "CMD-SUDO",
			input:  reconImpactCommand("sudo -h builder /bin/bash"),
			want:   true,
		},
		{
			name:   "sudo reordered discovery options",
			ruleID: "CMD-SUDO",
			input:  reconImpactCommand("sudo -l -U alice"),
			want:   true,
			status: actionfacts.StatusPartial,
		},
		{
			name:   "sudo reordered shell options",
			ruleID: "CMD-SUDO",
			input:  reconImpactCommand("sudo -s -u root"),
			want:   true,
			status: actionfacts.StatusPartial,
		},
		{
			name:   "sudo ordinary command",
			ruleID: "CMD-SUDO",
			input:  reconImpactCommand("sudo -n apt-get update"),
			status: actionfacts.StatusPartial,
		},
		{
			name:   "root setgid discovery",
			ruleID: "CMD-SUDO",
			input:  reconImpactCommand("find /usr -perm /2000 -type f"),
			want:   true,
		},
		{
			name:   "root capability discovery",
			ruleID: "CMD-SUDO",
			input:  reconImpactCommand("getcap --recursive /"),
			want:   true,
		},
		{
			name:   "project capability discovery",
			ruleID: "CMD-SUDO",
			input:  reconImpactCommand("getcap -r /repo"),
		},
		{
			name:   "setid executable",
			ruleID: "CMD-CHMOD-WORLD",
			input:  reconImpactCommand("chmod 4755 /usr/local/bin/helper"),
			want:   true,
		},
		{
			name:   "symbolic setid executable",
			ruleID: "CMD-CHMOD-WORLD",
			input:  reconImpactCommand("chmod u+s /usr/local/bin/helper"),
			want:   true,
		},
		{
			name:   "symbolic protected world write",
			ruleID: "CMD-CHMOD-WORLD",
			input:  reconImpactCommand("chmod o+w /etc/shadow"),
			want:   true,
		},
		{
			name:   "symbolic ordinary executable",
			ruleID: "CMD-CHMOD-WORLD",
			input:  reconImpactCommand("chmod u+x /tmp/helper"),
		},
		{
			name:   "protected secret made public",
			ruleID: "CMD-CHMOD-WORLD",
			input:  reconImpactCommand("chmod 0644 /etc/shadow"),
			want:   true,
		},
		{
			name:   "workspace permission change",
			ruleID: "CMD-CHMOD-WORLD",
			input:  reconImpactCommand("chmod 0777 /tmp/build-output"),
		},
		{
			name:   "protected ownership change",
			ruleID: "CMD-CHMOD-WORLD",
			input:  reconImpactCommand("chown attacker /etc/sudoers"),
			want:   true,
		},
		{
			name:   "setid install",
			ruleID: "CMD-CHMOD-WORLD",
			input:  reconImpactCommand("install -m 4755 helper /usr/local/bin/helper"),
			want:   true,
		},
		{
			name:   "dangerous file capability",
			ruleID: "CMD-CHMOD-WORLD",
			input:  reconImpactCommand("setcap cap_setuid+ep /usr/local/bin/helper"),
			want:   true,
		},
		{
			name:   "protected acl mutation",
			ruleID: "CMD-CHMOD-WORLD",
			input:  reconImpactCommand("setfacl -m u:attacker:rw /etc/shadow"),
			want:   true,
		},
		{
			name:   "protected acl removal",
			ruleID: "CMD-CHMOD-WORLD",
			input:  reconImpactCommand("setfacl -x u:attacker /etc/shadow"),
			want:   true,
		},
		{
			name:   "recursive active ssh group change",
			ruleID: "CMD-CHMOD-WORLD",
			input:  reconImpactCommand("chgrp -R developers /home/alice/.ssh"),
			want:   true,
		},
		{
			name:   "piped powershell acl mutation",
			ruleID: "CMD-CHMOD-WORLD",
			input: actionfacts.Input{
				Tool:        "powershell",
				Command:     "Get-Acl C:\\Temp\\source | Set-Acl -Path C:\\Windows\\System32\\config\\SAM",
				ActiveHome:  `C:\Users\Alice`,
				DialectHint: actionfacts.DialectPowerShell,
			},
			want: true,
		},
		{
			name:   "dd block overwrite",
			ruleID: "CMD-DD-IF",
			input:  reconImpactCommand("dd if=/tmp/inert.bin of=/dev/sda bs=4M"),
			want:   true,
		},
		{
			name:   "dd device read",
			ruleID: "CMD-DD-IF",
			input:  reconImpactCommand("dd if=/dev/sda of=/tmp/backup.img"),
		},
		{
			name:   "filesystem format",
			ruleID: "CMD-MKFS",
			input:  reconImpactCommand("mkfs.ext4 /dev/sda"),
			want:   true,
		},
		{
			name:   "filesystem format preview",
			ruleID: "CMD-MKFS",
			input:  reconImpactCommand("mkfs.ext4 -n /dev/sda"),
		},
		{
			name:   "device shred",
			ruleID: "CMD-MKFS",
			input:  reconImpactCommand("shred -n 1 /dev/sda"),
			want:   true,
		},
		{
			name:   "device cryptsetup erase",
			ruleID: "CMD-MKFS",
			input:  reconImpactCommand("cryptsetup luksErase /dev/sda1"),
			want:   true,
		},
		{
			name:   "device nvme sanitize",
			ruleID: "CMD-MKFS",
			input:  reconImpactCommand("nvme sanitize /dev/nvme0n1"),
			want:   true,
		},
		{
			name:   "device parted label",
			ruleID: "CMD-MKFS",
			input:  reconImpactCommand("parted /dev/sda mklabel gpt"),
			want:   true,
		},
		{
			name:   "macos bare disk erase",
			ruleID: "CMD-MKFS",
			input:  reconImpactCommand("diskutil eraseDisk APFS Empty disk2"),
			want:   true,
		},
		{
			name:   "windows oem disk clear",
			ruleID: "CMD-MKFS",
			input: actionfacts.Input{
				Tool:        "powershell",
				Command:     "Clear-Disk -Number 1 -RemoveOEM",
				DialectHint: actionfacts.DialectPowerShell,
			},
			want: true,
		},
		{
			name:   "device tee",
			ruleID: "CMD-MKFS",
			input:  reconImpactCommand("tee /dev/sda"),
			want:   true,
		},
		{
			name:   "device redirect",
			ruleID: "CMD-MKFS",
			input:  reconImpactCommand("printf x > /dev/sda"),
			want:   true,
		},
		{
			name:   "ordinary shred target",
			ruleID: "CMD-MKFS",
			input:  reconImpactCommand("shred -n 1 /tmp/fixture.img"),
			status: actionfacts.StatusPartial,
		},
		{
			name:   "network range",
			ruleID: "recon.network_sweep",
			input:  reconImpactCommand("nmap 192.0.2.0/24"),
			want:   true,
		},
		{
			name:   "network single address",
			ruleID: "recon.network_sweep",
			input:  reconImpactCommand("nmap 192.0.2.1/32"),
		},
		{
			name:   "privileged root bind",
			ruleID: "privilege.container_host_escape",
			input:  reconImpactCommand("docker run --privileged -v /:/host ubuntu:24.04"),
			want:   true,
		},
		{
			name:   "privileged true root bind",
			ruleID: "privilege.container_host_escape",
			input:  reconImpactCommand("docker run --privileged=true -v /:/host ubuntu:24.04"),
			want:   true,
		},
		{
			name:   "privileged uppercase true root bind",
			ruleID: "privilege.container_host_escape",
			input:  reconImpactCommand("docker run --privileged=TRUE -v /:/host ubuntu:24.04"),
			want:   true,
		},
		{
			name:   "privileged numeric true root bind",
			ruleID: "privilege.container_host_escape",
			input:  reconImpactCommand("docker run --privileged=1 -v /:/host ubuntu:24.04"),
			want:   true,
		},
		{
			name:   "privileged false root bind",
			ruleID: "privilege.container_host_escape",
			input:  reconImpactCommand("docker run --privileged=false -v /:/host ubuntu:24.04"),
		},
		{
			name:   "privileged numeric false root bind",
			ruleID: "privilege.container_host_escape",
			input:  reconImpactCommand("docker run --privileged=0 -v /:/host ubuntu:24.04"),
		},
		{
			name:   "privileged final false root bind",
			ruleID: "privilege.container_host_escape",
			input:  reconImpactCommand("docker run --privileged=true --privileged=false -v /:/host ubuntu:24.04"),
		},
		{
			name:   "privileged final true root bind",
			ruleID: "privilege.container_host_escape",
			input:  reconImpactCommand("docker run --privileged=false --privileged=t -v /:/host ubuntu:24.04"),
			want:   true,
		},
		{
			name:   "privileged invalid boolean root bind",
			ruleID: "privilege.container_host_escape",
			input:  reconImpactCommand("docker run --privileged=maybe -v /:/host ubuntu:24.04"),
			status: actionfacts.StatusPartial,
		},
		{
			name:   "option text after image",
			ruleID: "privilege.container_host_escape",
			input:  reconImpactCommand("docker run -v /:/host ubuntu:24.04 --privileged"),
		},
		{
			name:   "miner image",
			ruleID: "impact.cryptomining_launch",
			input:  reconImpactCommand("docker run --rm registry.invalid/tools/xmrig:latest"),
			want:   true,
		},
		{
			name:   "miner entrypoint",
			ruleID: "impact.cryptomining_launch",
			input:  reconImpactCommand("podman run --entrypoint /opt/xmrig alpine:3"),
			want:   true,
		},
		{
			name:   "miner substring",
			ruleID: "impact.cryptomining_launch",
			input:  reconImpactCommand("docker run registry.invalid/tools/xmrig-exporter:latest"),
		},
		{
			name:   "kill all",
			ruleID: "impact.mass_process_termination",
			input:  reconImpactCommand("kill -9 -1"),
			want:   true,
			status: actionfacts.StatusPartial,
		},
		{
			name:   "kill one pid",
			ruleID: "impact.mass_process_termination",
			input:  reconImpactCommand("kill -9 123"),
		},
		{
			name:   "taskkill wildcard",
			ruleID: "impact.mass_process_termination",
			input: actionfacts.Input{
				Tool:        "cmd",
				Argv:        []string{"taskkill", "/F", "/IM", "*"},
				DialectHint: actionfacts.DialectCMD,
			},
			want: true,
		},
		{
			name:   "uid zero account",
			ruleID: "persistence.privileged_account_change",
			input:  reconImpactCommand("useradd --uid 0 --non-unique backup"),
			want:   true,
		},
		{
			name:   "privileged group",
			ruleID: "persistence.privileged_account_change",
			input:  reconImpactCommand("usermod -aG developers,sudo agent"),
			want:   true,
		},
		{
			name:   "ordinary account",
			ruleID: "persistence.privileged_account_change",
			input:  reconImpactCommand("useradd buildbot"),
		},
		{
			name:   "adduser uid zero",
			ruleID: "persistence.privileged_account_change",
			input:  reconImpactCommand("adduser --uid 0 backup"),
			want:   true,
		},
		{
			name:   "groupmems sudo add",
			ruleID: "persistence.privileged_account_change",
			input:  reconImpactCommand("groupmems -g sudo -a agent"),
			want:   true,
		},
		{
			name:   "macos admin group add",
			ruleID: "persistence.privileged_account_change",
			input:  reconImpactCommand("dseditgroup -a agent -t user admin"),
			want:   true,
		},
		{
			name:   "macos group membership append",
			ruleID: "persistence.privileged_account_change",
			input:  reconImpactCommand("dscl . -append /Groups/admin GroupMembership agent"),
			want:   true,
		},
		{
			name:   "windows net1 administrator add",
			ruleID: "persistence.privileged_account_change",
			input: actionfacts.Input{
				Tool:        "cmd",
				Argv:        []string{"net1", "localgroup", "Administrators", "agent", "/add"},
				DialectHint: actionfacts.DialectCMD,
			},
			want: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := actionfacts.Analyze(test.input)
			wantStatus := test.status
			if wantStatus == "" {
				wantStatus = actionfacts.StatusComplete
			}
			if facts.Parse.Status != wantStatus {
				t.Fatalf("parse = %#v, want %q; facts=%#v", facts.Parse, wantStatus, facts)
			}
			owner, ok := semanticReconImpactOwners[test.ruleID]
			if !ok {
				t.Fatalf("owner %q is missing", test.ruleID)
			}
			if got := owner.eligible(facts); got != test.want {
				t.Fatalf("eligible = %t, want %t; facts=%#v", got, test.want, facts)
			}
			if !test.want || !facts.Authoritative() {
				return
			}
			compiler, err := semantic.NewCompiler()
			if err != nil {
				t.Fatal(err)
			}
			program, code := compiler.Compile(
				reconImpactExpressionsForTest[test.ruleID],
			)
			if code != semantic.CompileOK {
				t.Fatalf("compile code = %q", code)
			}
			projected, projectionCode := semantic.Project(facts)
			if projectionCode != semantic.ProjectionOK {
				t.Fatalf("projection code = %q", projectionCode)
			}
			result, evalCode := program.EvalBool(context.Background(), projected)
			if evalCode != semantic.EvalOK || !result.Matched {
				t.Fatalf("CEL = %#v/%q, want match", result, evalCode)
			}
		})
	}
}

func TestSudoFallbackDispositionRouting(t *testing.T) {
	const connector = "sudo-fallback-disposition-test"
	installDefaultProfileConnector(t, connector)

	tests := []struct {
		name, command  string
		want, fallback bool
	}{
		{"joined preserve env shell", "sudo --preserve-env=PATH /bin/bash", true, false},
		{"joined preserve env ordinary command", "sudo --preserve-env=PATH apt-get update", false, false},
		{"determinate ordinary command", "sudo -n apt-get update", false, false},
		{"unknown option ordinary command", "sudo --future-option apt-get update", false, false},
		{"determinate privilege discovery", "sudo -l", true, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := reconImpactCommand(test.command)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:              input,
				LegacyText:         test.command,
				Connector:          connector,
				EnforcementCapable: true,
			})
			var matched *RuleFinding
			count := 0
			for index := range findings {
				if findings[index].RuleID == "CMD-SUDO" {
					matched = &findings[index]
					count++
				}
			}
			wantCount := 0
			if test.want {
				wantCount = 1
			}
			if count != wantCount {
				t.Fatalf(
					"CMD-SUDO count=%d, want %d: %v",
					count,
					wantCount,
					FindingStrings(findings),
				)
			}
			if matched != nil {
				if !matched.contributesToEnforcement() {
					t.Fatalf("CMD-SUDO is not enforcement eligible: %+v", *matched)
				}
				if got := matched.Evidence != ""; got != test.fallback {
					t.Fatalf(
						"fallback evidence=%t, want %t: %+v",
						got,
						test.fallback,
						*matched,
					)
				}
			}
		})
	}

	joinedPreserveEnv := actionfacts.Analyze(
		reconImpactCommand("sudo --preserve-env=PATH /bin/bash"),
	)
	owner := semanticReconImpactOwners["CMD-SUDO"]
	if !owner.eligible(joinedPreserveEnv) {
		t.Fatalf(
			"joined --preserve-env shell lost semantic ownership: %+v",
			joinedPreserveEnv,
		)
	}
}

func TestSemanticReconImpactFallbackProofBoundaries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input actionfacts.Input
		proof func(actionfacts.Input, actionfacts.Facts) bool
		want  bool
	}{
		{
			name:  "pid one namespace",
			input: reconImpactCommand("nsenter --target 1 --mount /bin/sh"),
			proof: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
				return hostNamespaceEntryFallbackProof(facts)
			},
			want: true,
		},
		{
			name:  "ordinary namespace",
			input: reconImpactCommand("nsenter --target 42 --mount /bin/sh"),
			proof: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
				return hostNamespaceEntryFallbackProof(facts)
			},
		},
		{
			name:  "kubernetes exec",
			input: reconImpactCommand("kubectl -n prod exec pod/api -- sh"),
			proof: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
				return workloadExecFallbackProof(facts)
			},
			want: true,
		},
		{
			name:  "kubernetes list",
			input: reconImpactCommand("kubectl -n prod get pod/api"),
			proof: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
				return workloadExecFallbackProof(facts)
			},
		},
		{
			name:  "local container exec",
			input: reconImpactCommand("docker exec api sh"),
			proof: func(_ actionfacts.Input, facts actionfacts.Facts) bool {
				return workloadExecFallbackProof(facts)
			},
		},
		{
			name:  "shell fork bomb",
			input: reconImpactCommand(":(){ :|:& };:"),
			proof: forkBombFallbackProof,
			want:  true,
		},
		{
			name:  "quoted fork bomb documentation",
			input: reconImpactCommand(`printf '%s\n' ':(){ :|:& };:'`),
			proof: forkBombFallbackProof,
		},
		{
			name: "perl fork bomb",
			input: actionfacts.Input{
				Tool: "exec",
				Argv: []string{"perl", "-e", "fork while fork"},
			},
			proof: forkBombFallbackProof,
			want:  true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := actionfacts.Analyze(test.input)
			if got := test.proof(test.input, facts); got != test.want {
				t.Fatalf(
					"proof = %t, want %t; parse=%#v facts=%#v",
					got,
					test.want,
					facts.Parse,
					facts,
				)
			}
		})
	}
}

func TestSemanticReconImpactOwnerAliasBoundary(t *testing.T) {
	t.Parallel()

	rmOwner := semanticReconImpactOwners["CMD-RM-RF"]
	rmOwner.id = "CMD-RM-RF"
	if got := rmOwner.claimedIDs(true); !sameStrings(
		got,
		[]string{
			"CMD-RM-RF",
			"CMD-WIN-REMOVE-ITEM-RF",
			"CMD-WIN-RMDIR-SQ",
		},
	) {
		t.Fatalf("recursive-delete aliases = %v", got)
	}
	chmodOwner := semanticReconImpactOwners["CMD-CHMOD-WORLD"]
	chmodOwner.id = "CMD-CHMOD-WORLD"
	if got := chmodOwner.claimedIDs(true); !sameStrings(
		got,
		[]string{"CMD-CHMOD-WORLD", "CMD-CHOWN-ROOT"},
	) {
		t.Fatalf("access-control aliases = %v", got)
	}
}

func reconImpactCommand(command string) actionfacts.Input {
	return actionfacts.Input{
		Tool:       "exec",
		Command:    command,
		CWD:        "/workspace",
		ActiveHome: "/home/alice",
	}
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
