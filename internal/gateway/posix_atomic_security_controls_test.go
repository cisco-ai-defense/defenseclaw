// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	pamPasswordCaptureRuleID = "credential.pam_password_capture"
	posixHardeningRuleID     = "tamper.posix_logging_hardening_disable"
	linuxSecurityRuleID      = "tamper.linux_security_control_disable"
)

func TestPOSIXAtomicSecurityControlsProfilePosture(t *testing.T) {
	positives := []struct {
		name    string
		ruleID  string
		command string
	}{
		{
			name: "pam password capture", ruleID: pamPasswordCaptureRuleID,
			command: `echo "session required pam_tty_audit.so enable=* log_passwd" >> /etc/pam.d/sshd`,
		},
		{
			name: "journald storage none", ruleID: posixHardeningRuleID,
			command: `sed -i 's/Storage=auto/Storage=none/' /etc/systemd/journald.conf`,
		},
		{
			name: "freebsd syslogd disabled", ruleID: posixHardeningRuleID,
			command: "service syslogd stop\nsysrc syslogd_enable=\"NO\"",
		},
		{
			name: "aslr disabled", ruleID: posixHardeningRuleID,
			command: `sysctl -w kernel.randomize_va_space=0`,
		},
		{
			name: "freebsd pf disabled", ruleID: posixHardeningRuleID,
			command: "service pf stop\nservice pf disable",
		},
		{
			name: "ufw logging off", ruleID: posixHardeningRuleID,
			command: `ufw logging off`,
		},
		{
			name: "legacy auditd stop", ruleID: linuxSecurityRuleID,
			command: `service auditd stop`,
		},
		{
			name: "legacy auditd stop through sudo", ruleID: linuxSecurityRuleID,
			command: `sudo service auditd stop`,
		},
	}
	profiles := []struct {
		name     string
		action   string
		severity string
	}{
		{name: "default", action: "alert", severity: "HIGH"},
		{name: "permissive", action: "alert", severity: "HIGH"},
		{name: "strict", action: "block", severity: "CRITICAL"},
	}

	for _, profile := range profiles {
		profile := profile
		t.Run(profile.name, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile.name)
			for _, positive := range positives {
				positive := positive
				t.Run(positive.name, func(t *testing.T) {
					input := actionfacts.Input{
						Tool: "shell", Command: positive.command, CWD: "/repo",
						DialectHint: actionfacts.DialectPOSIX,
					}
					facts := actionfacts.Analyze(input)
					proof, owned := trustedSemanticOwnerFindingProof(positive.ruleID, input, facts)
					if !owned || !proof.authorizes(positive.ruleID) {
						t.Fatalf("exact owner did not authorize proof=%+v facts=%+v", proof, facts)
					}

					cfg := &config.Config{}
					cfg.Guardrail.Mode = "action"
					cfg.Guardrail.Connector = connector
					cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile.name)
					response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
						HookEventName: "PreToolUse",
						ToolName:      "shell",
						CWD:           "/repo",
						ToolInput: map[string]interface{}{
							"command": positive.command,
						},
					})
					if response.Action != profile.action || response.RawAction != profile.action ||
						response.Severity != profile.severity ||
						!findingStringHasRuleID(response.Findings, positive.ruleID) {
						t.Fatalf("response=%+v want %s/%s with %s", response, profile.action, profile.severity, positive.ruleID)
					}
					if positive.ruleID == pamPasswordCaptureRuleID &&
						findingStringHasRuleID(response.Findings, "CMD-ETC-WRITE") {
						t.Fatalf("specific PAM proof retained noisy generic write finding: %+v", response)
					}
				})
			}
		})
	}
}

func TestPOSIXSystemLogBoundedFallbackProfilePosture(t *testing.T) {
	commands := []string{
		`sudo truncate -s 0 /var/log/auth.log 2>/dev/null || true`,
		`/usr/bin/truncate -s 0 /var/log/auth.log/current.log 2>/dev/null || true`,
		"chattr -i /var/log/audit/audit.log.1 2>/dev/null;\ntruncate -s 0 /var/log/audit/audit.log.1",
	}
	profiles := []struct {
		name     string
		action   string
		severity string
	}{
		{name: "default", action: "allow", severity: "HIGH"},
		{name: "permissive", action: "allow", severity: "HIGH"},
		{name: "strict", action: "allow", severity: "CRITICAL"},
	}
	for _, profile := range profiles {
		t.Run(profile.name, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile.name)
			for _, command := range commands {
				rawFindings := scanTrustedRulesForProfile(t, profile.name, command, "shell")
				if findingWithID(rawFindings, "tamper.posix_system_log_destruction") == nil {
					t.Fatalf("command=%q did not produce the bounded fallback candidate", command)
				}
				input := actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", DialectHint: actionfacts.DialectPOSIX}
				filtered := filterExactFallbackFindings(rawFindings, input, actionfacts.Analyze(input), true)
				if finding := findingWithID(filtered, "tamper.posix_system_log_destruction"); finding == nil || finding.contributesToEnforcement() {
					t.Fatalf("command=%q bounded fallback finding=%+v", command, finding)
				}
				hookArgs, err := json.Marshal(map[string]interface{}{"command": command})
				if err != nil {
					t.Fatal(err)
				}
				hookInput := actionfacts.Input{Tool: "shell", Args: hookArgs, CWD: "/repo"}
				hookFacts := actionfacts.Analyze(hookInput)
				if !actionfacts.ExactPOSIXSystemLogDestruction(hookFacts) {
					t.Fatalf("command=%q hook facts lost exact proof: %+v", command, hookFacts)
				}
				dispatched := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: hookInput, LegacyText: string(hookArgs), Connector: connector,
					EnforcementCapable: true,
				})
				if finding := findingWithID(dispatched, "tamper.posix_system_log_destruction"); finding == nil || finding.contributesToEnforcement() {
					t.Fatalf("command=%q dispatched finding=%+v all=%+v", command, finding, dispatched)
				}
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = connector
				cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile.name)
				response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
					HookEventName: "PreToolUse",
					ToolName:      "shell",
					CWD:           "/repo",
					ToolInput: map[string]interface{}{
						"command": command,
					},
				})
				if response.Action != profile.action || response.RawAction != profile.action ||
					response.Severity != profile.severity ||
					!findingStringHasRuleID(response.Findings, "tamper.posix_system_log_destruction") {
					t.Fatalf("command=%q response=%+v want %s/%s", command, response, profile.action, profile.severity)
				}
			}
		})
	}
}

func TestPOSIXMultipleSecurityLogDestructionAlertsWithoutBlocking(t *testing.T) {
	const command = `rm -rf /var/log/secure /var/log/wtmp`
	owner := semanticOwners["tamper.posix_system_log_destruction"]
	if owner.prerequisite == nil || owner.detectionOnly || !owner.alertOnly {
		t.Fatalf("system-log owner posture=%+v", owner)
	}
	for _, profile := range []struct {
		name     string
		severity string
	}{
		{name: "default", severity: "HIGH"},
		{name: "permissive", severity: "HIGH"},
		{name: "strict", severity: "CRITICAL"},
	} {
		t.Run(profile.name, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile.name)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile.name)
			response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: "/repo",
				ToolInput: map[string]interface{}{"command": command},
			})
			if response.Action != guardrailActionAlert || response.WouldBlock ||
				response.Severity != profile.severity ||
				!findingStringHasRuleID(response.Findings, "tamper.posix_system_log_destruction") {
				t.Fatalf("profile=%s response=%+v", profile.name, response)
			}
		})
	}
}

func TestPOSIXJournalRetentionDoesNotProduceSystemLogDestruction(t *testing.T) {
	const command = `sudo find /var/log/journal -type f -name '*.journal' -mtime +0 -delete`
	input := actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo", DialectHint: actionfacts.DialectPOSIX}
	facts := actionfacts.Analyze(input)
	if actionfacts.ExactPOSIXSystemLogDestruction(facts) {
		t.Fatalf("bounded journal retention was classified as log destruction: %+v", facts)
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		raw := scanTrustedRulesForProfile(t, profile, command, "shell")
		filtered := filterExactFallbackFindings(raw, input, facts, true)
		if finding := findingWithID(filtered, "tamper.posix_system_log_destruction"); finding != nil {
			t.Fatalf("profile=%s retention finding=%+v", profile, finding)
		}
	}
}

func TestPOSIXAtomicSecurityControlsFallbackContracts(t *testing.T) {
	for _, test := range []struct {
		name    string
		ruleID  string
		command string
		want    bool
	}{
		{
			name: "exact pam capture", ruleID: pamPasswordCaptureRuleID,
			command: `echo "session required pam_tty_audit.so enable=* log_passwd" >> /etc/pam.d/sshd`, want: true,
		},
		{
			name: "dynamic pam capture", ruleID: pamPasswordCaptureRuleID,
			command: `echo "session required pam_tty_audit.so enable=$USERS log_passwd" >> /etc/pam.d/sshd`,
		},
		{
			name: "exact pf pair", ruleID: posixHardeningRuleID,
			command: "service pf stop\nservice pf disable", want: true,
		},
		{
			name: "partial pf change", ruleID: posixHardeningRuleID,
			command: `service pf stop`,
		},
		{
			name: "exact legacy auditd stop", ruleID: linuxSecurityRuleID,
			command: `sudo service auditd stop`, want: true,
		},
		{
			name: "legacy auditd restart", ruleID: linuxSecurityRuleID,
			command: `service auditd restart`,
		},
		{
			name: "legacy auditd stop with extra argument", ruleID: linuxSecurityRuleID,
			command: `service auditd stop now`,
		},
		{
			name:    "exact log truncate failure suppression",
			ruleID:  "tamper.posix_system_log_destruction",
			command: `sudo truncate -s 0 /var/log/auth.log 2>/dev/null || true`, want: true,
		},
		{
			name:    "nonliteral log failure branch",
			ruleID:  "tamper.posix_system_log_destruction",
			command: `sudo truncate -s 0 /var/log/auth.log 2>/dev/null || echo failed`,
		},
		{
			name:    "mismatched rotated audit log lineage",
			ruleID:  "tamper.posix_system_log_destruction",
			command: `chattr -i /var/log/audit/audit.log.1; truncate -s 0 /var/log/audit/audit.log.2`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			contract, ok := exactFallbackContracts[test.ruleID]
			wantDetectionOnly := test.ruleID == "tamper.posix_system_log_destruction"
			if !ok || contract.proves == nil || contract.boundedSubgraphProves == nil ||
				contract.detectionOnly != wantDetectionOnly {
				t.Fatalf("fallback contract %s is incomplete: %+v", test.ruleID, contract)
			}
			input := actionfacts.Input{
				Tool: "shell", Command: test.command, CWD: "/repo",
				DialectHint: actionfacts.DialectPOSIX,
			}
			facts := actionfacts.Analyze(input)
			if got := contract.proves(input, facts); got != test.want {
				t.Fatalf("fallback proof=%t want=%t facts=%+v", got, test.want, facts)
			}
			if got := contract.boundedSubgraphProves(input, facts); got != test.want {
				t.Fatalf("bounded proof=%t want=%t facts=%+v", got, test.want, facts)
			}
		})
	}
}
