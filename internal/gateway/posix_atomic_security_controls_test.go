// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	pamPasswordCaptureRuleID = "credential.pam_password_capture"
	posixHardeningRuleID     = "tamper.posix_logging_hardening_disable"
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
	} {
		t.Run(test.name, func(t *testing.T) {
			contract, ok := exactFallbackContracts[test.ruleID]
			if !ok || contract.proves == nil || contract.boundedSubgraphProves == nil || contract.detectionOnly {
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
