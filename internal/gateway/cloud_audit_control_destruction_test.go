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

const cloudAuditControlDestructionRuleID = "tamper.cloud_audit_control_destruction"

func TestCloudAuditControlDestructionProfilePosture(t *testing.T) {
	positives := []struct {
		name    string
		command string
	}{
		{name: "aws stop logging", command: "aws cloudtrail stop-logging --name production-trail --region us-east-1"},
		{name: "aws delete trail", command: "aws cloudtrail delete-trail --name production-trail --region us-east-1"},
		{name: "gcp delete audit activity", command: "gcloud logging logs delete projects/security-prod-123/logs/cloudaudit.googleapis.com%2Factivity --quiet"},
	}
	profiles := []struct {
		name     string
		severity string
	}{
		{name: "default", severity: "HIGH"},
		{name: "permissive", severity: "HIGH"},
		{name: "strict", severity: "LOW"},
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
					proof, owned := trustedSemanticOwnerFindingProof(
						cloudAuditControlDestructionRuleID, input, facts,
					)
					if !owned || !proof.authorizes(cloudAuditControlDestructionRuleID) {
						t.Fatalf("exact owner did not authorize proof=%+v facts=%+v", proof, facts)
					}
					findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
						Input: input, LegacyText: positive.command, Connector: connector,
						EnforcementCapable: true,
					})
					matched := findingWithID(findings, cloudAuditControlDestructionRuleID)
					if matched == nil || !matched.contributesToEnforcement() || matched.Severity != profile.severity {
						t.Fatalf("finding=%+v all=%v, want %s exact proof", matched, FindingStrings(findings), profile.severity)
					}

					cfg := &config.Config{}
					cfg.Guardrail.Mode = "action"
					cfg.Guardrail.Connector = connector
					cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile.name)
					response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(
						t.Context(),
						codexHookRequest{
							HookEventName: "PreToolUse",
							ToolName:      "shell",
							CWD:           "/repo",
							ToolInput: map[string]interface{}{
								"command": positive.command,
							},
						},
					)
					if response.Action != "alert" || response.RawAction != "alert" ||
						response.Severity != profile.severity ||
						!findingStringHasRuleID(response.Findings, cloudAuditControlDestructionRuleID) {
						t.Fatalf("response=%+v, want alert/%s with %s", response, profile.severity, cloudAuditControlDestructionRuleID)
					}
				})
			}
		})
	}
}

func TestCloudAuditControlDestructionFallbackContract(t *testing.T) {
	contract, ok := exactFallbackContracts[cloudAuditControlDestructionRuleID]
	if !ok || contract.proves == nil || contract.boundedSubgraphProves == nil ||
		contract.detectionOnly {
		t.Fatalf("cloud audit-control fallback contract is incomplete: %+v", contract)
	}
	owner := semanticOwners[cloudAuditControlDestructionRuleID]
	if owner.detectionOnly {
		t.Fatal("cloud audit-control semantic owner must allow explicit protected-cloud policy")
	}
	for _, test := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "exact", command: "aws cloudtrail stop-logging --name production-trail --region us-east-1", want: true},
		{name: "placeholder", command: "aws cloudtrail stop-logging --name #{cloudtrail_name} --region #{region}"},
		{name: "read only", command: "aws cloudtrail describe-trails --region us-east-1"},
	} {
		t.Run(test.name, func(t *testing.T) {
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

func TestCloudAuditControlDestructionProtectedCloudPolicyBlocks(t *testing.T) {
	connector := activateUseCaseProfile(t, "cloud-production-protection")
	for _, command := range []string{
		"aws cloudtrail stop-logging --name production-trail --region us-east-1",
		"aws cloudtrail delete-trail --name production-trail --region us-east-1",
		"gcloud logging logs delete projects/security-prod-123/logs/cloudaudit.googleapis.com%2Factivity --quiet",
	} {
		got := EvaluateDeterministicAction(
			t.Context(),
			actionfacts.Input{Tool: "shell", Command: command, DialectHint: actionfacts.DialectPOSIX},
			command,
			connector,
			"default",
		)
		if got.Action != "block" || got.Severity != "CRITICAL" {
			t.Fatalf("protected cloud result=%+v, want CRITICAL block", got)
		}
	}
}

func TestCloudAuditControlDestructionOwnerRejectsNearMisses(t *testing.T) {
	for _, command := range []string{
		"aws cloudtrail describe-trails --region us-east-1",
		"aws cloudtrail get-trail-status --name production-trail --region us-east-1",
		"aws cloudtrail start-logging --name production-trail --region us-east-1",
		"aws cloudtrail delete-trail --name #{cloudtrail_name} --region #{region}",
		`aws cloudtrail delete-trail --name "$TRAIL" --region us-east-1`,
		"aws cloudtrail delete-trail --name production-trail --region us-east-1 --profile production",
		"aws cloudtrail delete-trail --name production-trail --region us-east-1\nwhoami",
		"gcloud logging logs delete projects/security-prod-123/logs/application --quiet",
		"gcloud logging logs delete projects/#{project-id}/logs/cloudaudit.googleapis.com%2Factivity --quiet",
		"printf '%s\\n' 'aws cloudtrail delete-trail --name production-trail --region us-east-1'",
	} {
		input := actionfacts.Input{
			Tool: "shell", Command: command, CWD: "/repo",
			DialectHint: actionfacts.DialectPOSIX,
		}
		facts := actionfacts.Analyze(input)
		proof, _ := trustedSemanticOwnerFindingProof(
			cloudAuditControlDestructionRuleID, input, facts,
		)
		if proof.authorizes(cloudAuditControlDestructionRuleID) {
			t.Fatalf("negative escaped exact owner: command=%q proof=%+v facts=%+v", command, proof, facts)
		}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: command, Connector: "codex", EnforcementCapable: true,
		})
		if findingWithID(findings, cloudAuditControlDestructionRuleID) != nil {
			t.Fatalf("negative produced finding: command=%q findings=%v facts=%+v", command, FindingStrings(findings), facts)
		}
	}
}
