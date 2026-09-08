// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

const cloudIAMAdministratorAttachmentRuleID = "privilege.cloud_iam_administrator_attachment"

func TestCloudIAMAdministratorAttachmentProfilePosture(t *testing.T) {
	profiles := []struct {
		name        string
		pack        string
		severity    string
		evalProfile string
	}{
		{name: "balanced", pack: "default", severity: "HIGH", evalProfile: "balanced"},
		{name: "default", pack: "default", severity: "HIGH", evalProfile: "default"},
		{name: "permissive", pack: "permissive", severity: "HIGH", evalProfile: "permissive"},
		{name: "strict", pack: "strict", severity: "LOW", evalProfile: "strict"},
	}
	for _, profile := range profiles {
		profile := profile
		t.Run(profile.name, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile.pack)
			command := "attach-user-policy --user-name backdoor-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
			input := cloudIAMGatewayInput(t, command)
			facts := actionfacts.Analyze(input)
			proof, owned := trustedSemanticOwnerFindingProof(
				cloudIAMAdministratorAttachmentRuleID, input, facts,
			)
			if !owned || !proof.authorizes(cloudIAMAdministratorAttachmentRuleID) {
				t.Fatalf("exact semantic owner did not authorize its detection proof: proof=%+v facts=%+v", proof, facts)
			}

			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(input.Args), Connector: connector,
				EnforcementCapable: true,
			})
			finding := findingWithID(findings, cloudIAMAdministratorAttachmentRuleID)
			if finding == nil || finding.Severity != profile.severity ||
				finding.contributesToEnforcement() {
				t.Fatalf("finding=%+v all=%v, want %s detection-only semantic result", finding, FindingStrings(findings), profile.severity)
			}

			evaluation := EvaluateDeterministicAction(
				t.Context(), input, string(input.Args), connector, profile.evalProfile,
			)
			if !slices.Contains(evaluation.RuleIDs, cloudIAMAdministratorAttachmentRuleID) ||
				evaluation.Route != "semantic" || evaluation.EnforceableSeverity != "NONE" ||
				evaluation.Action == "block" || evaluation.Action == "confirm" {
				t.Fatalf("evaluation=%+v, want semantic non-blocking detection", evaluation)
			}

			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile.pack)
			response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(
				t.Context(), codexHookRequest{
					HookEventName: "PreToolUse", ToolName: "aws_cli", CWD: "/repo",
					ToolInput: map[string]interface{}{"service": "iam", "command": command},
				},
			)
			if response.Action == "block" || response.RawAction == "block" ||
				response.Action == "confirm" || response.RawAction == "confirm" ||
				!findingStringHasRuleID(response.Findings, cloudIAMAdministratorAttachmentRuleID) {
				t.Fatalf("response=%+v, want visible detection without block/confirm", response)
			}
		})
	}
}

func TestCloudIAMAdministratorAttachmentSemanticOwnershipIsClosed(t *testing.T) {
	owner, ok := semanticOwners[cloudIAMAdministratorAttachmentRuleID]
	if !ok || owner.prerequisite == nil || owner.suppressFallback == nil ||
		!owner.detectionOnly {
		t.Fatalf("semantic owner=%+v ok=%t", owner, ok)
	}
	contract, ok := exactFallbackContracts[cloudIAMAdministratorAttachmentRuleID]
	if !ok || contract.proves == nil || contract.boundedSubgraphProves == nil ||
		!contract.detectionOnly {
		t.Fatalf("fallback contract=%+v ok=%t", contract, ok)
	}
	foundCatalog := false
	for _, category := range defaultRuleCategories {
		for _, rule := range category.Rules {
			if rule.ID != cloudIAMAdministratorAttachmentRuleID {
				continue
			}
			foundCatalog = rule.ToolCallOnly && rule.Expression != "" &&
				rule.Pattern != nil && rule.Severity == "HIGH"
		}
	}
	if !foundCatalog {
		t.Fatal("generated default catalog does not contain the CEL-owned IAM attachment rule")
	}
}

func TestCloudIAMAdministratorAttachmentOwnerRejectsNearMisses(t *testing.T) {
	tests := []struct {
		name    string
		tool    string
		service string
		command string
	}{
		{name: "creation only", tool: "aws_cli", service: "iam", command: "create-user --user-name backdoor-admin"},
		{name: "custom policy", tool: "aws_cli", service: "iam", command: "attach-user-policy --user-name backdoor-admin --policy-arn arn:aws:iam::123456789012:policy/Admin"},
		{name: "different service", tool: "aws_cli", service: "sts", command: "attach-user-policy --user-name backdoor-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"},
		{name: "dynamic principal", tool: "aws_cli", service: "iam", command: "attach-user-policy --user-name $USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"},
		{name: "extra option", tool: "aws_cli", service: "iam", command: "attach-user-policy --user-name backdoor-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile prod"},
		{name: "raw shell lacks fixed provider context", tool: "shell", command: "aws iam attach-user-policy --user-name backdoor-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var input actionfacts.Input
			if test.tool == "shell" {
				input = actionfacts.Input{Tool: "shell", Command: test.command, CWD: "/repo", DialectHint: actionfacts.DialectPOSIX}
			} else {
				raw, err := json.Marshal(map[string]string{"service": test.service, "command": test.command})
				if err != nil {
					t.Fatal(err)
				}
				input = actionfacts.Input{Tool: test.tool, Args: raw, CWD: "/repo"}
			}
			facts := actionfacts.Analyze(input)
			proof, _ := trustedSemanticOwnerFindingProof(
				cloudIAMAdministratorAttachmentRuleID, input, facts,
			)
			if proof.authorizes(cloudIAMAdministratorAttachmentRuleID) {
				t.Fatalf("near miss escaped owner: proof=%+v facts=%+v", proof, facts)
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: test.command, Connector: "codex",
				EnforcementCapable: true,
			})
			if findingWithID(findings, cloudIAMAdministratorAttachmentRuleID) != nil {
				t.Fatalf("near miss produced IAM finding: %v", FindingStrings(findings))
			}
		})
	}
}

func TestAWSCLIUnownedCommandCannotBecomeLocalShellFinding(t *testing.T) {
	for _, test := range []struct {
		name    string
		tool    string
		service string
		command string
	}{
		{name: "IAM field", tool: "aws_cli", service: "iam", command: "rm -rf /"},
		{name: "case variant", tool: "AWS_CLI", service: "iam", command: "rm -rf /"},
		{name: "unrelated service", tool: "aws_cli", service: "s3", command: "rm -rf /"},
		{name: "compound suffix", tool: "aws_cli", service: "iam", command: "create-user --user-name fixture; rm -rf /"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{
				"service": test.service, "command": test.command,
			})
			if err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{Tool: test.tool, Args: raw, CWD: "/repo"}
			facts := actionfacts.Analyze(input)
			if facts.Parse.Status != actionfacts.StatusPartial || len(facts.Commands) != 0 {
				t.Fatalf("facts=%+v, want value-free partial projection", facts)
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(raw), Connector: "codex",
				EnforcementCapable: true,
			})
			if len(findings) != 0 {
				t.Fatalf("unowned aws_cli field became local finding: %v", FindingStrings(findings))
			}
		})
	}
}

func cloudIAMGatewayInput(t *testing.T, command string) actionfacts.Input {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"service": "iam", "command": command})
	if err != nil {
		t.Fatal(err)
	}
	return actionfacts.Input{Tool: "aws_cli", Args: raw, CWD: "/repo"}
}
