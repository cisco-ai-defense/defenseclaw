// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

const cloudMetadataCredentialRuleID = "secrets.cloud_metadata_credential_read"

func TestCloudMetadataCredentialOwnerIsAlertOnly(t *testing.T) {
	owner := semanticOwners[cloudMetadataCredentialRuleID]
	if owner.prerequisite == nil || owner.detectionOnly || !owner.alertOnly {
		t.Fatalf("owner posture=%+v", owner)
	}
	input := cloudMetadataCredentialInput(t, "aws", "/latest/meta-data/iam/security-credentials/production-role")
	facts := actionfacts.Analyze(input)
	if !owner.eligible(facts) || !facts.Authoritative() {
		t.Fatalf("exact metadata credential read not owned: %+v", facts)
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, EnforcementCapable: true})
	matched := findingWithID(findings, cloudMetadataCredentialRuleID)
	if matched == nil || matched.Severity != "HIGH" || matched.contributesToEnforcement() ||
		!matched.contributesToAlertOnly() || matched.Evidence != "" {
		t.Fatalf("semantic finding=%+v all=%v", matched, FindingStrings(findings))
	}
}

func TestCloudMetadataCredentialAlertsWithoutBlockingInEveryProfile(t *testing.T) {
	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile)
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
			response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(t.Context(), codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "cloud_metadata", CWD: "/repo",
				ToolInput: map[string]interface{}{
					"provider": "gcp", "path": "/computeMetadata/v1/instance/service-accounts/default/token",
				},
			})
			if response.Action != guardrailActionAlert || response.WouldBlock || response.Severity != "HIGH" ||
				!findingStringHasRuleID(response.Findings, cloudMetadataCredentialRuleID) {
				t.Fatalf("profile=%s response=%+v", profile, response)
			}
		})
	}
}

func TestCloudMetadataCredentialSafeNegativesDoNotAlert(t *testing.T) {
	for _, input := range []actionfacts.Input{
		cloudMetadataCredentialInput(t, "aws", "/latest/meta-data/instance-id"),
		cloudMetadataCredentialInput(t, "gcp", "/computeMetadata/v1/project/project-id"),
		cloudMetadataCredentialInput(t, "azure", "/metadata/instance?api-version=2021-02-01"),
	} {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, EnforcementCapable: true})
		if findingWithID(findings, cloudMetadataCredentialRuleID) != nil {
			t.Fatalf("safe metadata read produced finding: %v", FindingStrings(findings))
		}
	}
}

func cloudMetadataCredentialInput(t *testing.T, provider, path string) actionfacts.Input {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"provider": provider, "path": path})
	if err != nil {
		t.Fatal(err)
	}
	return actionfacts.Input{Tool: "cloud_metadata", Args: raw, CWD: "/repo"}
}
