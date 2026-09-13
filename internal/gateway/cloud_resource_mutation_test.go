// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

const cloudS3DataDeleteRuleID = "impact.cloud_s3_data_delete"
const cloudObservedResourceDeleteRuleID = "impact.cloud_observed_resource_delete"

func TestCloudS3DataDeleteOwnerAlertsWithoutBlocking(t *testing.T) {
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	const expression = `f.commands.exists(c, c.argv_complete && c.program == 'aws' && defenseclaw.guardrail.semantic.v1.OperationKind.OPERATION_KIND_DELETE in c.operations && (('s3' in c.argv) || ('s3api' in c.argv)))`
	if _, code := compiler.Compile(expression); code != semantic.CompileOK {
		t.Fatalf("compile code=%s", code)
	}
	owner := semanticOwners[cloudS3DataDeleteRuleID]
	if owner.prerequisite == nil || owner.detectionOnly || !owner.alertOnly {
		t.Fatalf("owner posture=%+v", owner)
	}
	raw, err := json.Marshal(map[string]string{
		"service": "s3",
		"command": "rm s3://example-bucket/releases/ --recursive --region us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	input := actionfacts.Input{Tool: "aws_cli", Args: raw, CWD: "/repo"}
	facts := actionfacts.Analyze(input)
	if !facts.Authoritative() || !owner.eligible(facts) {
		t.Fatalf("exact mutation not owned: %+v", facts)
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(raw), Connector: connector,
				EnforcementCapable: true,
			})
			finding := findingWithID(findings, cloudS3DataDeleteRuleID)
			if finding == nil || finding.Severity != "HIGH" ||
				finding.contributesToEnforcement() || !finding.contributesToAlertOnly() {
				t.Fatalf("profile=%s finding=%+v all=%v", profile, finding, FindingStrings(findings))
			}
		})
	}
}

func TestObservedCloudResourceDeleteIsStrictAlertOnly(t *testing.T) {
	owner := semanticOwners[cloudObservedResourceDeleteRuleID]
	if owner.prerequisite == nil || owner.detectionOnly || !owner.alertOnly {
		t.Fatalf("observed cloud owner posture=%+v", owner)
	}
	for _, test := range []struct {
		name, tool, raw string
	}{
		{"aws volume", "aws.cloudtrail_event", gatewayAWSDeleteVolumeEvent},
		{"azure binding", "azure.activity_event", gatewayAzureRoleAssignmentDeleteEvent},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := actionfacts.Input{Tool: test.tool, Args: json.RawMessage(test.raw)}
			for _, profile := range []string{"default", "permissive", "strict"} {
				profile := profile
				t.Run(profile, func(t *testing.T) {
					connector := "observed-cloud-" + test.name + "-" + profile
					installToolCallCorpusProfileConnector(t, connector, profile)
					result := EvaluateDeterministicAction(context.Background(), input, "", connector, profile)
					matched := slices.Contains(result.RuleIDs, cloudObservedResourceDeleteRuleID)
					if profile != "strict" {
						if matched {
							t.Fatalf("profile=%s result=%+v, want no universal finding", profile, result)
						}
						return
					}
					if !matched || result.Action != "alert" || len(result.Findings) != 1 ||
						result.Findings[0].ContributesToEnforcement {
						t.Fatalf("strict result=%+v, want one alert-only observed finding", result)
					}
				})
			}
		})
	}
}

func TestObservedCloudResourceDeleteProtectedPackAlerts(t *testing.T) {
	connector := activateUseCaseProfile(t, "cloud-production-protection")
	for _, test := range []struct {
		name, tool, raw string
	}{
		{"aws volume", "aws.cloudtrail_event", gatewayAWSDeleteVolumeEvent},
		{"azure binding", "azure.activity_event", gatewayAzureRoleAssignmentDeleteEvent},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := EvaluateDeterministicAction(
				context.Background(),
				actionfacts.Input{Tool: test.tool, Args: json.RawMessage(test.raw)},
				"",
				connector,
				"default",
			)
			if !slices.Contains(result.RuleIDs, cloudObservedResourceDeleteRuleID) ||
				result.Action != "alert" || result.Severity != "CRITICAL" ||
				len(result.Findings) != 1 || result.Findings[0].ContributesToEnforcement {
				t.Fatalf("protected result=%+v, want CRITICAL post-action alert", result)
			}
		})
	}
}

func TestObservedGCPObjectDeleteHasNoAtomicFinding(t *testing.T) {
	input := actionfacts.Input{Tool: "gcp.audit_event", Args: json.RawMessage(gatewayGCPObjectDeleteEvent)}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "gcp-object-noise-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		result := EvaluateDeterministicAction(context.Background(), input, "", connector, profile)
		if len(result.Findings) != 0 || result.Action != "allow" {
			t.Fatalf("profile=%s result=%+v, want no atomic GCP object-delete finding", profile, result)
		}
	}
	connector := activateUseCaseProfile(t, "cloud-production-protection")
	result := EvaluateDeterministicAction(context.Background(), input, "", connector, "default")
	if len(result.Findings) != 0 || result.Action != "allow" {
		t.Fatalf("protected pack result=%+v, want no unscoped single-object block", result)
	}
}

const gatewayAWSDeleteVolumeEvent = `{"event_name":"DeleteVolume","event_source":"ec2.amazonaws.com","provider":"aws","request_parameters":{"volumeId":"vol-example"},"status":{"error_code":null,"error_message_present":false,"outcome":"succeeded"}}`

const gatewayAzureRoleAssignmentDeleteEvent = `{"operation":"Microsoft.Authorization/roleAssignments/delete","provider":"azure","request":{"authorization":{"action":"Microsoft.Authorization/roleAssignments/delete","scope":"/subscriptions/sub-a/resourceGroups/group-a"}},"resources":[{"id":"/subscriptions/sub-a/resourceGroups/group-a/providers/Microsoft.Authorization/roleAssignments/binding-a"}],"service":"Microsoft.Authorization","status":{"evidence":"azure_status_succeeded","outcome":"succeeded"}}`

const gatewayGCPObjectDeleteEvent = `{"operation":"storage.objects.delete","provider":"gcp","request":{"authorization":[{"granted":true,"permission":"storage.objects.delete","resource":"projects/_/buckets/bucket-a/objects/test-a.txt","resourceAttributes":{}}],"parameters":{}},"resources":[{"id":"projects/_/buckets/bucket-a/objects/test-a.txt"}],"service":"storage.googleapis.com","status":{"evidence":"gcp_empty_status_success","outcome":"succeeded"}}`

func TestCloudS3DataDeleteOwnerRejectsNearMisses(t *testing.T) {
	for _, command := range []string{
		"ls s3://example-bucket --recursive",
		"rm s3://example-bucket/releases/build.tgz",
		"rm s3://example-bucket/releases/ --recursive --dryrun",
		"rm s3://example-bucket/$PREFIX --recursive",
		"rm s3://example-bucket/releases/ --recursive --exclude '*.log'",
	} {
		raw, err := json.Marshal(map[string]string{"service": "s3", "command": command})
		if err != nil {
			t.Fatal(err)
		}
		input := actionfacts.Input{Tool: "aws_cli", Args: raw, CWD: "/repo"}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: string(raw), EnforcementCapable: true,
		})
		if findingWithID(findings, cloudS3DataDeleteRuleID) != nil {
			t.Fatalf("near miss %q matched: %v", command, FindingStrings(findings))
		}
	}
}
