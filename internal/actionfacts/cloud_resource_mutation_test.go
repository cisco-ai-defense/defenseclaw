// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCloudResourceMutationFactsExactAWSDeletes(t *testing.T) {
	tests := []struct {
		name      string
		input     Input
		operation CloudResourceMutationOperation
		scope     string
		recursive bool
	}{
		{
			name:      "recursive prefix with linuxarena arguments",
			input:     Input{Tool: "shell", Command: "aws s3 rm s3://models/models/aleph/ --recursive --endpoint-url https://s3:9000 --region us-east-1 --no-verify-ssl"},
			operation: CloudResourceDeletePrefix, scope: "prefix", recursive: true,
		},
		{
			name:      "recursive bucket root",
			input:     Input{Tool: "shell", Command: "aws s3 rm s3://example-bucket --recursive"},
			operation: CloudResourceDeletePrefix, scope: "prefix", recursive: true,
		},
		{
			name:      "single object",
			input:     Input{Tool: "shell", Command: "aws s3 rm 's3://example-bucket/releases/build 7.tgz' --only-show-errors"},
			operation: CloudResourceDeleteObject, scope: "object",
		},
		{
			name:      "structured delete object",
			input:     Input{Tool: "aws_cli", Args: json.RawMessage(`{"service":"s3api","command":"delete-object --bucket example-bucket --key releases/build.tgz --region us-east-1"}`)},
			operation: CloudResourceDeleteObject, scope: "object",
		},
		{
			name:      "forced bucket removal",
			input:     Input{Tool: "shell", Command: "aws s3 rb s3://example-bucket --force"},
			operation: CloudResourceDeleteBucket, scope: "bucket", recursive: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			mutations := ExactCloudResourceMutations(facts)
			if len(mutations) != 1 {
				t.Fatalf("mutations=%#v parse=%#v commands=%#v", mutations, facts.Parse, facts.Commands)
			}
			mutation := mutations[0]
			if mutation.Operation != test.operation || mutation.Scope != test.scope ||
				mutation.Recursive != test.recursive || !mutation.Exact ||
				mutation.Provider != "aws" || mutation.Service != "s3" ||
				!validPrivateDigest(mutation.ResourceIdentityDigest) ||
				!validPrivateDigest(mutation.ObjectIdentityDigest) {
				t.Fatalf("mutation=%#v", mutation)
			}
			encoded, err := json.Marshal(mutation)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"example-bucket", "models/aleph", "build.tgz", "secret"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatalf("public facts retained %q: %s", secret, encoded)
				}
			}
		})
	}
}

func TestCloudResourceMutationFactsHardNegatives(t *testing.T) {
	commands := []string{
		"aws s3 ls s3://example-bucket --recursive",
		"aws s3 rm s3://example-bucket/path --recursive --dryrun",
		"aws s3 rm s3://example-bucket/$PREFIX --recursive",
		"aws s3 rm s3://example-bucket/path --recursive --exclude '*.log'",
		"aws s3 rm s3://example-bucket/path --unknown-option",
		"aws s3 rb s3://example-bucket",
		"aws s3api delete-object --bucket example-bucket --key '$KEY'",
		"aws s3api delete-objects --bucket example-bucket --delete '{\"Objects\":[{\"Key\":\"a\"}]}'",
		"aws s3 rm s3://Example-Bucket/path --recursive",
		"echo aws s3 rm s3://example-bucket/path --recursive",
		"AWS_ACCESS_KEY_ID=app-user AWS_SECRET_ACCESS_KEY=secret aws s3 rm s3://example-bucket/path --recursive",
	}
	for _, command := range commands {
		t.Run(command, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: command})
			if mutations := ExactCloudResourceMutations(facts); len(mutations) != 0 {
				t.Fatalf("mutations=%#v parse=%#v commands=%#v", mutations, facts.Parse, facts.Commands)
			}
		})
	}
}

func TestCloudResourceMutationIdentityIsStableAndSeparated(t *testing.T) {
	first := ExactCloudResourceMutations(Analyze(Input{Tool: "shell", Command: "aws s3 rm s3://example-bucket/a"}))
	same := ExactCloudResourceMutations(Analyze(Input{Tool: "shell", Command: "aws s3api delete-object --bucket example-bucket --key a"}))
	other := ExactCloudResourceMutations(Analyze(Input{Tool: "shell", Command: "aws s3 rm s3://example-bucket/b"}))
	if len(first) != 1 || len(same) != 1 || len(other) != 1 {
		t.Fatalf("unexpected facts: %#v %#v %#v", first, same, other)
	}
	if first[0].ResourceIdentityDigest != same[0].ResourceIdentityDigest ||
		first[0].ObjectIdentityDigest != same[0].ObjectIdentityDigest ||
		first[0].ObjectIdentityDigest == other[0].ObjectIdentityDigest {
		t.Fatalf("identity mismatch: %#v %#v %#v", first, same, other)
	}
}

func TestCloudAuditResourceMutationFactsAreObservedOnly(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, tool, raw string
		operation       CloudResourceMutationOperation
	}{
		{"aws disk", "aws.cloudtrail_event", validAWSDeleteVolumeEvent, CloudResourceDeleteDisk},
		{"azure binding", "azure.activity_event", validAzureRoleAssignmentDeleteEvent, CloudResourceDeleteIAMBinding},
		{"gcp object", "gcp.audit_event", validGCPObjectDeleteEvent, CloudResourceDeleteObject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: tc.tool, Args: json.RawMessage(tc.raw)})
			mutations := ExactCloudResourceMutations(facts)
			if !facts.Authoritative() || len(mutations) != 1 || mutations[0].Operation != tc.operation || !mutations[0].Observed {
				t.Fatalf("parse=%+v mutations=%+v", facts.Parse, mutations)
			}
			if projected := facts.EnforcementProjection().CloudResourceMutations; len(projected) != 0 {
				t.Fatalf("observed audit fact entered enforcement: %+v", projected)
			}
		})
	}
}

func TestCloudAuditResourceMutationIdentityScopesAreSeparated(t *testing.T) {
	t.Parallel()
	azureFirst := ExactCloudResourceMutations(Analyze(Input{Tool: "azure.activity_event", Args: json.RawMessage(validAzureRoleAssignmentDeleteEvent)}))
	azureSameScope := ExactCloudResourceMutations(Analyze(Input{Tool: "azure.activity_event", Args: json.RawMessage(strings.ReplaceAll(validAzureRoleAssignmentDeleteEvent, "binding-a", "binding-b"))}))
	azureOtherScope := ExactCloudResourceMutations(Analyze(Input{Tool: "azure.activity_event", Args: json.RawMessage(strings.ReplaceAll(validAzureRoleAssignmentDeleteEvent, "group-a", "group-b"))}))
	gcpFirst := ExactCloudResourceMutations(Analyze(Input{Tool: "gcp.audit_event", Args: json.RawMessage(validGCPObjectDeleteEvent)}))
	gcpSameBucket := ExactCloudResourceMutations(Analyze(Input{Tool: "gcp.audit_event", Args: json.RawMessage(strings.ReplaceAll(validGCPObjectDeleteEvent, "test-a.txt", "test-b.txt"))}))
	gcpOtherBucket := ExactCloudResourceMutations(Analyze(Input{Tool: "gcp.audit_event", Args: json.RawMessage(strings.ReplaceAll(validGCPObjectDeleteEvent, "bucket-a", "bucket-b"))}))
	for name, mutations := range map[string][]CloudResourceMutationFact{
		"azure first": azureFirst, "azure same scope": azureSameScope, "azure other scope": azureOtherScope,
		"gcp first": gcpFirst, "gcp same bucket": gcpSameBucket, "gcp other bucket": gcpOtherBucket,
	} {
		if len(mutations) != 1 {
			t.Fatalf("%s mutations=%+v", name, mutations)
		}
	}
	if azureFirst[0].ResourceIdentityDigest != azureSameScope[0].ResourceIdentityDigest ||
		azureFirst[0].ObjectIdentityDigest == azureSameScope[0].ObjectIdentityDigest ||
		azureFirst[0].ResourceIdentityDigest == azureOtherScope[0].ResourceIdentityDigest {
		t.Fatalf("Azure scope/binding identities are not separated: %+v %+v %+v", azureFirst, azureSameScope, azureOtherScope)
	}
	if gcpFirst[0].ResourceIdentityDigest != gcpSameBucket[0].ResourceIdentityDigest ||
		gcpFirst[0].ObjectIdentityDigest == gcpSameBucket[0].ObjectIdentityDigest ||
		gcpFirst[0].ResourceIdentityDigest == gcpOtherBucket[0].ResourceIdentityDigest {
		t.Fatalf("GCP bucket/object identities are not separated: %+v %+v %+v", gcpFirst, gcpSameBucket, gcpOtherBucket)
	}
}

func TestCloudAuditResourceMutationRejectsMixedChannels(t *testing.T) {
	t.Parallel()
	for _, input := range []Input{
		{Tool: "aws.cloudtrail_event", Args: json.RawMessage(validAWSDeleteVolumeEvent), Command: "aws ec2 delete-volume --volume-id vol-example"},
		{Tool: "azure.activity_event", Args: json.RawMessage(validAzureRoleAssignmentDeleteEvent), Argv: []string{"az", "role", "assignment", "delete"}},
		{Tool: "gcp.audit_event", Args: json.RawMessage(validGCPObjectDeleteEvent), Command: "gcloud storage rm gs://bucket-a/test-a.txt"},
	} {
		if got := ExactCloudResourceMutations(Analyze(input)); len(got) != 0 {
			t.Fatalf("mixed audit channels projected: %+v", got)
		}
	}
}

func TestCloudAuditResourceMutationRejectsFailedOrMalformed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, tool, raw string
	}{
		{"aws failed", "aws.cloudtrail_event", `{"event_name":"DeleteVolume","event_source":"ec2.amazonaws.com","provider":"aws","request_parameters":{"volumeId":"vol-1"},"status":{"error_code":"Denied","error_message_present":true,"outcome":"failed"}}`},
		{"aws request extension", "aws.cloudtrail_event", strings.Replace(validAWSDeleteVolumeEvent, `"volumeId":"vol-example"`, `"volumeId":"vol-example","force":true`, 1)},
		{"aws status extension", "aws.cloudtrail_event", strings.Replace(validAWSDeleteVolumeEvent, `"outcome":"succeeded"`, `"outcome":"succeeded","evidence":"untrusted"`, 1)},
		{"azure missing request", "azure.activity_event", strings.Replace(validAzureRoleAssignmentDeleteEvent, `,"request":{"authorization":{"action":"Microsoft.Authorization/roleAssignments/delete","scope":"/subscriptions/sub-a/resourceGroups/group-a"}}`, "", 1)},
		{"azure wrong authorization action", "azure.activity_event", strings.Replace(validAzureRoleAssignmentDeleteEvent, "Microsoft.Authorization/roleAssignments/delete\",\"scope", "Microsoft.Authorization/roleAssignments/write\",\"scope", 1)},
		{"azure unrelated scope", "azure.activity_event", strings.Replace(validAzureRoleAssignmentDeleteEvent, `/subscriptions/sub-a/resourceGroups/group-a"}}`, `/subscriptions/sub-b/resourceGroups/group-b"}}`, 1)},
		{"azure status extension", "azure.activity_event", strings.Replace(validAzureRoleAssignmentDeleteEvent, `"outcome":"succeeded"}`, `"outcome":"succeeded","code":0}`, 1)},
		{"gcp missing object", "gcp.audit_event", strings.ReplaceAll(validGCPObjectDeleteEvent, "projects/_/buckets/bucket-a/objects/test-a.txt", "projects/_/buckets/bucket-a")},
		{"gcp authorization denied", "gcp.audit_event", strings.Replace(validGCPObjectDeleteEvent, `"granted":true`, `"granted":false`, 1)},
		{"gcp authorization wrong resource", "gcp.audit_event", strings.Replace(validGCPObjectDeleteEvent, `"resource":"projects/_/buckets/bucket-a/objects/test-a.txt"`, `"resource":"projects/_/buckets/bucket-a/objects/other.txt"`, 1)},
		{"gcp authorization missing", "gcp.audit_event", strings.Replace(validGCPObjectDeleteEvent, `[{"granted":true,"permission":"storage.objects.delete","resource":"projects/_/buckets/bucket-a/objects/test-a.txt","resourceAttributes":{}}]`, `[]`, 1)},
		{"gcp parameter mismatch", "gcp.audit_event", strings.Replace(validGCPObjectDeleteEvent, `"parameters":{}`, `"parameters":{"bucket":"bucket-b"}`, 1)},
		{"gcp request extension", "gcp.audit_event", strings.Replace(validGCPObjectDeleteEvent, `"parameters":{}`, `"parameters":{},"opaque":true`, 1)},
		{"gcp status extension", "gcp.audit_event", strings.Replace(validGCPObjectDeleteEvent, `"outcome":"succeeded"}`, `"outcome":"succeeded","code":0}`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: test.tool, Args: json.RawMessage(test.raw)})
			if got := ExactCloudResourceMutations(facts); len(got) != 0 {
				t.Fatalf("malformed audit mutation projected: %+v", got)
			}
		})
	}
}

const validAWSDeleteVolumeEvent = `{"event_name":"DeleteVolume","event_source":"ec2.amazonaws.com","provider":"aws","request_parameters":{"volumeId":"vol-example"},"status":{"error_code":null,"error_message_present":false,"outcome":"succeeded"}}`

const validAzureRoleAssignmentDeleteEvent = `{"operation":"Microsoft.Authorization/roleAssignments/delete","provider":"azure","request":{"authorization":{"action":"Microsoft.Authorization/roleAssignments/delete","scope":"/subscriptions/sub-a/resourceGroups/group-a"}},"resources":[{"id":"/subscriptions/sub-a/resourceGroups/group-a/providers/Microsoft.Authorization/roleAssignments/binding-a"}],"service":"Microsoft.Authorization","status":{"evidence":"azure_status_succeeded","outcome":"succeeded"}}`

const validGCPObjectDeleteEvent = `{"operation":"storage.objects.delete","provider":"gcp","request":{"authorization":[{"granted":true,"permission":"storage.objects.delete","resource":"projects/_/buckets/bucket-a/objects/test-a.txt","resourceAttributes":{}}],"parameters":{}},"resources":[{"id":"projects/_/buckets/bucket-a/objects/test-a.txt"}],"service":"storage.googleapis.com","status":{"evidence":"gcp_empty_status_success","outcome":"succeeded"}}`
