// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestCloudAuditSecurityOperations(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		source     string
		event      string
		parameters string
		principal  string
		want       CloudAuditSecurityOperation
	}{
		{"delete trail", "cloudtrail.amazonaws.com", "DeleteTrail", `{"name":"trail"}`, `{"account_id":"111111111111"}`, CloudAuditTelemetryDisable},
		{"disable management writes", "cloudtrail.amazonaws.com", "PutEventSelectors", `{"eventSelectors":[{"includeManagementEvents":false,"readWriteType":"ReadOnly"}]}`, `{"account_id":"111111111111"}`, CloudAuditTelemetryDisable},
		{"external snapshot share", "ec2.amazonaws.com", "ModifySnapshotAttribute", `{"createVolumePermission":{"add":{"items":[{"userId":"222222222222"}]}}}`, `{"account_id":"111111111111"}`, CloudAuditExternalSnapshotShare},
		{"worldwide ssh", "ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", `{"cidrIp":"208.236.235.254/0","fromPort":22,"ipProtocol":"tcp","toPort":22}`, `{"account_id":"111111111111"}`, CloudAuditWorldwideSSHExposure},
		{"administrator role", "iam.amazonaws.com", "AttachRolePolicy", `{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess","roleName":"build"}`, `{"account_id":"111111111111"}`, CloudAuditAdministratorAttach},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := json.RawMessage(`{"provider":"aws","event_source":"` + tc.source + `","event_name":"` + tc.event + `","status":{"error_code":null,"error_message_present":false,"outcome":"succeeded"},"request_parameters":` + tc.parameters + `,"principal":` + tc.principal + `}`)
			facts := Analyze(Input{Tool: "aws.cloudtrail_event", Args: args})
			operations := ExactCloudAuditSecurityOperations(facts)
			if len(operations) != 1 || operations[0].Operation != tc.want {
				t.Fatalf("operations=%+v facts=%+v", operations, facts.CloudAuditSecurityOperations)
			}
		})
	}
}

func TestCloudAuditSecurityOperationsRejectNearMisses(t *testing.T) {
	t.Parallel()
	cases := []string{
		`{"provider":"aws","event_source":"cloudtrail.amazonaws.com","event_name":"DeleteTrail","status":{"error_code":"AccessDenied","error_message_present":true,"outcome":"failed"},"request_parameters":{"name":"trail"}}`,
		`{"provider":"aws","event_source":"cloudtrail.amazonaws.com","event_name":"PutEventSelectors","status":{"error_code":null,"error_message_present":false,"outcome":"succeeded"},"request_parameters":{"eventSelectors":[{"includeManagementEvents":true,"readWriteType":"All"}]}}`,
		`{"provider":"aws","event_source":"ec2.amazonaws.com","event_name":"ModifySnapshotAttribute","status":{"error_code":null,"error_message_present":false,"outcome":"succeeded"},"request_parameters":{"createVolumePermission":{"add":{"items":[{"userId":"111111111111"}]}}},"principal":{"account_id":"111111111111"}}`,
		`{"provider":"aws","event_source":"ec2.amazonaws.com","event_name":"AuthorizeSecurityGroupIngress","status":{"error_code":null,"error_message_present":false,"outcome":"succeeded"},"request_parameters":{"cidrIp":"10.0.0.0/8","fromPort":22,"ipProtocol":"tcp","toPort":22}}`,
		`{"provider":"aws","event_source":"iam.amazonaws.com","event_name":"AttachRolePolicy","status":{"error_code":null,"error_message_present":false,"outcome":"succeeded"},"request_parameters":{"policyArn":"arn:aws:iam::aws:policy/ReadOnlyAccess"}}`,
		`{"provider":"aws","event_source":"cloudtrail.amazonaws.com","event_name":"DeleteTrail","status":{"error_code":null,"error_message_present":false,"outcome":"succeeded"},"request_parameters":{"name":"trail"},"unexpected":"value"}`,
	}
	for _, raw := range cases {
		facts := Analyze(Input{Tool: "aws.cloudtrail_event", Args: json.RawMessage(raw)})
		if operations := ExactCloudAuditSecurityOperations(facts); len(operations) != 0 {
			t.Fatalf("near miss projected: %+v raw=%s", operations, raw)
		}
	}
}

func TestCloudAuditSecurityOperationsAreNeverEnforcementEvidence(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"provider":"aws","event_source":"cloudtrail.amazonaws.com","event_name":"DeleteTrail","status":{"error_code":null,"error_message_present":false,"outcome":"succeeded"},"request_parameters":{"name":"trail"}}`)
	facts := Analyze(Input{Tool: "aws.cloudtrail_event", Args: raw})
	if len(facts.CloudAuditSecurityOperations) != 1 {
		t.Fatalf("facts=%+v", facts.CloudAuditSecurityOperations)
	}
	if got := facts.EnforcementProjection().CloudAuditSecurityOperations; len(got) != 0 {
		t.Fatalf("audit observation entered enforcement projection: %+v", got)
	}
}
