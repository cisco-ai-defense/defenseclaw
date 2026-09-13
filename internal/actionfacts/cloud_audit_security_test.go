// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
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
		{"disable management writes", "cloudtrail.amazonaws.com", "PutEventSelectors", `{"eventSelectors":[{"includeManagementEvents":false,"readWriteType":"ReadOnly"}],"trailName":"stratus-red-team-ctes-trail-khlvciwdor"}`, `{"account_id":"111111111111"}`, CloudAuditTelemetryDisable},
		{"external EBS snapshot share", "ec2.amazonaws.com", "ModifySnapshotAttribute", `{"attributeType":"CREATE_VOLUME_PERMISSION","createVolumePermission":{"add":{"items":[{"userId":"098797384747"}]}},"snapshotId":"snap-041993b54a9b3af6f"}`, `{"account_id":"756680937392"}`, CloudAuditExternalSnapshotShare},
		{"external AMI share", "ec2.amazonaws.com", "ModifyImageAttribute", `{"attributeType":"launchPermission","imageId":"ami-de1fbCab6ccB03e6D","launchPermission":{"add":{"items":[{"userId":"846424999548"}]}}}`, `{"account_id":"118238665043"}`, CloudAuditExternalSnapshotShare},
		{"external RDS snapshot share", "rds.amazonaws.com", "ModifyDBSnapshotAttribute", `{"attributeName":"restore","dBSnapshotIdentifier":"exfiltration","valuesToAdd":["503161813013"]}`, `{"account_id":"171471557522"}`, CloudAuditExternalSnapshotShare},
		{"worldwide ssh", "ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", `{"cidrIp":"208.236.235.254/0","fromPort":22,"groupId":"sg-003dc7f1f1c686164","ipPermissions":{},"ipProtocol":"tcp","toPort":22}`, `{"account_id":"032092706103"}`, CloudAuditWorldwideSSHExposure},
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
		`{"provider":"aws","event_source":"cloudtrail.amazonaws.com","event_name":"PutEventSelectors","status":{"error_code":null,"error_message_present":false,"outcome":"succeeded"},"request_parameters":{"eventSelectors":[{"includeManagementEvents":true,"readWriteType":"All"}],"trailName":"trail"}}`,
		`{"provider":"aws","event_source":"ec2.amazonaws.com","event_name":"ModifySnapshotAttribute","status":{"error_code":null,"error_message_present":false,"outcome":"succeeded"},"request_parameters":{"attributeType":"CREATE_VOLUME_PERMISSION","createVolumePermission":{"add":{"items":[{"userId":"111111111111"}]}},"snapshotId":"snap-0123456789abcdef0"},"principal":{"account_id":"111111111111"}}`,
		`{"provider":"aws","event_source":"ec2.amazonaws.com","event_name":"AuthorizeSecurityGroupIngress","status":{"error_code":null,"error_message_present":false,"outcome":"succeeded"},"request_parameters":{"cidrIp":"10.0.0.0/8","fromPort":22,"groupId":"sg-0123456789abcdef0","ipProtocol":"tcp","toPort":22}}`,
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

func TestCloudAuditSecurityOperationsRejectUnprovenSensitiveParameters(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		source     string
		event      string
		parameters string
		principal  string
	}{
		{
			name:       "event selectors missing trail name",
			source:     "cloudtrail.amazonaws.com",
			event:      "PutEventSelectors",
			parameters: `{"eventSelectors":[{"includeManagementEvents":false,"readWriteType":"ReadOnly"}]}`,
		},
		{
			name:       "event selectors malformed trail name",
			source:     "cloudtrail.amazonaws.com",
			event:      "PutEventSelectors",
			parameters: `{"eventSelectors":[{"includeManagementEvents":false,"readWriteType":"ReadOnly"}],"trailName":"trail\nname"}`,
		},
		{
			name:       "event selectors overlong trail name",
			source:     "cloudtrail.amazonaws.com",
			event:      "PutEventSelectors",
			parameters: `{"eventSelectors":[{"includeManagementEvents":false,"readWriteType":"ReadOnly"}],"trailName":"` + strings.Repeat("a", 513) + `"}`,
		},
		{
			name:       "event selectors conflicting trail field",
			source:     "cloudtrail.amazonaws.com",
			event:      "PutEventSelectors",
			parameters: `{"eventSelectors":[{"includeManagementEvents":false,"readWriteType":"ReadOnly"}],"name":"other-trail","trailName":"trail"}`,
		},
		{
			name:       "event selectors benign management coverage",
			source:     "cloudtrail.amazonaws.com",
			event:      "PutEventSelectors",
			parameters: `{"eventSelectors":[{"includeManagementEvents":true,"readWriteType":"All"}],"trailName":"trail"}`,
		},
		{
			name:       "worldwide ssh missing group id",
			source:     "ec2.amazonaws.com",
			event:      "AuthorizeSecurityGroupIngress",
			parameters: `{"cidrIp":"0.0.0.0/0","fromPort":22,"ipProtocol":"tcp","toPort":22}`,
		},
		{
			name:       "worldwide ssh malformed group id",
			source:     "ec2.amazonaws.com",
			event:      "AuthorizeSecurityGroupIngress",
			parameters: `{"cidrIp":"0.0.0.0/0","fromPort":22,"groupId":"sg-production","ipProtocol":"tcp","toPort":22}`,
		},
		{
			name:       "worldwide ssh conflicting nested permission",
			source:     "ec2.amazonaws.com",
			event:      "AuthorizeSecurityGroupIngress",
			parameters: `{"cidrIp":"0.0.0.0/0","fromPort":22,"groupId":"sg-0123456789abcdef0","ipPermissions":{"items":[{"cidrIp":"10.0.0.0/8"}]},"ipProtocol":"tcp","toPort":22}`,
		},
		{
			name:       "worldwide ssh conflicting extra field",
			source:     "ec2.amazonaws.com",
			event:      "AuthorizeSecurityGroupIngress",
			parameters: `{"cidrIp":"0.0.0.0/0","fromPort":22,"groupId":"sg-0123456789abcdef0","groupName":"default","ipProtocol":"tcp","toPort":22}`,
		},
		{
			name:       "ssh constrained cidr",
			source:     "ec2.amazonaws.com",
			event:      "AuthorizeSecurityGroupIngress",
			parameters: `{"cidrIp":"192.0.2.0/24","fromPort":22,"groupId":"sg-0123456789abcdef0","ipProtocol":"tcp","toPort":22}`,
		},
		{
			name:       "ssh constrained port range",
			source:     "ec2.amazonaws.com",
			event:      "AuthorizeSecurityGroupIngress",
			parameters: `{"cidrIp":"0.0.0.0/0","fromPort":22,"groupId":"sg-0123456789abcdef0","ipProtocol":"tcp","toPort":23}`,
		},
		{
			name:       "ssh ipv6 worldwide alternative",
			source:     "ec2.amazonaws.com",
			event:      "AuthorizeSecurityGroupIngress",
			parameters: `{"cidrIp":"::/0","fromPort":22,"groupId":"sg-0123456789abcdef0","ipProtocol":"tcp","toPort":22}`,
		},
		{
			name:       "snapshot share missing resource",
			source:     "ec2.amazonaws.com",
			event:      "ModifySnapshotAttribute",
			parameters: `{"attributeType":"CREATE_VOLUME_PERMISSION","createVolumePermission":{"add":{"items":[{"userId":"222222222222"}]}}}`,
		},
		{
			name:       "snapshot share malformed resource",
			source:     "ec2.amazonaws.com",
			event:      "ModifySnapshotAttribute",
			parameters: `{"attributeType":"CREATE_VOLUME_PERMISSION","createVolumePermission":{"add":{"items":[{"userId":"222222222222"}]}},"snapshotId":"snapshot-production"}`,
		},
		{
			name:       "snapshot share wrong attribute",
			source:     "ec2.amazonaws.com",
			event:      "ModifySnapshotAttribute",
			parameters: `{"attributeType":"productCodes","createVolumePermission":{"add":{"items":[{"userId":"222222222222"}]}},"snapshotId":"snap-0123456789abcdef0"}`,
		},
		{
			name:       "snapshot share malformed added account",
			source:     "ec2.amazonaws.com",
			event:      "ModifySnapshotAttribute",
			parameters: `{"attributeType":"CREATE_VOLUME_PERMISSION","createVolumePermission":{"add":{"items":[{"userId":"22222222222x"}]}},"snapshotId":"snap-0123456789abcdef0"}`,
		},
		{
			name:       "snapshot share missing added account",
			source:     "ec2.amazonaws.com",
			event:      "ModifySnapshotAttribute",
			parameters: `{"attributeType":"CREATE_VOLUME_PERMISSION","createVolumePermission":{"add":{"items":[]}},"snapshotId":"snap-0123456789abcdef0"}`,
		},
		{
			name:       "snapshot share malformed owner account",
			source:     "ec2.amazonaws.com",
			event:      "ModifySnapshotAttribute",
			parameters: `{"attributeType":"CREATE_VOLUME_PERMISSION","createVolumePermission":{"add":{"items":[{"userId":"222222222222"}]}},"snapshotId":"snap-0123456789abcdef0"}`,
			principal:  `{"account_id":"11111111111x"}`,
		},
		{
			name:       "snapshot share conflicting permission",
			source:     "ec2.amazonaws.com",
			event:      "ModifySnapshotAttribute",
			parameters: `{"attributeType":"CREATE_VOLUME_PERMISSION","createVolumePermission":{"add":{"items":[{"userId":"222222222222"}]}},"launchPermission":{"add":{"items":[{"userId":"222222222222"}]}},"snapshotId":"snap-0123456789abcdef0"}`,
		},
		{
			name:       "snapshot share removes account",
			source:     "ec2.amazonaws.com",
			event:      "ModifySnapshotAttribute",
			parameters: `{"attributeType":"CREATE_VOLUME_PERMISSION","createVolumePermission":{"remove":{"items":[{"userId":"222222222222"}]}},"snapshotId":"snap-0123456789abcdef0"}`,
		},
		{
			name:       "snapshot share retains owner only",
			source:     "ec2.amazonaws.com",
			event:      "ModifySnapshotAttribute",
			parameters: `{"attributeType":"CREATE_VOLUME_PERMISSION","createVolumePermission":{"add":{"items":[{"userId":"111111111111"}]}},"snapshotId":"snap-0123456789abcdef0"}`,
		},
		{
			name:       "image share missing resource",
			source:     "ec2.amazonaws.com",
			event:      "ModifyImageAttribute",
			parameters: `{"attributeType":"launchPermission","imageId":"","launchPermission":{"add":{"items":[{"userId":"222222222222"}]}}}`,
		},
		{
			name:       "image share wrong attribute",
			source:     "ec2.amazonaws.com",
			event:      "ModifyImageAttribute",
			parameters: `{"attributeType":"description","imageId":"ami-0123456789abcdef0","launchPermission":{"add":{"items":[{"userId":"222222222222"}]}}}`,
		},
		{
			name:       "image share malformed added account",
			source:     "ec2.amazonaws.com",
			event:      "ModifyImageAttribute",
			parameters: `{"attributeType":"launchPermission","imageId":"ami-0123456789abcdef0","launchPermission":{"add":{"items":[{"userId":"22222222222"}]}}}`,
		},
		{
			name:       "image share conflicting permission field",
			source:     "ec2.amazonaws.com",
			event:      "ModifyImageAttribute",
			parameters: `{"attributeType":"launchPermission","createVolumePermission":{"add":{"items":[{"userId":"222222222222"}]}},"imageId":"ami-0123456789abcdef0","launchPermission":{"add":{"items":[{"userId":"222222222222"}]}}}`,
		},
		{
			name:       "image share retains owner only",
			source:     "ec2.amazonaws.com",
			event:      "ModifyImageAttribute",
			parameters: `{"attributeType":"launchPermission","imageId":"ami-0123456789abcdef0","launchPermission":{"add":{"items":[{"userId":"111111111111"}]}}}`,
		},
		{
			name:       "rds share missing resource",
			source:     "rds.amazonaws.com",
			event:      "ModifyDBSnapshotAttribute",
			parameters: `{"attributeName":"restore","valuesToAdd":["222222222222"]}`,
		},
		{
			name:       "rds share malformed resource",
			source:     "rds.amazonaws.com",
			event:      "ModifyDBSnapshotAttribute",
			parameters: `{"attributeName":"restore","dBSnapshotIdentifier":"1invalid--snapshot-","valuesToAdd":["222222222222"]}`,
		},
		{
			name:       "rds share wrong attribute",
			source:     "rds.amazonaws.com",
			event:      "ModifyDBSnapshotAttribute",
			parameters: `{"attributeName":"visibility","dBSnapshotIdentifier":"snapshot","valuesToAdd":["222222222222"]}`,
		},
		{
			name:       "rds share malformed added account",
			source:     "rds.amazonaws.com",
			event:      "ModifyDBSnapshotAttribute",
			parameters: `{"attributeName":"restore","dBSnapshotIdentifier":"snapshot","valuesToAdd":["22222222222x"]}`,
		},
		{
			name:       "rds share missing added account",
			source:     "rds.amazonaws.com",
			event:      "ModifyDBSnapshotAttribute",
			parameters: `{"attributeName":"restore","dBSnapshotIdentifier":"snapshot","valuesToAdd":[]}`,
		},
		{
			name:       "rds share conflicting removal",
			source:     "rds.amazonaws.com",
			event:      "ModifyDBSnapshotAttribute",
			parameters: `{"attributeName":"restore","dBSnapshotIdentifier":"snapshot","valuesToAdd":["222222222222"],"valuesToRemove":["333333333333"]}`,
		},
		{
			name:       "rds share retains owner only",
			source:     "rds.amazonaws.com",
			event:      "ModifyDBSnapshotAttribute",
			parameters: `{"attributeName":"restore","dBSnapshotIdentifier":"snapshot","valuesToAdd":["111111111111"]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			principal := tc.principal
			if principal == "" {
				principal = `{"account_id":"111111111111"}`
			}
			args := json.RawMessage(`{"provider":"aws","event_source":"` + tc.source + `","event_name":"` + tc.event + `","status":{"error_code":null,"error_message_present":false,"outcome":"succeeded"},"request_parameters":` + tc.parameters + `,"principal":` + principal + `}`)
			facts := Analyze(Input{Tool: "aws.cloudtrail_event", Args: args})
			if operations := ExactCloudAuditSecurityOperations(facts); len(operations) != 0 {
				t.Fatalf("unproven operation projected: %+v args=%s", operations, args)
			}
		})
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
