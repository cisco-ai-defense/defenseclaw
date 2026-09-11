// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

const sourceAWSRoleTrustPolicy = `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:user/dev-jdoe"}, "Action": "sts:AssumeRole"}]}`

func TestExactCloudIAMPrincipalOperationUsesSourceAWSCLIShapes(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		operation CloudIAMPrincipalOperation
		wantOp    OperationKind
	}{
		{
			name: "source user create", command: "create-user --user-name backdoor-admin",
			operation: CloudIAMUserCreate, wantOp: OperationAccountChange,
		},
		{
			name: "source user create with path", command: "create-user --user-name temp-admin --path /",
			operation: CloudIAMUserCreate, wantOp: OperationAccountChange,
		},
		{
			name:      "source user administrator attach",
			command:   "attach-user-policy --user-name backdoor-admin --policy-arn " + awsAdministratorAccessARN,
			operation: CloudIAMUserAdminAttach, wantOp: OperationPermissionChange,
		},
		{
			name:      "source role create",
			command:   "create-role --role-name BackdoorAdminRole --assume-role-policy-document '" + sourceAWSRoleTrustPolicy + "'",
			operation: CloudIAMRoleCreate, wantOp: OperationAccountChange,
		},
		{
			name:      "source role administrator attach",
			command:   "attach-role-policy --role-name BackdoorAdminRole --policy-arn " + awsAdministratorAccessARN,
			operation: CloudIAMRoleAdminAttach, wantOp: OperationPermissionChange,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(cloudIAMTestInput(t, test.command))
			if facts.Parse.Status != StatusComplete || !facts.EnforcementEligible() {
				t.Fatalf("parse=%+v commands=%+v, want complete executable projection", facts.Parse, facts.Commands)
			}
			operation, digest, ok := ExactCloudIAMPrincipalOperation(facts)
			if !ok || operation != test.operation || !validPrivateDigest(digest) {
				t.Fatalf("operation=%q digest=%q ok=%t", operation, digest, ok)
			}
			if len(facts.Commands) != 1 || facts.Commands[0].Program != "aws" ||
				!commandHasOperation(facts.Commands[0], test.wantOp) {
				t.Fatalf("commands=%+v, want aws/%s", facts.Commands, test.wantOp)
			}
			if test.operation == CloudIAMUserAdminAttach ||
				test.operation == CloudIAMRoleAdminAttach {
				if !commandHasOperation(facts.Commands[0], OperationPrivilege) ||
					!ExactCloudIAMAdministratorAttachment(facts) {
					t.Fatalf("administrator attachment did not expose exact CEL facts: %+v", facts.Commands[0])
				}
			}
		})
	}
}

func TestCloudIAMPrincipalIdentityJoinsOnlySameKindAndExactName(t *testing.T) {
	digest := func(command string) (CloudIAMPrincipalOperation, string) {
		t.Helper()
		operation, value, ok := ExactCloudIAMPrincipalOperation(
			Analyze(cloudIAMTestInput(t, command)),
		)
		if !ok {
			t.Fatalf("no operation for %q", command)
		}
		return operation, value
	}
	_, createdUser := digest("create-user --user-name backdoor-admin")
	_, attachedUser := digest("attach-user-policy --user-name backdoor-admin --policy-arn " + awsAdministratorAccessARN)
	_, mismatchedUser := digest("attach-user-policy --user-name other-admin --policy-arn " + awsAdministratorAccessARN)
	_, createdRole := digest("create-role --role-name backdoor-admin --assume-role-policy-document '" + sourceAWSRoleTrustPolicy + "'")
	_, attachedRole := digest("attach-role-policy --role-name backdoor-admin --policy-arn " + awsAdministratorAccessARN)

	if createdUser != attachedUser {
		t.Fatal("same exact AWS user did not produce the same opaque identity")
	}
	if createdUser == mismatchedUser || createdUser == createdRole || createdUser == attachedRole {
		t.Fatal("different name or principal kind collided in opaque identity")
	}
	if createdRole != attachedRole {
		t.Fatal("same exact AWS role did not produce the same opaque identity")
	}
}

func TestCloudIAMPrincipalOperationAbstainsOnUnresolvedOrOpenShapes(t *testing.T) {
	tests := []struct {
		name string
		tool string
		args map[string]any
	}{
		{name: "dynamic user", tool: "aws_cli", args: map[string]any{"service": "iam", "command": "create-user --user-name $USER"}},
		{name: "placeholder user", tool: "aws_cli", args: map[string]any{"service": "iam", "command": "attach-user-policy --user-name <user> --policy-arn " + awsAdministratorAccessARN}},
		{name: "custom policy unresolved", tool: "aws_cli", args: map[string]any{"service": "iam", "command": "attach-user-policy --user-name backdoor-admin --policy-arn arn:aws:iam::123456789012:policy/Admin"}},
		{name: "inline wildcard existing user", tool: "aws_cli", args: map[string]any{"service": "iam", "command": `put-user-policy --user-name existing --policy-name Admin --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'`}},
		{name: "reordered attach flags", tool: "aws_cli", args: map[string]any{"service": "iam", "command": "attach-user-policy --policy-arn " + awsAdministratorAccessARN + " --user-name backdoor-admin"}},
		{name: "extra option", tool: "aws_cli", args: map[string]any{"service": "iam", "command": "create-user --user-name backdoor-admin --tags Key=Fixture,Value=True"}},
		{name: "gcp service", tool: "aws_cli", args: map[string]any{"service": "gcp", "command": "create-user --user-name backdoor-admin"}},
		{name: "raw shell not stable provider context", tool: "shell", args: map[string]any{"command": "aws iam create-user --user-name backdoor-admin"}},
		{name: "multiple commands", tool: "aws_cli", args: map[string]any{"service": "iam", "command": "create-user --user-name backdoor-admin; whoami"}},
		{name: "unknown argument field", tool: "aws_cli", args: map[string]any{"service": "iam", "command": "create-user --user-name backdoor-admin", "profile": "production"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(test.args)
			if err != nil {
				t.Fatal(err)
			}
			facts := Analyze(Input{Tool: test.tool, Args: raw, CWD: "/repo"})
			if operation, digest, ok := ExactCloudIAMPrincipalOperation(facts); ok || operation != "" || digest != "" {
				t.Fatalf("unresolved shape escaped: operation=%q digest=%q facts=%+v", operation, digest, facts)
			}
			if ExactCloudIAMAdministratorAttachment(facts) {
				t.Fatalf("unresolved shape completed administrator attachment: %+v", facts)
			}
		})
	}
}

func TestCloudIAMRoleTrustPolicyIsClosed(t *testing.T) {
	for _, value := range []string{
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"${PRINCIPAL}"},"Action":"sts:AssumeRole"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/dev-jdoe"},"Action":"sts:AssumeRole","Condition":{}}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::123456789012:user/dev-jdoe"},"Action":"sts:AssumeRole"}]}`,
		`{"Version":"2012-10-17","Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/dev-jdoe"},"Action":"sts:AssumeRole"}]}`,
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/dev-jdoe"},"Action":"sts:AssumeRole"}]} {"extra":true}`,
	} {
		if exactAWSRoleTrustPolicy(value) {
			t.Fatalf("open or non-source trust policy accepted: %s", value)
		}
	}
}

func TestAWSCLIUnownedCommandsNeverBecomeShellFacts(t *testing.T) {
	for _, test := range []struct {
		name    string
		tool    string
		service string
		command string
	}{
		{name: "shell payload in IAM field", tool: "aws_cli", service: "iam", command: "rm -rf /"},
		{name: "case variant cannot bypass closure", tool: "AWS_CLI", service: "iam", command: "rm -rf /"},
		{name: "unrelated service", tool: "aws_cli", service: "s3", command: "rm -rf /"},
		{name: "unowned IAM read", tool: "aws_cli", service: "iam", command: "list-users"},
		{name: "shell compound after candidate", tool: "aws_cli", service: "iam", command: "create-user --user-name fixture; rm -rf /"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{
				"service": test.service, "command": test.command,
			})
			if err != nil {
				t.Fatal(err)
			}
			facts := Analyze(Input{Tool: test.tool, Args: raw, CWD: "/repo"})
			if facts.Parse.Status != StatusPartial || len(facts.Commands) != 0 ||
				len(facts.Paths) != 0 || len(facts.CloudIAMPrincipalOperations) != 0 {
				t.Fatalf("unowned aws_cli material escaped closed extraction: %+v", facts)
			}
		})
	}
}

func cloudIAMTestInput(t *testing.T, command string) Input {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"service": "iam", "command": command})
	if err != nil {
		t.Fatal(err)
	}
	return Input{Tool: "aws_cli", Args: raw, CWD: "/repo"}
}
