// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	cloudIAMPrincipalDigestDomain = "defenseclaw/actionfacts/cloud-iam-principal/v1"
	awsAdministratorAccessARN     = "arn:aws:iam::aws:policy/AdministratorAccess"
)

var (
	awsIAMPrincipalNamePattern = regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{1,64}$`)
	awsIAMPrincipalARNPattern  = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:(?:user|role)/[A-Za-z0-9_+=,.@/-]{1,512}$`)
)

// ExactCloudIAMPrincipalOperation returns one value-free AWS IAM operation
// and its exact principal identity. Only the closed structured aws_cli schema
// is eligible; raw shell commands and unresolved identities abstain.
func ExactCloudIAMPrincipalOperation(
	facts Facts,
) (CloudIAMPrincipalOperation, string, bool) {
	if !facts.Authoritative() || !facts.EnforcementEligible() ||
		len(facts.CloudIAMPrincipalOperations) != 1 {
		return "", "", false
	}
	fact := facts.CloudIAMPrincipalOperations[0]
	switch fact.Operation {
	case CloudIAMUserCreate, CloudIAMRoleCreate,
		CloudIAMUserAdminAttach, CloudIAMRoleAdminAttach,
		CloudIAMUserWildcardPolicy, CloudIAMRoleWildcardPolicy:
	default:
		return "", "", false
	}
	if !validPrivateDigest(fact.PrincipalIdentityDigest) {
		return "", "", false
	}
	return fact.Operation, fact.PrincipalIdentityDigest, true
}

// ExactCloudIAMAdministratorAttachment is the code-owned prerequisite for the
// detection-only CEL owner. It deliberately does not claim that a standalone
// administrator attachment is unauthorized.
func ExactCloudIAMAdministratorAttachment(facts Facts) bool {
	operation, _, ok := ExactCloudIAMPrincipalOperation(facts)
	return ok && (operation == CloudIAMUserAdminAttach ||
		operation == CloudIAMRoleAdminAttach)
}

// ExactCloudIAMWildcardInlinePolicy recognizes only an exact inline Allow
// policy with Action "*" and Resource "*" for one static user or role.
func ExactCloudIAMWildcardInlinePolicy(facts Facts) bool {
	operation, _, ok := ExactCloudIAMPrincipalOperation(facts)
	return ok && (operation == CloudIAMUserWildcardPolicy ||
		operation == CloudIAMRoleWildcardPolicy)
}

func extractExactAWSCLIArgs(raw json.RawMessage) extractedInput {
	if len(bytes.TrimSpace(raw)) == 0 {
		return extractedInput{status: StatusNotApplicable}
	}
	if len(raw) > maxArgsJSONBytes {
		return extractedInput{status: StatusLimitExceeded, issues: []IssueCode{IssueInputLimit}}
	}
	if !utf8.Valid(raw) {
		return extractedInput{status: StatusInvalid, issues: []IssueCode{IssueInvalidUTF8}}
	}
	if issue := validateJSONWithStringLimit(raw, maxCommandBytes); issue != "" {
		status := StatusInvalid
		if issue == IssueDuplicateJSONKey {
			status = StatusAmbiguous
		} else if issue == IssueInputLimit || issue == IssueDepthLimit {
			status = StatusLimitExceeded
		}
		return extractedInput{status: status, issues: []IssueCode{issue}}
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || len(object) != 2 {
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	service, serviceOK := object["service"].(string)
	command, commandOK := object["command"].(string)
	if !serviceOK || !commandOK ||
		(service != "iam" && service != "s3" && service != "s3api") || command == "" ||
		strings.TrimSpace(command) != command || strings.IndexByte(command, 0) >= 0 {
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	for key := range object {
		if key != "service" && key != "command" {
			return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
		}
	}
	synthesized := "aws " + service + " " + command
	parsed := parsePOSIX(synthesized, 1, 0)
	if parsed.status != StatusComplete || len(parsed.commands) != 1 {
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	_, _, _, iamOK := exactCloudIAMPrincipalArgv(parsed.commands[0].Argv)
	_, resourceOK := exactAWSCloudResourceMutation(parsed.commands[0].Argv)
	if !iamOK && !resourceOK {
		return extractedInput{status: StatusPartial, issues: []IssueCode{IssueUnknownOperandGrammar}}
	}
	return extractedInput{
		command: synthesized,
		status:  StatusComplete,
	}
}

func projectCloudIAMPrincipalOperations(
	input Input,
	facts Facts,
) []CloudIAMPrincipalOperationFact {
	if input.Tool != "aws_cli" || !facts.Authoritative() ||
		!facts.EnforcementEligible() || len(facts.Commands) != 1 {
		return nil
	}
	if extracted := extractExactAWSCLIArgs(input.Args); extracted.status != StatusComplete ||
		extracted.command == "" {
		return nil
	}
	operation, kind, name, ok := exactCloudIAMPrincipalArgv(facts.Commands[0].Argv)
	if !ok {
		return nil
	}
	digest := cloudIAMPrincipalIdentityDigest(kind, name)
	if digest == "" {
		return nil
	}
	return []CloudIAMPrincipalOperationFact{{
		Operation: operation, PrincipalIdentityDigest: digest,
	}}
}

func classifyCloudIAMPrincipalAdministration(command *CommandFact) bool {
	if command == nil || !command.ArgvComplete || command.Effect != EffectExecute {
		return false
	}
	operation, _, _, ok := exactCloudIAMPrincipalArgv(command.Argv)
	if !ok {
		return false
	}
	switch operation {
	case CloudIAMUserCreate, CloudIAMRoleCreate:
		addOperation(command, OperationAccountChange)
		addOperation(command, OperationWrite)
	case CloudIAMUserAdminAttach, CloudIAMRoleAdminAttach:
		addOperation(command, OperationPermissionChange)
		addOperation(command, OperationPrivilege)
		addOperation(command, OperationConfigChange)
	case CloudIAMUserWildcardPolicy, CloudIAMRoleWildcardPolicy:
		addOperation(command, OperationPermissionChange)
		addOperation(command, OperationPrivilege)
		addOperation(command, OperationConfigChange)
	default:
		return false
	}
	return true
}

func exactCloudIAMPrincipalArgv(
	argv []string,
) (CloudIAMPrincipalOperation, string, string, bool) {
	if len(argv) < 4 || argv[0] != "aws" || argv[1] != "iam" {
		return "", "", "", false
	}
	switch argv[2] {
	case "create-user":
		if len(argv) != 5 && len(argv) != 7 {
			return "", "", "", false
		}
		if argv[3] != "--user-name" || !exactAWSIAMPrincipalName(argv[4]) {
			return "", "", "", false
		}
		if len(argv) == 7 && (argv[5] != "--path" || argv[6] != "/") {
			return "", "", "", false
		}
		return CloudIAMUserCreate, "user", argv[4], true
	case "create-role":
		if len(argv) != 7 || argv[3] != "--role-name" ||
			!exactAWSIAMPrincipalName(argv[4]) ||
			argv[5] != "--assume-role-policy-document" ||
			!exactAWSRoleTrustPolicy(argv[6]) {
			return "", "", "", false
		}
		return CloudIAMRoleCreate, "role", argv[4], true
	case "attach-user-policy":
		if len(argv) != 7 || argv[3] != "--user-name" ||
			!exactAWSIAMPrincipalName(argv[4]) || argv[5] != "--policy-arn" ||
			argv[6] != awsAdministratorAccessARN {
			return "", "", "", false
		}
		return CloudIAMUserAdminAttach, "user", argv[4], true
	case "attach-role-policy":
		if len(argv) != 7 || argv[3] != "--role-name" ||
			!exactAWSIAMPrincipalName(argv[4]) || argv[5] != "--policy-arn" ||
			argv[6] != awsAdministratorAccessARN {
			return "", "", "", false
		}
		return CloudIAMRoleAdminAttach, "role", argv[4], true
	case "put-user-policy", "put-role-policy":
		if len(argv) != 9 {
			return "", "", "", false
		}
		kind, nameFlag, operation := "user", "--user-name", CloudIAMUserWildcardPolicy
		if argv[2] == "put-role-policy" {
			kind, nameFlag, operation = "role", "--role-name", CloudIAMRoleWildcardPolicy
		}
		if argv[3] != nameFlag || !exactAWSIAMPrincipalName(argv[4]) ||
			argv[5] != "--policy-name" || !exactAWSIAMPolicyName(argv[6]) ||
			argv[7] != "--policy-document" || !exactAWSWildcardAdminPolicy(argv[8]) {
			return "", "", "", false
		}
		return operation, kind, argv[4], true
	default:
		return "", "", "", false
	}
}

func exactAWSIAMPolicyName(name string) bool {
	return len(name) <= 128 && awsIAMPrincipalNamePattern.MatchString(name) &&
		!strings.ContainsAny(name, "$`*?[]{}<>'\"")
}

func exactAWSWildcardAdminPolicy(value string) bool {
	if value == "" || len(value) > maxCommandBytes || strings.ContainsAny(value, "$`") ||
		validateJSONWithStringLimit([]byte(value), maxCommandBytes) != "" {
		return false
	}
	var policy struct {
		Version   string `json:"Version"`
		Statement []struct {
			Effect   string `json:"Effect"`
			Action   string `json:"Action"`
			Resource string `json:"Resource"`
		} `json:"Statement"`
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil || policy.Version != "2012-10-17" ||
		len(policy.Statement) != 1 {
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return false
	}
	statement := policy.Statement[0]
	return statement.Effect == "Allow" && statement.Action == "*" &&
		statement.Resource == "*"
}

func exactAWSIAMPrincipalName(name string) bool {
	return awsIAMPrincipalNamePattern.MatchString(name) &&
		!strings.ContainsAny(name, "$`*?[]{}<>'\"")
}

func exactAWSRoleTrustPolicy(value string) bool {
	if value == "" || len(value) > maxCommandBytes || strings.ContainsAny(value, "$`") {
		return false
	}
	if validateJSONWithStringLimit([]byte(value), maxCommandBytes) != "" {
		return false
	}
	var policy struct {
		Version   string `json:"Version"`
		Statement []struct {
			Effect    string            `json:"Effect"`
			Principal map[string]string `json:"Principal"`
			Action    string            `json:"Action"`
		} `json:"Statement"`
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil || policy.Version != "2012-10-17" ||
		len(policy.Statement) != 1 {
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return false
	}
	statement := policy.Statement[0]
	if statement.Effect != "Allow" || statement.Action != "sts:AssumeRole" ||
		len(statement.Principal) != 1 {
		return false
	}
	principal, ok := statement.Principal["AWS"]
	return ok && awsIAMPrincipalARNPattern.MatchString(principal)
}

func cloudIAMPrincipalIdentityDigest(kind, name string) string {
	if (kind != "user" && kind != "role") || !exactAWSIAMPrincipalName(name) {
		return ""
	}
	hash := sha256.New()
	var length [4]byte
	for _, value := range []string{
		cloudIAMPrincipalDigestDomain, "aws", kind, name,
	} {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
