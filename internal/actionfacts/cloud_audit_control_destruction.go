// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// classifyCloudAuditControlDestruction adds destructive audit-control
// semantics only to the three closed argv forms accepted by
// ExactCloudAuditControlDestruction. Near-miss cloud administration remains
// owned by the existing provider parser or falls back conservatively.
func classifyCloudAuditControlDestruction(command *CommandFact) bool {
	if command == nil || !command.ArgvComplete ||
		!staticArguments(command.Arguments) ||
		!exactCloudAuditControlDestructionArgv(command.Argv) {
		return false
	}
	addOperation(command, OperationDelete)
	addOperation(command, OperationConfigChange)
	addOperation(command, OperationPolicyBypass)
	return true
}

// ExactCloudAuditControlDestruction proves one direct static operation:
//
//   - AWS CloudTrail stop-logging for one literal trail and region;
//   - AWS CloudTrail delete-trail for one literal trail and region; or
//   - GCP deletion of one project's Cloud Audit Activity log.
//
// No Azure form is accepted because the mined sources contained no complete,
// closed Azure audit-destruction command suitable for deterministic proof.
//
// It deliberately rejects provider setup, wrappers, control flow, pipelines,
// redirects, multiple commands, placeholders, dynamic identifiers, and broad
// logging administration. The proof is suitable for an alert; account-level
// blocking still requires trusted deployment policy outside ActionFacts.
func ExactCloudAuditControlDestruction(facts Facts) bool {
	if !facts.Authoritative() || len(facts.Commands) != 1 {
		return false
	}
	command := facts.Commands[0]
	if !exactUnconditionalTopLevelCommand(command) || !command.ArgvComplete ||
		!staticArguments(command.Arguments) ||
		!hasFactOperation(command, OperationDelete) ||
		!hasFactOperation(command, OperationConfigChange) ||
		!hasFactOperation(command, OperationPolicyBypass) {
		return false
	}
	return exactCloudAuditControlDestructionArgv(command.Argv)
}

func exactCloudAuditControlDestructionArgv(argv []string) bool {
	if exactAWSCloudTrailAuditDestructionArgv(argv) {
		return true
	}
	return exactGCPCloudAuditActivityDeleteArgv(argv)
}

func exactAWSCloudTrailAuditDestructionArgv(argv []string) bool {
	if len(argv) != 7 || argv[0] != "aws" || argv[1] != "cloudtrail" ||
		argv[2] != "stop-logging" && argv[2] != "delete-trail" {
		return false
	}
	values := make(map[string]string, 2)
	for index := 3; index < len(argv); index += 2 {
		option := argv[index]
		if option != "--name" && option != "--region" || values[option] != "" {
			return false
		}
		values[option] = argv[index+1]
	}
	return validAWSCloudTrailName(values["--name"]) &&
		validAWSRegion(values["--region"])
}

func validAWSCloudTrailName(value string) bool {
	if len(value) < 3 || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || strings.ContainsRune("._-", char) {
			continue
		}
		return false
	}
	return true
}

func validAWSRegion(value string) bool {
	if len(value) < 8 || len(value) > 32 || value[0] == '-' ||
		value[len(value)-1] < '0' || value[len(value)-1] > '9' ||
		strings.Count(value, "-") < 2 || strings.Contains(value, "--") {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func exactGCPCloudAuditActivityDeleteArgv(argv []string) bool {
	if len(argv) != 6 || argv[0] != "gcloud" || argv[1] != "logging" ||
		argv[2] != "logs" || argv[3] != "delete" || argv[5] != "--quiet" {
		return false
	}
	const prefix = "projects/"
	const suffix = "/logs/cloudaudit.googleapis.com%2Factivity"
	resource := argv[4]
	if !strings.HasPrefix(resource, prefix) || !strings.HasSuffix(resource, suffix) {
		return false
	}
	project := strings.TrimSuffix(strings.TrimPrefix(resource, prefix), suffix)
	return validGCPProjectID(project)
}

func validGCPProjectID(value string) bool {
	if len(value) < 6 || len(value) > 30 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	last := value[len(value)-1]
	if !(last >= 'a' && last <= 'z' || last >= '0' && last <= '9') {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' {
			continue
		}
		return false
	}
	return true
}
