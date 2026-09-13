// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// classifyCloudAuditControlDestruction adds destructive audit-control
// semantics only to the closed argv forms accepted by
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
//   - AWS CloudTrail delete-trail for one literal trail and region;
//   - AWS deletion of one literal VPC flow log;
//   - AWS deletion of one literal Route 53 Resolver query-log configuration;
//   - AWS CloudTrail replacement with one selector that excludes management
//     events; or
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
	if exactAWSCloudTrailAuditDestructionArgv(argv) ||
		exactAWSFlowLogDeleteArgv(argv) ||
		exactAWSResolverQueryLogDeleteArgv(argv) ||
		exactAWSCloudTrailEventSelectorsDisableArgv(argv) {
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

func exactAWSFlowLogDeleteArgv(argv []string) bool {
	return exactAWSSingleResourceOperation(
		argv,
		"ec2",
		"delete-flow-logs",
		"--flow-log-ids",
		validAWSFlowLogID,
	)
}

func exactAWSResolverQueryLogDeleteArgv(argv []string) bool {
	return exactAWSSingleResourceOperation(
		argv,
		"route53resolver",
		"delete-resolver-query-log-config",
		"--resolver-query-log-config-id",
		validAWSResolverQueryLogConfigID,
	)
}

func exactAWSSingleResourceOperation(
	argv []string,
	service string,
	operation string,
	resourceOption string,
	validResource func(string) bool,
) bool {
	if len(argv) != 5 && len(argv) != 7 || argv[0] != "aws" ||
		argv[1] != service || argv[2] != operation {
		return false
	}
	values := make(map[string]string, 2)
	for index := 3; index < len(argv); index += 2 {
		option := argv[index]
		if option != resourceOption && option != "--region" || values[option] != "" {
			return false
		}
		values[option] = argv[index+1]
	}
	if !validResource(values[resourceOption]) {
		return false
	}
	return values["--region"] == "" || validAWSRegion(values["--region"])
}

func validAWSFlowLogID(value string) bool {
	return validAWSHexResourceID(value, "fl-")
}

func validAWSResolverQueryLogConfigID(value string) bool {
	const prefix = "rqlc-"
	if !strings.HasPrefix(value, prefix) || len(value) < len(prefix)+8 ||
		len(value) > len(prefix)+64 {
		return false
	}
	for _, char := range value[len(prefix):] {
		if char < '0' || char > '9' && char < 'a' || char > 'f' {
			return false
		}
	}
	return true
}

func validAWSHexResourceID(value string, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+17 {
		return false
	}
	for _, char := range value[len(prefix):] {
		if char < '0' || char > '9' && char < 'a' || char > 'f' {
			return false
		}
	}
	return true
}

func exactAWSCloudTrailEventSelectorsDisableArgv(argv []string) bool {
	if len(argv) != 7 && len(argv) != 9 || argv[0] != "aws" ||
		argv[1] != "cloudtrail" || argv[2] != "put-event-selectors" {
		return false
	}
	values := make(map[string]string, 3)
	for index := 3; index < len(argv); index += 2 {
		option := argv[index]
		if option != "--trail-name" && option != "--event-selectors" && option != "--region" ||
			values[option] != "" {
			return false
		}
		values[option] = argv[index+1]
	}
	if !validAWSCloudTrailName(values["--trail-name"]) ||
		values["--event-selectors"] == "" ||
		values["--region"] != "" && !validAWSRegion(values["--region"]) {
		return false
	}
	return exactAWSManagementEventsDisabledSelector(values["--event-selectors"])
}

func exactAWSManagementEventsDisabledSelector(value string) bool {
	type eventSelector struct {
		ReadWriteType           string `json:"ReadWriteType"`
		IncludeManagementEvents *bool  `json:"IncludeManagementEvents"`
	}
	var selectors []eventSelector
	decoder := json.NewDecoder(bytes.NewBufferString(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&selectors); err != nil || len(selectors) != 1 {
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return false
	}
	selector := selectors[0]
	return selector.ReadWriteType == "ReadOnly" &&
		selector.IncludeManagementEvents != nil &&
		!*selector.IncludeManagementEvents
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
