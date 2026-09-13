// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"net/netip"
	"strings"
)

var cloudAuditOuterKeys = map[string]bool{
	"provider": true, "event_source": true, "event_name": true,
	"status": true, "request_parameters": true, "event_id": true,
	"event_time": true, "principal": true, "region": true,
	"request_id": true, "technique": true,
}

// ExactCloudAuditSecurityOperations returns validated, value-free audit facts.
func ExactCloudAuditSecurityOperations(facts Facts) []CloudAuditSecurityOperationFact {
	result := make([]CloudAuditSecurityOperationFact, 0, len(facts.CloudAuditSecurityOperations))
	for _, fact := range facts.CloudAuditSecurityOperations {
		if fact.Provider != "aws" || !fact.Exact || !validCloudAuditOperation(fact.Operation) {
			return nil
		}
		result = append(result, fact)
	}
	return result
}

func validCloudAuditOperation(operation CloudAuditSecurityOperation) bool {
	switch operation {
	case CloudAuditTelemetryDisable, CloudAuditExternalSnapshotShare,
		CloudAuditWorldwideSSHExposure, CloudAuditAdministratorAttach:
		return true
	default:
		return false
	}
}

func projectCloudAuditSecurityOperations(input Input) []CloudAuditSecurityOperationFact {
	if input.Tool != "aws.cloudtrail_event" || input.Command != "" || len(input.Argv) != 0 {
		return nil
	}
	operation, ok := exactCloudAuditSecurityOperationInput(input.Args)
	if !ok {
		return nil
	}
	return []CloudAuditSecurityOperationFact{{Provider: "aws", Operation: operation, Exact: true}}
}

func exactCloudAuditSecurityOperationInput(raw json.RawMessage) (CloudAuditSecurityOperation, bool) {
	object, problem := exactJSONObject(raw)
	if problem.status != "" || !exactObjectKeys(object, cloudAuditOuterKeys) ||
		exactString(object["provider"]) != "aws" || !successfulCloudAuditStatus(object["status"]) {
		return "", false
	}
	source, name := exactString(object["event_source"]), exactString(object["event_name"])
	parameters, ok := object["request_parameters"].(map[string]any)
	if !ok {
		return "", false
	}
	return exactCloudAuditOperation(source, name, parameters, object["principal"])
}

func exactObjectKeys(object map[string]any, allowed map[string]bool) bool {
	if object == nil {
		return false
	}
	for key := range object {
		if !allowed[key] {
			return false
		}
	}
	return true
}

func successfulCloudAuditStatus(value any) bool {
	status, ok := value.(map[string]any)
	if !ok || len(status) != 3 || exactString(status["outcome"]) != "succeeded" ||
		status["error_code"] != nil {
		return false
	}
	present, ok := status["error_message_present"].(bool)
	return ok && !present
}

func exactCloudAuditOperation(source, name string, parameters map[string]any, principal any) (CloudAuditSecurityOperation, bool) {
	switch source + ":" + name {
	case "cloudtrail.amazonaws.com:DeleteTrail", "cloudtrail.amazonaws.com:StopLogging":
		return CloudAuditTelemetryDisable, exactBoundedCloudIdentity(parameters["name"])
	case "ec2.amazonaws.com:DeleteFlowLogs":
		request, ok := parameters["DeleteFlowLogsRequest"].(map[string]any)
		flowLog, requestOK := request["FlowLogId"].(map[string]any)
		return CloudAuditTelemetryDisable, ok && requestOK && exactBoundedCloudIdentity(flowLog["content"])
	case "route53resolver.amazonaws.com:DeleteResolverQueryLogConfig":
		return CloudAuditTelemetryDisable, exactBoundedCloudIdentity(parameters["resolverQueryLogConfigId"])
	case "cloudtrail.amazonaws.com:PutEventSelectors":
		if exactReadOnlyEventSelectorDisable(parameters) {
			return CloudAuditTelemetryDisable, true
		}
	case "ec2.amazonaws.com:ModifySnapshotAttribute", "ec2.amazonaws.com:ModifyImageAttribute",
		"rds.amazonaws.com:ModifyDBSnapshotAttribute":
		if exactExternalSnapshotShare(parameters, principal) {
			return CloudAuditExternalSnapshotShare, true
		}
	case "ec2.amazonaws.com:AuthorizeSecurityGroupIngress":
		if exactWorldwideSSHIngress(parameters) {
			return CloudAuditWorldwideSSHExposure, true
		}
	case "iam.amazonaws.com:AttachRolePolicy", "iam.amazonaws.com:AttachUserPolicy":
		principalName := parameters["roleName"]
		if name == "AttachUserPolicy" {
			principalName = parameters["userName"]
		}
		if exactString(parameters["policyArn"]) == awsAdministratorAccessARN &&
			awsIAMPrincipalNamePattern.MatchString(exactString(principalName)) {
			return CloudAuditAdministratorAttach, true
		}
	}
	return "", false
}

func exactBoundedCloudIdentity(value any) bool {
	identity := exactString(value)
	return identity != "" && len(identity) <= 512 && validateScalar(identity, maxScalarBytes) == "" &&
		!strings.ContainsAny(identity, "\r\n\x00")
}

func exactReadOnlyEventSelectorDisable(parameters map[string]any) bool {
	selectors, ok := parameters["eventSelectors"].([]any)
	if !ok || len(selectors) != 1 {
		return false
	}
	selector, ok := selectors[0].(map[string]any)
	if !ok || len(selector) != 2 || exactString(selector["readWriteType"]) != "ReadOnly" {
		return false
	}
	include, ok := selector["includeManagementEvents"].(bool)
	return ok && !include
}

func exactExternalSnapshotShare(parameters map[string]any, principal any) bool {
	principalObject, ok := principal.(map[string]any)
	if !ok {
		return false
	}
	owner := exactString(principalObject["account_id"])
	if len(owner) != 12 {
		return false
	}
	var candidates []any
	if values, ok := parameters["valuesToAdd"].([]any); ok {
		candidates = values
	}
	for _, key := range []string{"createVolumePermission", "launchPermission"} {
		permission, ok := parameters[key].(map[string]any)
		if !ok {
			continue
		}
		add, ok := permission["add"].(map[string]any)
		if !ok {
			continue
		}
		if items, ok := add["items"].([]any); ok {
			for _, item := range items {
				if itemObject, ok := item.(map[string]any); ok {
					candidates = append(candidates, itemObject["userId"])
				}
			}
		}
	}
	for _, candidate := range candidates {
		account := exactString(candidate)
		if len(account) == 12 && account != owner {
			return true
		}
	}
	return false
}

func exactWorldwideSSHIngress(parameters map[string]any) bool {
	if exactString(parameters["ipProtocol"]) != "tcp" || exactInteger(parameters["fromPort"]) != 22 ||
		exactInteger(parameters["toPort"]) != 22 {
		return false
	}
	prefix, err := netip.ParsePrefix(exactString(parameters["cidrIp"]))
	return err == nil && prefix.Addr().Is4() && prefix.Bits() == 0
}

func exactString(value any) string {
	result, _ := value.(string)
	return result
}

func exactInteger(value any) int64 {
	number, ok := value.(json.Number)
	if !ok {
		return -1
	}
	result, err := number.Int64()
	if err != nil {
		return -1
	}
	return result
}
