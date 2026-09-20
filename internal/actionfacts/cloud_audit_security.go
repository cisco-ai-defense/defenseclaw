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

var worldwideSSHParameterKeys = map[string]bool{
	"cidrIp": true, "fromPort": true, "groupId": true,
	"ipPermissions": true, "ipProtocol": true, "toPort": true,
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

// exactCloudShareOperationEnvelope recognizes the complete, value-bounded
// event grammar for the three snapshot-sharing APIs even when the operation
// failed or removed permission. Those controls are authoritative benign
// same-operation inputs, but they deliberately emit no security-operation
// fact. Successful external additions still require exactCloudAuditOperation.
func exactCloudShareOperationEnvelope(raw json.RawMessage) bool {
	object, problem := exactJSONObject(raw)
	if problem.status != "" || !exactObjectKeys(object, cloudAuditOuterKeys) ||
		exactString(object["provider"]) != "aws" {
		return false
	}
	succeeded, statusOK := exactClosedCloudAuditStatus(object["status"])
	if !statusOK {
		return false
	}
	operation := exactString(object["event_source"]) + ":" + exactString(object["event_name"])
	switch operation {
	case "ec2.amazonaws.com:ModifySnapshotAttribute",
		"ec2.amazonaws.com:ModifyImageAttribute",
		"rds.amazonaws.com:ModifyDBSnapshotAttribute":
	default:
		return false
	}
	parameters, hasParameters := object["request_parameters"].(map[string]any)
	if !hasParameters {
		return !succeeded && object["request_parameters"] == nil
	}
	switch operation {
	case "ec2.amazonaws.com:ModifySnapshotAttribute":
		return len(parameters) == 3 &&
			exactString(parameters["attributeType"]) == "CREATE_VOLUME_PERMISSION" &&
			exactEC2ResourceID(parameters["snapshotId"], "snap") &&
			exactClosedAccountPermissionMutation(parameters["createVolumePermission"])
	case "ec2.amazonaws.com:ModifyImageAttribute":
		return len(parameters) == 3 && exactString(parameters["attributeType"]) == "launchPermission" &&
			exactEC2ResourceID(parameters["imageId"], "ami") &&
			exactClosedAccountPermissionMutation(parameters["launchPermission"])
	case "rds.amazonaws.com:ModifyDBSnapshotAttribute":
		return exactClosedRDSSnapshotPermissionMutation(parameters)
	default:
		return false
	}
}

func exactClosedCloudAuditStatus(value any) (bool, bool) {
	if successfulCloudAuditStatus(value) {
		return true, true
	}
	status, ok := value.(map[string]any)
	if !ok || len(status) != 3 || exactString(status["outcome"]) != "failed" ||
		!exactBoundedCloudIdentity(status["error_code"]) {
		return false, false
	}
	_, presentOK := status["error_message_present"].(bool)
	return false, presentOK
}

func exactClosedAccountPermissionMutation(value any) bool {
	permission, ok := value.(map[string]any)
	if !ok || len(permission) != 1 {
		return false
	}
	var body any
	if add, present := permission["add"]; present {
		body = add
	} else if remove, present := permission["remove"]; present {
		body = remove
	} else {
		return false
	}
	mutation, ok := body.(map[string]any)
	if !ok || len(mutation) != 1 {
		return false
	}
	items, ok := mutation["items"].([]any)
	if !ok || len(items) == 0 || len(items) > 16 {
		return false
	}
	for _, value := range items {
		item, ok := value.(map[string]any)
		if !ok || len(item) != 1 {
			return false
		}
		if exactString(item["group"]) == "all" {
			continue
		}
		if !validAWSAccountID(exactString(item["userId"])) {
			return false
		}
	}
	return true
}

func exactClosedRDSSnapshotPermissionMutation(parameters map[string]any) bool {
	if len(parameters) != 3 || exactString(parameters["attributeName"]) != "restore" ||
		!exactRDSDBSnapshotIdentifier(parameters["dBSnapshotIdentifier"]) {
		return false
	}
	var values any
	if add, present := parameters["valuesToAdd"]; present {
		values = add
	} else if remove, present := parameters["valuesToRemove"]; present {
		values = remove
	} else {
		return false
	}
	accounts, ok := values.([]any)
	if !ok || len(accounts) == 0 || len(accounts) > 16 {
		return false
	}
	for _, candidate := range accounts {
		account := exactString(candidate)
		if account != "all" && !validAWSAccountID(account) {
			return false
		}
	}
	return true
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
	case "ec2.amazonaws.com:ModifySnapshotAttribute":
		if exactExternalEC2SnapshotShare(parameters, principal) {
			return CloudAuditExternalSnapshotShare, true
		}
	case "ec2.amazonaws.com:ModifyImageAttribute":
		if exactExternalEC2ImageShare(parameters, principal) {
			return CloudAuditExternalSnapshotShare, true
		}
	case "rds.amazonaws.com:ModifyDBSnapshotAttribute":
		if exactExternalRDSDBSnapshotShare(parameters, principal) {
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
	if len(parameters) != 2 || !exactBoundedCloudIdentity(parameters["trailName"]) {
		return false
	}
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

func exactExternalEC2SnapshotShare(parameters map[string]any, principal any) bool {
	if len(parameters) != 3 || exactString(parameters["attributeType"]) != "CREATE_VOLUME_PERMISSION" ||
		!exactEC2ResourceID(parameters["snapshotId"], "snap") {
		return false
	}
	return exactExternalAccountPermission(parameters["createVolumePermission"], principal)
}

func exactExternalEC2ImageShare(parameters map[string]any, principal any) bool {
	if len(parameters) != 3 || exactString(parameters["attributeType"]) != "launchPermission" ||
		!exactEC2ResourceID(parameters["imageId"], "ami") {
		return false
	}
	return exactExternalAccountPermission(parameters["launchPermission"], principal)
}

func exactExternalRDSDBSnapshotShare(parameters map[string]any, principal any) bool {
	if len(parameters) != 3 || exactString(parameters["attributeName"]) != "restore" ||
		!exactRDSDBSnapshotIdentifier(parameters["dBSnapshotIdentifier"]) {
		return false
	}
	owner, ok := exactCloudAccountID(principal)
	if !ok {
		return false
	}
	accounts, ok := parameters["valuesToAdd"].([]any)
	if !ok || len(accounts) == 0 {
		return false
	}
	external := false
	for _, candidate := range accounts {
		account := exactString(candidate)
		if !validAWSAccountID(account) {
			return false
		}
		external = external || account != owner
	}
	return external
}

func exactExternalAccountPermission(value, principal any) bool {
	owner, ok := exactCloudAccountID(principal)
	if !ok {
		return false
	}
	permission, ok := value.(map[string]any)
	if !ok || len(permission) != 1 {
		return false
	}
	add, ok := permission["add"].(map[string]any)
	if !ok || len(add) != 1 {
		return false
	}
	items, ok := add["items"].([]any)
	if !ok || len(items) == 0 {
		return false
	}
	external := false
	for _, item := range items {
		itemObject, ok := item.(map[string]any)
		if !ok || len(itemObject) != 1 {
			return false
		}
		account := exactString(itemObject["userId"])
		if !validAWSAccountID(account) {
			return false
		}
		external = external || account != owner
	}
	return external
}

func exactCloudAccountID(principal any) (string, bool) {
	principalObject, ok := principal.(map[string]any)
	if !ok {
		return "", false
	}
	owner := exactString(principalObject["account_id"])
	return owner, validAWSAccountID(owner)
}

func validAWSAccountID(account string) bool {
	if len(account) != 12 {
		return false
	}
	for index := range account {
		if account[index] < '0' || account[index] > '9' {
			return false
		}
	}
	return true
}

func exactEC2ResourceID(value any, prefix string) bool {
	identity := exactString(value)
	if !strings.HasPrefix(identity, prefix+"-") {
		return false
	}
	suffix := identity[len(prefix)+1:]
	if len(suffix) != 8 && len(suffix) != 17 {
		return false
	}
	for index := range suffix {
		character := suffix[index]
		if character < '0' || character > '9' {
			lower := character | 0x20
			if lower < 'a' || lower > 'f' {
				return false
			}
		}
	}
	return true
}

func exactRDSDBSnapshotIdentifier(value any) bool {
	identity := exactString(value)
	if len(identity) == 0 || len(identity) > 255 || !asciiLetter(identity[0]) ||
		identity[len(identity)-1] == '-' || strings.Contains(identity, "--") {
		return false
	}
	for index := range identity {
		character := identity[index]
		if !asciiLetter(character) && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func asciiLetter(character byte) bool {
	lower := character | 0x20
	return lower >= 'a' && lower <= 'z'
}

func exactWorldwideSSHIngress(parameters map[string]any) bool {
	if (len(parameters) != 5 && len(parameters) != 6) ||
		!exactObjectKeys(parameters, worldwideSSHParameterKeys) {
		return false
	}
	if !exactEC2ResourceID(parameters["groupId"], "sg") || exactString(parameters["ipProtocol"]) != "tcp" ||
		exactInteger(parameters["fromPort"]) != 22 ||
		exactInteger(parameters["toPort"]) != 22 {
		return false
	}
	if nested, present := parameters["ipPermissions"]; present {
		permission, ok := nested.(map[string]any)
		if !ok || len(permission) != 0 {
			return false
		}
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
