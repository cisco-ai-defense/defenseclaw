// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

const (
	cloudResourceIdentityDomain = "defenseclaw/actionfacts/cloud-resource/v1"
	cloudObjectIdentityDomain   = "defenseclaw/actionfacts/cloud-object/v1"
)

var (
	awsS3BucketPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	awsS3IPAddressPattern = regexp.MustCompile(`^[0-9.]+$`)
)

// ExactCloudResourceMutations returns validated value-free cloud mutation
// facts. Any invalid private fact invalidates the whole projection.
func ExactCloudResourceMutations(facts Facts) []CloudResourceMutationFact {
	result := make([]CloudResourceMutationFact, 0, len(facts.CloudResourceMutations))
	for _, fact := range facts.CloudResourceMutations {
		if !validCloudResourceMutation(fact) {
			return nil
		}
		result = append(result, fact)
	}
	return result
}

func validCloudResourceMutation(fact CloudResourceMutationFact) bool {
	if !fact.Exact ||
		!validPrivateDigest(fact.ResourceIdentityDigest) ||
		!validPrivateDigest(fact.ObjectIdentityDigest) {
		return false
	}
	if fact.Observed {
		switch fact.Operation {
		case CloudResourceDeleteDisk:
			return fact.Provider == "aws" && fact.Service == "ec2" && fact.Scope == "disk" && !fact.Recursive
		case CloudResourceDeleteIAMBinding:
			return fact.Provider == "azure" && fact.Service == "iam" && fact.Scope == "binding" && !fact.Recursive
		case CloudResourceDeleteObject:
			return fact.Provider == "gcp" && fact.Service == "storage" && fact.Scope == "object" && !fact.Recursive
		default:
			return false
		}
	}
	if fact.Provider != "aws" || fact.Service != "s3" {
		return false
	}
	switch fact.Operation {
	case CloudResourceDeleteObject:
		return fact.Scope == "object" && !fact.Recursive
	case CloudResourceDeletePrefix:
		return fact.Scope == "prefix" && fact.Recursive
	case CloudResourceDeleteBucket:
		return fact.Scope == "bucket" && fact.Recursive
	default:
		return false
	}
}

func projectCloudResourceMutations(input Input, facts Facts) []CloudResourceMutationFact {
	if cloudAuditResourceMutationTool(input.Tool) {
		// Audit-event tools are closed structured channels. Mixing an alternate
		// command or argv channel into the same input makes the observation
		// ambiguous and must not fall through to command classification.
		if input.Command != "" || len(input.Argv) != 0 {
			return nil
		}
		return exactCloudAuditResourceMutationInput(input.Tool, input.Args)
	}
	if !facts.Authoritative() || !facts.EnforcementEligible() || len(facts.Commands) != 1 {
		return nil
	}
	if input.Tool == "aws_cli" {
		extracted := extractExactAWSCLIArgs(input.Args)
		if extracted.status != StatusComplete || extracted.command == "" {
			return nil
		}
	}
	fact, ok := exactAWSCloudResourceMutation(facts.Commands[0].Argv)
	if !ok || !validCloudResourceMutation(fact) {
		return nil
	}
	return []CloudResourceMutationFact{fact}
}

func cloudAuditResourceMutationTool(tool string) bool {
	switch tool {
	case "aws.cloudtrail_event", "azure.activity_event", "gcp.audit_event":
		return true
	default:
		return false
	}
}

func exactCloudAuditResourceMutationInput(tool string, raw json.RawMessage) []CloudResourceMutationFact {
	object, problem := exactJSONObject(raw)
	if problem.status != "" {
		return nil
	}
	var provider, service, scope, resource, objectID string
	var operation CloudResourceMutationOperation
	switch tool {
	case "aws.cloudtrail_event":
		if !exactObjectKeys(object, cloudAuditOuterKeys) || exactString(object["provider"]) != "aws" ||
			exactString(object["event_source"]) != "ec2.amazonaws.com" || exactString(object["event_name"]) != "DeleteVolume" ||
			!successfulCloudAuditStatus(object["status"]) {
			return nil
		}
		parameters, ok := object["request_parameters"].(map[string]any)
		if !ok || len(parameters) != 1 || !exactBoundedCloudIdentity(parameters["volumeId"]) {
			return nil
		}
		provider, service, operation, scope = "aws", "ec2", CloudResourceDeleteDisk, "disk"
		resource, objectID = exactString(parameters["volumeId"]), "disk-root"
	case "azure.activity_event":
		allowed := map[string]bool{"actor": true, "correlation_id": true, "operation": true, "operation_id": true, "provider": true, "request": true, "resources": true, "service": true, "status": true, "timestamp": true}
		if !exactObjectKeys(object, allowed) || exactString(object["provider"]) != "azure" ||
			exactString(object["operation"]) != "Microsoft.Authorization/roleAssignments/delete" ||
			exactString(object["service"]) != "Microsoft.Authorization" || !successfulProviderAuditStatus(object["status"], "azure_status_succeeded") {
			return nil
		}
		resource = exactSingleAuditResource(object["resources"])
		parentScope, bindingID, ok := exactAzureRoleAssignmentIdentity(resource)
		if !ok || !exactAzureRoleAssignmentRequest(object["request"], resource, parentScope) {
			return nil
		}
		provider, service, operation, scope = "azure", "iam", CloudResourceDeleteIAMBinding, "binding"
		resource, objectID = parentScope, bindingID
	case "gcp.audit_event":
		allowed := map[string]bool{"actor": true, "operation": true, "provider": true, "request": true, "resources": true, "service": true, "status": true, "timestamp": true}
		if !exactObjectKeys(object, allowed) || exactString(object["provider"]) != "gcp" ||
			exactString(object["operation"]) != "storage.objects.delete" || exactString(object["service"]) != "storage.googleapis.com" ||
			!successfulProviderAuditStatus(object["status"], "gcp_empty_status_success") {
			return nil
		}
		resource = exactSingleAuditResource(object["resources"])
		bucketResource, fullObject, ok := exactGCPStorageObjectIdentity(resource)
		if !ok || !exactGCPObjectDeleteRequest(object["request"], resource) {
			return nil
		}
		provider, service, operation, scope = "gcp", "storage", CloudResourceDeleteObject, "object"
		resource, objectID = bucketResource, fullObject
	default:
		return nil
	}
	fact := CloudResourceMutationFact{
		Provider: provider, Service: service, Operation: operation, Scope: scope,
		ResourceIdentityDigest: framedPrivateDigest(cloudResourceIdentityDomain, provider, service, resource),
		ObjectIdentityDigest:   framedPrivateDigest(cloudObjectIdentityDomain, provider, service, resource, objectID),
		Observed:               true, Exact: true,
	}
	if !validCloudResourceMutation(fact) {
		return nil
	}
	return []CloudResourceMutationFact{fact}
}

func successfulProviderAuditStatus(value any, evidence string) bool {
	status, ok := value.(map[string]any)
	return ok && len(status) == 2 && exactString(status["outcome"]) == "succeeded" &&
		exactString(status["evidence"]) == evidence
}

func exactAzureRoleAssignmentIdentity(resource string) (string, string, bool) {
	const marker = "/providers/microsoft.authorization/roleassignments/"
	lower := strings.ToLower(resource)
	index := strings.Index(lower, marker)
	if index <= 0 || !strings.HasPrefix(lower, "/subscriptions/") {
		return "", "", false
	}
	parent, binding := resource[:index], resource[index+len(marker):]
	if !exactBoundedCloudIdentity(parent) || !exactBoundedCloudIdentity(binding) ||
		strings.Contains(binding, "/") || strings.Contains(lower[index+len(marker):], marker) {
		return "", "", false
	}
	return parent, resource, true
}

func exactAzureRoleAssignmentRequest(value any, resource, parentScope string) bool {
	request, ok := value.(map[string]any)
	if !ok || len(request) != 1 {
		return false
	}
	authorization, ok := request["authorization"].(map[string]any)
	if !ok || len(authorization) != 2 ||
		exactString(authorization["action"]) != "Microsoft.Authorization/roleAssignments/delete" {
		return false
	}
	scope := strings.TrimSuffix(exactString(authorization["scope"]), "/")
	if !exactBoundedCloudIdentity(scope) {
		return false
	}
	return strings.EqualFold(scope, resource) || strings.EqualFold(scope, parentScope) ||
		strings.HasPrefix(strings.ToLower(resource), strings.ToLower(scope)+"/")
}

func exactGCPStorageObjectIdentity(resource string) (string, string, bool) {
	const prefix = "projects/_/buckets/"
	const marker = "/objects/"
	if !strings.HasPrefix(resource, prefix) {
		return "", "", false
	}
	remainder := strings.TrimPrefix(resource, prefix)
	index := strings.Index(remainder, marker)
	if index <= 0 || index+len(marker) >= len(remainder) ||
		strings.Contains(remainder[index+len(marker):], "\x00") {
		return "", "", false
	}
	bucket := remainder[:index]
	object := remainder[index+len(marker):]
	if strings.Contains(bucket, "/") || !exactBoundedCloudIdentity(bucket) ||
		!exactBoundedCloudIdentity(object) {
		return "", "", false
	}
	return prefix + bucket, resource, true
}

func exactGCPObjectDeleteRequest(value any, resource string) bool {
	request, ok := value.(map[string]any)
	if !ok || len(request) != 2 {
		return false
	}
	parameters, ok := request["parameters"].(map[string]any)
	if !ok || !exactGCPObjectDeleteParameters(parameters, resource) {
		return false
	}
	authorizations, ok := request["authorization"].([]any)
	if !ok || len(authorizations) == 0 || len(authorizations) > 64 {
		return false
	}
	matched := false
	for _, candidate := range authorizations {
		authorization, ok := candidate.(map[string]any)
		if !ok || !exactGCPAuthorizationShape(authorization) {
			return false
		}
		granted, ok := authorization["granted"].(bool)
		if ok && granted && exactString(authorization["permission"]) == "storage.objects.delete" &&
			exactString(authorization["resource"]) == resource {
			matched = true
		}
	}
	return matched
}

func exactGCPObjectDeleteParameters(parameters map[string]any, resource string) bool {
	if len(parameters) > 2 {
		return false
	}
	for key, value := range parameters {
		if key != "bucket" && key != "object" || !exactBoundedCloudIdentity(value) {
			return false
		}
	}
	bucketResource, _, ok := exactGCPStorageObjectIdentity(resource)
	if !ok {
		return false
	}
	bucket := strings.TrimPrefix(bucketResource, "projects/_/buckets/")
	object := strings.SplitN(resource, "/objects/", 2)[1]
	if value := exactString(parameters["bucket"]); value != "" && value != bucket {
		return false
	}
	if value := exactString(parameters["object"]); value != "" && value != object {
		return false
	}
	return true
}

func exactGCPAuthorizationShape(authorization map[string]any) bool {
	allowed := map[string]bool{
		"granted": true, "permission": true, "resource": true, "resourceAttributes": true,
	}
	if !exactObjectKeys(authorization, allowed) || len(authorization) < 3 || len(authorization) > 4 {
		return false
	}
	if _, ok := authorization["granted"].(bool); !ok ||
		!exactBoundedCloudIdentity(authorization["permission"]) ||
		!exactBoundedCloudIdentity(authorization["resource"]) {
		return false
	}
	attributes, present := authorization["resourceAttributes"]
	if !present {
		return true
	}
	object, ok := attributes.(map[string]any)
	if !ok || len(object) > 2 {
		return false
	}
	for key, value := range object {
		if key != "name" && key != "type" || !exactBoundedCloudIdentity(value) {
			return false
		}
	}
	return true
}

func exactSingleAuditResource(value any) string {
	resources, ok := value.([]any)
	if !ok || len(resources) != 1 {
		return ""
	}
	resource, ok := resources[0].(map[string]any)
	if !ok || len(resource) != 1 || !exactBoundedCloudIdentity(resource["id"]) {
		return ""
	}
	return exactString(resource["id"])
}

func exactAWSCloudResourceMutation(argv []string) (CloudResourceMutationFact, bool) {
	if len(argv) < 4 || argv[0] != "aws" {
		return CloudResourceMutationFact{}, false
	}
	var operation CloudResourceMutationOperation
	var scope, bucket, object string
	var recursive bool
	switch {
	case argv[1] == "s3" && argv[2] == "rm":
		uri, flags, ok := exactAWSS3Operands(argv[3:])
		if !ok {
			return CloudResourceMutationFact{}, false
		}
		bucket, object, ok = exactAWSS3URI(uri)
		if !ok {
			return CloudResourceMutationFact{}, false
		}
		recursive = flags["--recursive"]
		if object == "" && !recursive {
			return CloudResourceMutationFact{}, false
		}
		operation, scope = CloudResourceDeleteObject, "object"
		if recursive {
			operation, scope = CloudResourceDeletePrefix, "prefix"
		}
	case argv[1] == "s3" && argv[2] == "rb":
		uri, flags, ok := exactAWSS3Operands(argv[3:])
		if !ok || !flags["--force"] {
			return CloudResourceMutationFact{}, false
		}
		bucket, object, ok = exactAWSS3URI(uri)
		if !ok || object != "" {
			return CloudResourceMutationFact{}, false
		}
		operation, scope, recursive = CloudResourceDeleteBucket, "bucket", true
	case argv[1] == "s3api" && argv[2] == "delete-object":
		values, flags, ok := exactAWSNamedOptions(argv[3:])
		if !ok || flags["--dryrun"] || values["--bucket"] == "" || values["--key"] == "" {
			return CloudResourceMutationFact{}, false
		}
		bucket, object = strings.ToLower(values["--bucket"]), values["--key"]
		if !exactAWSS3Bucket(bucket) || !exactAWSS3Object(object) {
			return CloudResourceMutationFact{}, false
		}
		operation, scope = CloudResourceDeleteObject, "object"
	case argv[1] == "s3api" && argv[2] == "delete-bucket":
		values, flags, ok := exactAWSNamedOptions(argv[3:])
		if !ok || flags["--dryrun"] || values["--bucket"] == "" {
			return CloudResourceMutationFact{}, false
		}
		bucket = strings.ToLower(values["--bucket"])
		if !exactAWSS3Bucket(bucket) {
			return CloudResourceMutationFact{}, false
		}
		operation, scope, recursive = CloudResourceDeleteBucket, "bucket", true
	default:
		return CloudResourceMutationFact{}, false
	}
	if object == "" {
		object = "bucket-root"
	}
	return CloudResourceMutationFact{
		Provider:               "aws",
		Service:                "s3",
		Operation:              operation,
		Scope:                  scope,
		ResourceIdentityDigest: framedPrivateDigest(cloudResourceIdentityDomain, "aws", "s3", bucket),
		ObjectIdentityDigest:   framedPrivateDigest(cloudObjectIdentityDomain, "aws", "s3", bucket, object),
		Recursive:              recursive,
		Exact:                  true,
	}, true
}

func exactAWSS3Operands(argv []string) (string, map[string]bool, bool) {
	flags := make(map[string]bool)
	uri := ""
	for index := 0; index < len(argv); index++ {
		argument := argv[index]
		switch argument {
		case "--recursive", "--force", "--no-verify-ssl", "--only-show-errors", "--quiet", "--no-cli-pager":
			if flags[argument] {
				return "", nil, false
			}
			flags[argument] = true
		case "--dryrun":
			return "", nil, false
		case "--endpoint-url", "--region", "--profile", "--cli-connect-timeout", "--cli-read-timeout":
			if flags[argument] || index+1 >= len(argv) || !exactAWSOptionValue(argv[index+1]) {
				return "", nil, false
			}
			flags[argument] = true
			index++
		default:
			if strings.HasPrefix(argument, "-") || uri != "" {
				return "", nil, false
			}
			uri = argument
		}
	}
	return uri, flags, uri != ""
}

func exactAWSNamedOptions(argv []string) (map[string]string, map[string]bool, bool) {
	values := make(map[string]string)
	flags := make(map[string]bool)
	valueOptions := map[string]bool{
		"--bucket": true, "--key": true, "--version-id": true,
		"--endpoint-url": true, "--region": true, "--profile": true,
		"--cli-connect-timeout": true, "--cli-read-timeout": true,
	}
	flagOptions := map[string]bool{"--no-verify-ssl": true, "--no-cli-pager": true, "--dryrun": true}
	for index := 0; index < len(argv); index++ {
		argument := argv[index]
		if flagOptions[argument] {
			if flags[argument] {
				return nil, nil, false
			}
			flags[argument] = true
			continue
		}
		if !valueOptions[argument] || values[argument] != "" || index+1 >= len(argv) ||
			!exactAWSOptionValue(argv[index+1]) {
			return nil, nil, false
		}
		index++
		values[argument] = argv[index]
	}
	return values, flags, true
}

func exactAWSOptionValue(value string) bool {
	return value != "" && len(value) <= maxCommandBytes &&
		!strings.ContainsAny(value, "$`\\\r\n\x00") &&
		!strings.Contains(value, "{{") && !strings.Contains(value, "}}")
}

func exactAWSS3URI(raw string) (string, string, bool) {
	if !exactAWSOptionValue(raw) || !strings.HasPrefix(raw, "s3://") {
		return "", "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "s3" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Host != strings.ToLower(parsed.Host) ||
		!exactAWSS3Bucket(parsed.Host) {
		return "", "", false
	}
	object, err := url.PathUnescape(strings.TrimPrefix(parsed.EscapedPath(), "/"))
	if err != nil || !exactAWSS3ObjectOrEmpty(object) {
		return "", "", false
	}
	return parsed.Host, object, true
}

func exactAWSS3Bucket(value string) bool {
	return awsS3BucketPattern.MatchString(value) && !strings.Contains(value, "..") &&
		!awsS3IPAddressPattern.MatchString(value)
}

func exactAWSS3Object(value string) bool { return value != "" && exactAWSS3ObjectOrEmpty(value) }

func exactAWSS3ObjectOrEmpty(value string) bool {
	return len(value) <= 1024 && !strings.ContainsAny(value, "\r\n\x00$`\\") &&
		!strings.ContainsAny(value, "*?[") && !strings.Contains(value, "..")
}
