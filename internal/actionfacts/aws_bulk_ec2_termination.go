// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"regexp"
)

const (
	minAWSBulkEC2TerminationInstances = 10
	maxAWSBulkEC2TerminationInstances = 100
)

var canonicalEC2InstanceIDPattern = regexp.MustCompile(`^i-(?:[0-9a-f]{8}|[0-9a-f]{17})$`)

// AWSBulkEC2TerminationFact is deliberately value-free. Its existence proves
// that one trusted aws.ec2.terminate_instances invocation names a bounded set
// of distinct canonical literal instance IDs and is not a dry run.
type AWSBulkEC2TerminationFact struct{}

func projectAWSBulkEC2Terminations(input Input) []AWSBulkEC2TerminationFact {
	if input.Tool != "aws.ec2.terminate_instances" || input.Command != "" ||
		len(input.Argv) != 0 || !validTrustedToolResourceIdentity(input.ToolResourceIdentity) {
		return nil
	}
	if !exactAWSBulkEC2TerminationArgs(input.Args) {
		return nil
	}
	return []AWSBulkEC2TerminationFact{{}}
}

func exactAWSBulkEC2TerminationArgs(raw json.RawMessage) bool {
	object, problem := exactJSONObject(raw)
	if problem.status != "" || len(object) < 1 || len(object) > 2 {
		return false
	}
	for key := range object {
		if key != "InstanceIds" && key != "DryRun" {
			return false
		}
	}
	if dryRun, present := object["DryRun"]; present {
		value, ok := dryRun.(bool)
		if !ok || value {
			return false
		}
	}
	instanceIDs, ok := object["InstanceIds"].([]any)
	if !ok || len(instanceIDs) < minAWSBulkEC2TerminationInstances ||
		len(instanceIDs) > maxAWSBulkEC2TerminationInstances {
		return false
	}
	seen := make(map[string]struct{}, len(instanceIDs))
	for _, rawID := range instanceIDs {
		instanceID, ok := rawID.(string)
		if !ok || !canonicalEC2InstanceIDPattern.MatchString(instanceID) {
			return false
		}
		if _, duplicate := seen[instanceID]; duplicate {
			return false
		}
		seen[instanceID] = struct{}{}
	}
	return true
}

// ExactAWSBulkEC2Termination accepts only the private value-free fact minted
// by Analyze for an authoritative invocation of the closed tool schema.
func ExactAWSBulkEC2Termination(facts Facts) bool {
	return facts.Authoritative() && facts.EnforcementEligible() &&
		len(facts.AWSBulkEC2Terminations) == 1
}
