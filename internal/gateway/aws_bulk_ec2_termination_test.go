// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const awsBulkEC2TerminationRuleID = "impact.aws_bulk_ec2_termination"

func TestAWSBulkEC2TerminationProfilePosture(t *testing.T) {
	owner, present := semanticOwners[awsBulkEC2TerminationRuleID]
	if !present || owner.prerequisite == nil || owner.suppressFallback == nil ||
		owner.alertOnly || owner.detectionOnly {
		t.Fatalf("semantic owner=%+v, present=%t", owner, present)
	}

	input := gatewayAWSBulkEC2TerminationInput(t, 12)
	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			connector := "aws-bulk-ec2-" + profile
			installToolCallCorpusProfileConnector(t, connector, profile)
			result := EvaluateDeterministicAction(context.Background(), input, "", connector, profile)
			if !slices.Contains(result.RuleIDs, awsBulkEC2TerminationRuleID) || len(result.Findings) != 1 {
				t.Fatalf("profile=%s result=%+v, want one bulk-termination finding", profile, result)
			}
			wantAction := "alert"
			if profile == "strict" {
				wantAction = "block"
			}
			if result.Action != wantAction || result.Severity != "HIGH" ||
				!result.Findings[0].ContributesToEnforcement {
				t.Fatalf("profile=%s result=%+v, want action=%s HIGH enforceable finding", profile, result, wantAction)
			}
		})
	}
}

func TestAWSBulkEC2TerminationOwnerRejectsNearMisses(t *testing.T) {
	owner := semanticOwners[awsBulkEC2TerminationRuleID]
	for _, test := range []struct {
		name  string
		input actionfacts.Input
	}{
		{"below threshold", gatewayAWSBulkEC2TerminationInput(t, 9)},
		{"untrusted identity", func() actionfacts.Input {
			in := gatewayAWSBulkEC2TerminationInput(t, 12)
			in.ToolResourceIdentity = ""
			return in
		}()},
		{"dry run", actionfacts.Input{Tool: "aws.ec2.terminate_instances", Args: json.RawMessage(`{"InstanceIds":["i-00000000","i-00000001","i-00000002","i-00000003","i-00000004","i-00000005","i-00000006","i-00000007","i-00000008","i-00000009"],"DryRun":true}`), ToolResourceIdentity: "aws://synthetic-account/us-east-1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			facts := actionfacts.Analyze(test.input)
			if owner.eligible(facts) {
				t.Fatalf("near miss eligible: %+v", facts)
			}
		})
	}
}

func gatewayAWSBulkEC2TerminationInput(t *testing.T, count int) actionfacts.Input {
	t.Helper()
	ids := make([]string, count)
	for index := range ids {
		ids[index] = fmt.Sprintf("i-%08x", index)
	}
	args, err := json.Marshal(map[string]any{"InstanceIds": ids})
	if err != nil {
		t.Fatal(err)
	}
	return actionfacts.Input{
		Tool:                 "aws.ec2.terminate_instances",
		Args:                 args,
		ToolResourceIdentity: "aws://synthetic-account/us-east-1",
	}
}
