// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const syntheticEC2ResourceIdentity = "aws://synthetic-account/us-east-1"

func TestExactAWSBulkEC2Termination(t *testing.T) {
	for _, dryRunField := range []string{"", `,"DryRun":false`} {
		input := awsBulkEC2TerminationInput(t, 12, dryRunField)
		facts := Analyze(input)
		if !facts.Authoritative() || !ExactAWSBulkEC2Termination(facts) {
			t.Fatalf("facts=%+v, want exact bulk termination", facts)
		}
		if len(facts.EnforcementProjection().AWSBulkEC2Terminations) != 1 {
			t.Fatal("value-free bulk termination fact missing from enforcement projection")
		}
		encoded, err := json.Marshal(facts)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "i-00000000") ||
			strings.Contains(string(encoded), syntheticEC2ResourceIdentity) {
			t.Fatalf("private EC2 input escaped value-free fact: %s", encoded)
		}
	}
}

func TestAWSBulkEC2TerminationRejectsNearMisses(t *testing.T) {
	valid := awsInstanceIDs(10)
	duplicate := append(append([]string(nil), valid[:9]...), valid[0])
	shortID := append([]string(nil), valid...)
	shortID[0] = "i-ABCDEF12"
	longID := append([]string(nil), valid...)
	longID[0] = "i-0123456789abcdef"
	dynamicID := append([]string(nil), valid...)
	dynamicID[0] = "i-${INSTANCE_ID}"

	tests := []struct {
		name  string
		input Input
	}{
		{"nine instances", awsBulkEC2TerminationInput(t, 9, "")},
		{"over bounded maximum", awsBulkEC2TerminationInput(t, 101, "")},
		{"duplicate instance", awsBulkEC2TerminationInputWithIDs(t, duplicate, "")},
		{"noncanonical uppercase", awsBulkEC2TerminationInputWithIDs(t, shortID, "")},
		{"noncanonical mixed length", awsBulkEC2TerminationInputWithIDs(t, longID, "")},
		{"dynamic instance", awsBulkEC2TerminationInputWithIDs(t, dynamicID, "")},
		{"dry run", awsBulkEC2TerminationInput(t, 10, `,"DryRun":true`)},
		{"unknown key", awsBulkEC2TerminationInput(t, 10, `,"Region":"us-east-1"`)},
		{"missing trusted identity", func() Input { in := awsBulkEC2TerminationInput(t, 10, ""); in.ToolResourceIdentity = ""; return in }()},
		{"dynamic trusted identity", func() Input {
			in := awsBulkEC2TerminationInput(t, 10, "")
			in.ToolResourceIdentity = "aws://${ACCOUNT}"
			return in
		}()},
		{"wrong tool", func() Input {
			in := awsBulkEC2TerminationInput(t, 10, "")
			in.Tool = "aws.ec2.stop_instances"
			return in
		}()},
		{"conflicting command", func() Input { in := awsBulkEC2TerminationInput(t, 10, ""); in.Command = "echo inert"; return in }()},
		{"conflicting argv", func() Input {
			in := awsBulkEC2TerminationInput(t, 10, "")
			in.Argv = []string{"echo", "inert"}
			return in
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			if ExactAWSBulkEC2Termination(facts) || len(facts.AWSBulkEC2Terminations) != 0 {
				t.Fatalf("near miss minted fact: %+v", facts)
			}
		})
	}
}

func awsBulkEC2TerminationInput(t *testing.T, count int, suffix string) Input {
	t.Helper()
	return awsBulkEC2TerminationInputWithIDs(t, awsInstanceIDs(count), suffix)
}

func awsBulkEC2TerminationInputWithIDs(t *testing.T, ids []string, suffix string) Input {
	t.Helper()
	encoded, err := json.Marshal(ids)
	if err != nil {
		t.Fatal(err)
	}
	return Input{
		Tool:                 "aws.ec2.terminate_instances",
		Args:                 json.RawMessage(`{"InstanceIds":` + string(encoded) + suffix + `}`),
		ToolResourceIdentity: syntheticEC2ResourceIdentity,
	}
}

func awsInstanceIDs(count int) []string {
	ids := make([]string, count)
	for index := range ids {
		ids[index] = fmt.Sprintf("i-%08x", index)
	}
	return ids
}
