// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"strings"
	"testing"
)

func TestGeneratedGenAIMessageValidationUsesExactStructuredContract(t *testing.T) {
	input := TelemetryStructuredGenAIInputMessages{Items: []TelemetryStructuredGenAIChatMessage{{
		Role: "user", Parts: TelemetryStructuredGenAIMessageParts{Items: []TelemetryStructuredGenAIMessagePart{
			TelemetryStructuredArmGenAIMessagePartText{Value: TelemetryStructuredGenAITextPart{Content: "hello"}},
		}},
	}}}
	if err := ValidateTelemetryStructuredGenAIInputMessages(input); err != nil {
		t.Fatalf("valid generated input: %v", err)
	}
	input.Items[0].Parts.Items = []TelemetryStructuredGenAIMessagePart{
		TelemetryStructuredArmGenAIMessagePartText{Value: TelemetryStructuredGenAITextPart{Content: strings.Repeat("x", 4097)}},
	}
	if err := ValidateTelemetryStructuredGenAIInputMessages(input); err == nil {
		t.Fatal("oversized generated input text part was accepted")
	}

	output := TelemetryStructuredGenAIOutputMessages{Items: []TelemetryStructuredGenAIOutputMessage{{
		Role: "assistant", FinishReason: Present("length"),
		Parts: TelemetryStructuredGenAIMessageParts{Items: []TelemetryStructuredGenAIMessagePart{
			TelemetryStructuredArmGenAIMessagePartText{Value: TelemetryStructuredGenAITextPart{Content: "done"}},
		}},
	}}}
	if err := ValidateTelemetryStructuredGenAIOutputMessages(output); err != nil {
		t.Fatalf("valid generated output: %v", err)
	}
	output.Items[0].FinishReason = Absent[string]()
	if err := ValidateTelemetryStructuredGenAIOutputMessages(output); err != nil {
		t.Fatalf("valid generated output without provider finish reason: %v", err)
	}
}

func TestGeneratedGenAIToolValidationUsesExactStructuredContract(t *testing.T) {
	value := TelemetryStructuredArmGenAICanonicalJSONString{Value: "private.person@example.com"}
	argumentEntry, err := NewGenAIToolCallArgumentsEntryMember("email", value)
	if err != nil {
		t.Fatal(err)
	}
	arguments := TelemetryStructuredGenAIToolCallArguments{
		Entries: []GenAIToolCallArgumentsEntryMemberInput{argumentEntry},
	}
	if err := ValidateTelemetryStructuredGenAIToolCallArguments(arguments); err != nil {
		t.Fatalf("valid generated tool arguments: %v", err)
	}

	resultEntry, err := NewGenAIToolCallResultEntryMember("content", value)
	if err != nil {
		t.Fatal(err)
	}
	result := TelemetryStructuredGenAIToolCallResult{
		Entries: []GenAIToolCallResultEntryMemberInput{resultEntry},
	}
	if err := ValidateTelemetryStructuredGenAIToolCallResult(result); err != nil {
		t.Fatalf("valid generated tool result: %v", err)
	}

	oversized := TelemetryStructuredArmGenAICanonicalJSONString{Value: strings.Repeat("x", 4097)}
	argumentEntry, err = NewGenAIToolCallArgumentsEntryMember("raw", oversized)
	if err != nil {
		t.Fatal(err)
	}
	arguments.Entries = []GenAIToolCallArgumentsEntryMemberInput{argumentEntry}
	if err := ValidateTelemetryStructuredGenAIToolCallArguments(arguments); err == nil {
		t.Fatal("oversized generated tool argument was accepted")
	}
}
