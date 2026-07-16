// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import "fmt"

// ValidateTelemetryStructuredGenAIInputMessages validates the exact generated
// span.model.chat field contract without allocating an occurrence or exposing
// descriptor/construction authority. Producers can use it to fit bounded
// source content before starting a physical span.
func ValidateTelemetryStructuredGenAIInputMessages(input TelemetryStructuredGenAIInputMessages) error {
	encoded, err := encodeTelemetryStructuredGenAIInputMessages("gen_ai.input.messages", input, true)
	if err != nil {
		return err
	}
	return validateGeneratedModelChatField(encoded)
}

// ValidateTelemetryStructuredGenAIOutputMessages is the output counterpart of
// ValidateTelemetryStructuredGenAIInputMessages.
func ValidateTelemetryStructuredGenAIOutputMessages(input TelemetryStructuredGenAIOutputMessages) error {
	encoded, err := encodeTelemetryStructuredGenAIOutputMessages("gen_ai.output.messages", input, true)
	if err != nil {
		return err
	}
	return validateGeneratedModelChatField(encoded)
}

// ValidateTelemetryStructuredGenAIToolCallArguments validates the exact
// span.tool.execute argument-object contract without constructing a record.
func ValidateTelemetryStructuredGenAIToolCallArguments(input TelemetryStructuredGenAIToolCallArguments) error {
	encoded, err := encodeTelemetryStructuredGenAIToolCallArguments("gen_ai.tool.call.arguments", input, true)
	if err != nil {
		return err
	}
	return validateGeneratedToolExecuteField(encoded)
}

// ValidateTelemetryStructuredGenAIToolCallResult validates the exact
// span.tool.execute result-object contract without constructing a record.
func ValidateTelemetryStructuredGenAIToolCallResult(input TelemetryStructuredGenAIToolCallResult) error {
	encoded, err := encodeTelemetryStructuredGenAIToolCallResult("gen_ai.tool.call.result", input, true)
	if err != nil {
		return err
	}
	return validateGeneratedToolExecuteField(encoded)
}

func validateGeneratedModelChatField(encoded familyFieldValue) error {
	contract := generatedSpanModelChatDescriptor{}.familyDescriptorContract()
	return validateGeneratedContractField(contract, encoded)
}

func validateGeneratedToolExecuteField(encoded familyFieldValue) error {
	contract := generatedSpanToolExecuteDescriptor{}.familyDescriptorContract()
	return validateGeneratedContractField(contract, encoded)
}

func validateGeneratedContractField(contract familyDescriptorContract, encoded familyFieldValue) error {
	for _, field := range contract.fields {
		if field.key == encoded.key {
			return validateFamilyFieldValue(field, encoded.value)
		}
	}
	return fmt.Errorf("generated span.model.chat field %q is unavailable", encoded.key)
}
