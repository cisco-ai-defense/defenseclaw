// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

// Secure Client v8 still exports these aliases. Their values come only from
// registered canonical fields; v9 custom resource attributes cannot name them.
var secureClientResourceAliases = []struct {
	canonical  string
	descriptor familyFieldDescriptor
}{
	{"deployment.environment.name", familyFieldDescriptor{
		key: "deployment.environment", typeOf: familyFieldString,
		requirement: familyRequirementRecommended, fieldClass: FieldClassMetadata,
		constraints: familyFieldConstraints{maxUTF8Bytes: 4096}, source: familyValueInput,
	}},
	{"defenseclaw.deployment.mode", familyFieldDescriptor{
		key: "deployment.mode", typeOf: familyFieldString,
		requirement: familyRequirementRecommended, fieldClass: FieldClassMetadata,
		constraints: familyFieldConstraints{maxUTF8Bytes: 4096}, source: familyValueInput,
	}},
	{"defenseclaw.device.public_key_fingerprint", familyFieldDescriptor{
		key: "defenseclaw.device.id", typeOf: familyFieldString,
		requirement: familyRequirementRecommended, fieldClass: FieldClassIdentifier,
		constraints: familyFieldConstraints{maxUTF8Bytes: 256, pattern: "^[A-Za-z0-9][A-Za-z0-9:+._/-]*$"},
		source:      familyValueInput,
	}},
}

// WithSecureClientResourceAliases enables the retired aliases only for a
// trusted Secure Client plan. Callers must not derive this from custom input.
func WithSecureClientResourceAliases(resource TraceResourceInput) TraceResourceInput {
	resource.secureClientAliases = true
	return resource
}

// ValidateTelemetryResourceAttributesWithSecureClientAliases accepts only
// aliases that exactly copy the registered canonical values. All other keys
// still follow the generated v9 resource contract.
func ValidateTelemetryResourceAttributesWithSecureClientAliases(values map[string]any) error {
	canonical := make(map[string]any, len(values))
	for key, value := range values {
		canonical[key] = value
	}
	for _, alias := range secureClientResourceAliases {
		if value, present := canonical[alias.descriptor.key]; present {
			canonicalValue, valid := canonical[alias.canonical].(string)
			aliasValue, isString := value.(string)
			if !valid || !isString || aliasValue != canonicalValue {
				return familyBuildFailure(FamilyBuildConstraint)
			}
			delete(canonical, alias.descriptor.key)
		}
	}
	return ValidateTelemetryResourceAttributes(canonical)
}
