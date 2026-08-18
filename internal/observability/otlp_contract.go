// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

// OTLPValueKind is the canonical registry value arm used by the direct OTLP
// projection. It is deliberately narrower than Go's type system: a destination
// projector may not guess a numeric arm from a rendered JSON value when the
// generated family descriptor already owns that distinction.
type OTLPValueKind uint8

const (
	OTLPValueInvalid OTLPValueKind = iota
	OTLPValueString
	OTLPValueBoolean
	OTLPValueInt64
	OTLPValueUint32
	OTLPValueUint64
	OTLPValueDouble
	OTLPValueStringArray
	OTLPValueStructured
)

// TraceOTLPAttributeKind resolves one generated span attribute to its exact
// canonical value arm. The switch binds the runtime projector to generated
// descriptor values; it does not duplicate individual attribute schemas.
func TraceOTLPAttributeKind(family EventName, key string) (OTLPValueKind, bool) {
	contract, ok := traceOTLPContract(family)
	if !ok {
		return OTLPValueInvalid, false
	}
	return otlpDescriptorKind(contract.fields, key)
}

// TraceOTLPEventAttributeKind resolves one registered event attribute under a
// generated span family. Unknown family/event/key combinations fail closed.
func TraceOTLPEventAttributeKind(family EventName, event, key string) (OTLPValueKind, bool) {
	contract, ok := traceOTLPContract(family)
	if !ok {
		return OTLPValueInvalid, false
	}
	for _, candidate := range contract.allowedEvents {
		if candidate.name == event {
			return otlpDescriptorKind(candidate.fields, key)
		}
	}
	return OTLPValueInvalid, false
}

// TraceOTLPLinkAttributeKind resolves one generated link attribute. Relation is
// generated as an ordinary string field and all other unknown keys are rejected.
func TraceOTLPLinkAttributeKind(family EventName, key string) (OTLPValueKind, bool) {
	contract, ok := traceOTLPContract(family)
	if !ok {
		return OTLPValueInvalid, false
	}
	return otlpDescriptorKind(contract.linkFields, key)
}

// TraceOTLPResourceAttributeKind resolves the fixed generated resource
// vocabulary. A validated custom resource member is represented as a string and
// is intentionally reported through the second result rather than added to an
// independently maintained key catalog.
func TraceOTLPResourceAttributeKind(family EventName, key string) (OTLPValueKind, bool) {
	contract, ok := traceOTLPContract(family)
	if !ok {
		return OTLPValueInvalid, false
	}
	return otlpDescriptorKind(contract.resourceFields, key)
}

// TelemetryResourceCompatibilityAliases returns the generated compatibility
// resource aliases keyed by wire name. Receivers use this generated view to
// validate a native round trip without maintaining a second reserved-key list.
func TelemetryResourceCompatibilityAliases() map[string]string {
	contract := generatedTelemetryResourceContract()
	aliases := make(map[string]string, len(contract.aliases))
	for _, alias := range contract.aliases {
		aliases[alias.descriptor.key] = alias.canonical
	}
	return aliases
}

// TraceOTLPScopeAttributeKind resolves the immutable generated scope
// vocabulary.
func TraceOTLPScopeAttributeKind(family EventName, key string) (OTLPValueKind, bool) {
	contract, ok := traceOTLPContract(family)
	if !ok {
		return OTLPValueInvalid, false
	}
	return otlpDescriptorKind(contract.scopeFields, key)
}

// CanonicalTraceCanaryDestination resolves the release-canary target from a
// generated canonical trace record. Unmarked records return marked=false and
// valid=true. A marked record is valid only when the marker is exactly true and
// its destination is a stable token. Canonical destination consumers use this
// before routing so a targeted canary cannot be exported to, queued by, or
// reported as a failure of any sibling destination.
func CanonicalTraceCanaryDestination(record Record) (target string, marked bool, valid bool) {
	body, present := record.Body()
	if !present {
		return "", false, true
	}
	object, err := body.Object()
	if err != nil {
		return "", false, false
	}
	attributes, ok := object["attributes"].(map[string]any)
	if !ok {
		return "", false, false
	}
	marker, marked := attributes["defenseclaw.telemetry.canary"]
	if !marked {
		return "", false, true
	}
	boolean, ok := marker.(bool)
	if !ok || !boolean {
		return "", true, false
	}
	target, ok = attributes["defenseclaw.telemetry.canary.destination"].(string)
	return target, true, ok && IsStableToken(target)
}

func otlpDescriptorKind(descriptors []familyFieldDescriptor, key string) (OTLPValueKind, bool) {
	for _, descriptor := range descriptors {
		if descriptor.key != key {
			continue
		}
		switch descriptor.typeOf {
		case familyFieldString:
			return OTLPValueString, true
		case familyFieldBoolean:
			return OTLPValueBoolean, true
		case familyFieldInt64:
			return OTLPValueInt64, true
		case familyFieldUint32:
			return OTLPValueUint32, true
		case familyFieldUint64:
			return OTLPValueUint64, true
		case familyFieldDouble:
			return OTLPValueDouble, true
		case familyFieldStringArray:
			return OTLPValueStringArray, true
		case familyFieldStructured:
			return OTLPValueStructured, true
		default:
			return OTLPValueInvalid, false
		}
	}
	return OTLPValueInvalid, false
}

// traceOTLPContract is exhaustive over the generated trace-family catalog. The
// returned contracts remain generated authority; this adapter only supplies the
// otherwise-missing runtime lookup from a validated family ID.
func traceOTLPContract(family EventName) (familyTraceContract, bool) {
	switch family {
	case EventName(TelemetryFamilyAdminOperation):
		return generatedSpanAdminOperationDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyAgentInvoke):
		return generatedSpanAgentInvokeDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyAgentTransition):
		return generatedSpanAgentTransitionDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyAIDiscovery):
		return generatedSpanAIDiscoveryDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyAIDiscoveryDetector):
		return generatedSpanAIDiscoveryDetectorDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyApprovalResolve):
		return generatedSpanApprovalResolveDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyAssetScan):
		return generatedSpanAssetScanDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyAssetScanPhase):
		return generatedSpanAssetScanPhaseDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyAssetTransition):
		return generatedSpanAssetTransitionDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyConfigReload):
		return generatedSpanConfigReloadDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyDestinationExport):
		return generatedSpanDestinationExportDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyDiagnosticCanary):
		return generatedSpanDiagnosticCanaryDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyEnforcementApply):
		return generatedSpanEnforcementApplyDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyFindingEnrich):
		return generatedSpanFindingEnrichDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyGuardrailApply):
		return generatedSpanGuardrailApplyDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyGuardrailJudge):
		return generatedSpanGuardrailJudgeDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyGuardrailPhase):
		return generatedSpanGuardrailPhaseDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyModelChat):
		return generatedSpanModelChatDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyModelEmbeddings):
		return generatedSpanModelEmbeddingsDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyNetworkRequest):
		return generatedSpanNetworkRequestDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyRetrievalSearch):
		return generatedSpanRetrievalSearchDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyTelemetryNormalize):
		return generatedSpanTelemetryNormalizeDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyTelemetryReceive):
		return generatedSpanTelemetryReceiveDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyToolExecute):
		return generatedSpanToolExecuteDescriptor{}.familyTraceContract(), true
	case EventName(TelemetryFamilyWorkflowRun):
		return generatedSpanWorkflowRunDescriptor{}.familyTraceContract(), true
	default:
		return familyTraceContract{}, false
	}
}
