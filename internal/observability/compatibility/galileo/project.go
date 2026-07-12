// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package galileo

import (
	"bytes"
	"encoding/json"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/compatibility/profilemanifest"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"go.opentelemetry.io/otel/trace"
)

const (
	canaryMarkerKey      = "defenseclaw.telemetry.canary"
	canaryOperationKey   = "defenseclaw.telemetry.canary.operation"
	canaryDestinationKey = "defenseclaw.telemetry.canary.destination"
	canaryOperationValue = "runtime-pipeline-test"
)

// Project evaluates galileo-rich-v2 after route redaction. A rejection has no
// side effect on the supplied projection or any other destination projection.
func Project(input redaction.Projection, configured Limits) Result {
	limits, ok := configured.resolved()
	if !ok {
		return rejected(ReasonInvalidLimits)
	}
	encoded, err := input.Bytes()
	if err != nil {
		return rejected(ReasonInvalidProjection)
	}
	var envelope projectedEnvelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&envelope); err != nil || !validEnvelope(envelope) {
		return rejected(ReasonInvalidProjection)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return rejected(ReasonInvalidProjection)
	}
	attributes, ok := object(envelope.Body["attributes"])
	if !ok {
		return rejected(ReasonSchemaMissingRequired, "body.attributes")
	}
	if !profilemanifest.Eligible(
		ProfileID,
		observability.SignalTraces,
		observability.EventName(envelope.Family),
	) {
		return rejected(ReasonUnsupportedShape)
	}
	contract, reason, missing := selectContract(envelope, attributes)
	if reason != ReasonEligible {
		return rejected(reason, missing...)
	}

	projectedAttributes := projectAttributes(
		attributes, contract.allowedAttributes, limits.MaxAttributeValueBytes,
	)
	missing = prepareRequiredProjection(contract, envelope, projectedAttributes, limits)
	if len(missing) > 0 {
		return rejected(ReasonSchemaMissingRequired, missing...)
	}
	projectedAttributes = trimAttributes(
		projectedAttributes, requiredAttributeKeys(contract), limits.MaxAttributesPerSpan,
	)
	body, ok := projectBody(envelope.Body, projectedAttributes, contract, limits)
	if !ok {
		return rejected(ReasonInvalidProjection)
	}
	output := outputEnvelope{
		Profile: ProfileID, Shape: contract.shape,
		SchemaVersion: envelope.SchemaVersion, BucketCatalogVersion: envelope.BucketCatalogVersion,
		Timestamp: envelope.Timestamp, ObservedAt: envelope.ObservedAt,
		RecordID: envelope.RecordID, Bucket: envelope.Bucket, Signal: envelope.Signal,
		Family: envelope.Family, SpanName: envelope.SpanName, Source: envelope.Source,
		Connector: envelope.Connector, Action: envelope.Action, Phase: envelope.Phase, Outcome: envelope.Outcome,
		Correlation: cloneObject(envelope.Correlation), Provenance: cloneObject(envelope.Provenance),
		Projection: cloneObject(envelope.Projection), Body: body,
	}
	projected, err := json.Marshal(output)
	if err != nil {
		return rejected(ReasonInvalidProjection)
	}
	if len(projected) > limits.MaxProjectedSpanBytes {
		return rejected(ReasonProjectionTooLarge)
	}
	return accepted(contract.shape, projected)
}

func validEnvelope(envelope projectedEnvelope) bool {
	return envelope.SchemaVersion > 0 && envelope.BucketCatalogVersion > 0 &&
		envelope.RecordID != "" && envelope.Bucket != "" && envelope.Signal == "traces" &&
		envelope.Family != "" && envelope.SpanName != "" && envelope.Source != "" &&
		envelope.Timestamp != nil && envelope.Correlation != nil && envelope.Provenance != nil &&
		projectionMetadataValid(envelope.Projection) && envelope.Body != nil
}

func projectionMetadataValid(metadata map[string]any) bool {
	profile, profileOK := metadata["redaction_profile"].(string)
	state, stateOK := metadata["state"].(string)
	return profileOK && strings.TrimSpace(profile) != "" && stateOK && strings.TrimSpace(state) != ""
}

func selectContract(envelope projectedEnvelope, attributes map[string]any) (shapeContract, Reason, []string) {
	family := envelope.Family
	canaryPresent, canaryValid := generatedCanaryMetadata(attributes)
	if canaryPresent && (!canaryValid ||
		family != observability.TelemetryFamilyAgentInvoke &&
			family != observability.TelemetryFamilyModelChat) {
		return shapeContract{}, ReasonUnsupportedShape, nil
	}
	projection, ok := profilemanifest.FamilyProjection(
		ProfileID,
		observability.SignalTraces,
		observability.EventName(family),
	)
	if !ok || projection.Mode != "galileo_shape_v2" {
		return shapeContract{}, ReasonUnsupportedShape, nil
	}
	shape := Shape(projection.Shape)
	switch shape {
	case ShapeAgent, ShapeLLM, ShapeTool, ShapeRetriever, ShapeWorkflow:
	default:
		return shapeContract{}, ReasonUnsupportedShape, nil
	}
	operation := ""
	if projection.OperationAttribute != nil {
		var present bool
		operation, present = stringAttribute(attributes, *projection.OperationAttribute)
		if !present {
			return shapeContract{}, ReasonSchemaMissingRequired, []string{*projection.OperationAttribute}
		}
		if !containsString(projection.AllowedOperations, operation) {
			return shapeContract{}, ReasonUnsupportedShape, nil
		}
	}
	if shape == ShapeWorkflow {
		if _, present := canonicalWorkflowName(attributes); !present {
			return shapeContract{}, ReasonSchemaMissingRequired, []string{"defenseclaw.workflow.name"}
		}
		kind, present := stringAttribute(attributes, "openinference.span.kind")
		if present && kind != projection.OpenInferenceSpanKind {
			return shapeContract{}, ReasonUnsupportedShape, nil
		}
	}
	allowedKinds := make(map[string]struct{}, len(projection.AllowedSpanKinds))
	for _, kind := range projection.AllowedSpanKinds {
		allowedKinds[kind] = struct{}{}
	}
	if projection.OpenInferenceSpanKind == "" || len(allowedKinds) == 0 {
		return shapeContract{}, ReasonUnsupportedShape, nil
	}
	traceContract, ok := profilemanifest.FamilyTraceContract(
		ProfileID, observability.SignalTraces, observability.EventName(family),
	)
	if !ok || len(traceContract.AttributeKeys) == 0 {
		return shapeContract{}, ReasonUnsupportedShape, nil
	}
	registered, ok := observability.RegisteredTraceProjectionContract(observability.EventIdentity{
		Bucket: observability.Bucket(envelope.Bucket), Signal: observability.SignalTraces,
		Name: observability.EventName(family),
	})
	if !ok || !sameStrings(traceContract.AttributeKeys, registered.AttributeKeys) ||
		!sameStrings(traceContract.EventNames, sortedMapKeys(registered.EventAttributeKeys)) ||
		!sameStrings(traceContract.LinkRelations, registered.LinkRelations) {
		return shapeContract{}, ReasonUnsupportedShape, nil
	}
	// The generated compatibility manifest and catalog share one verified
	// materialized-view digest; the comparisons above bind every vocabulary
	// fact represented in both artifacts. Event-field, link-field, and scope-
	// field keys are intentionally not duplicated into the profile manifest:
	// they come directly from the compile-linked generated builder descriptor
	// that constructed and schema-derived the canonical record. Using that one
	// descriptor avoids a third destination-authored authority while still
	// failing closed when profile membership, attributes, events, or relations
	// drift from the digest-bound catalog.
	return contract(
		shape, family, operation, projection.OpenInferenceSpanKind,
		allowedKinds, traceContract, registered, projection.RequiredAttributes,
	), ReasonEligible, nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// generatedCanaryMetadata recognizes only the release probe carried by the
// generated agent/model families. The ordinary span.diagnostic.canary family
// remains an independent one-span diagnostic signal and is never rewritten
// into a Galileo agent or model shape.
func generatedCanaryMetadata(attributes map[string]any) (present, valid bool) {
	markerRaw, markerPresent := attributes[canaryMarkerKey]
	operationRaw, operationPresent := attributes[canaryOperationKey]
	destinationRaw, destinationPresent := attributes[canaryDestinationKey]
	present = markerPresent || operationPresent || destinationPresent
	if !present {
		return false, true
	}
	marker, markerOK := markerRaw.(bool)
	operation, operationOK := operationRaw.(string)
	destination, destinationOK := destinationRaw.(string)
	return true, markerOK && marker && operationOK && operation == canaryOperationValue &&
		destinationOK && observability.IsStableToken(destination)
}

func contract(
	shape Shape,
	family, operation, oiKind string,
	kinds map[string]struct{},
	traceContract profilemanifest.TraceContract,
	registered observability.TraceProjectionContract,
	requiredAttributes []string,
) shapeContract {
	eventFields := make(map[string]map[string]struct{}, len(registered.EventAttributeKeys))
	for name, keys := range registered.EventAttributeKeys {
		eventFields[name] = stringSet(keys)
	}
	return shapeContract{
		shape: shape, family: family, operation: operation, oiKind: oiKind,
		allowedKinds:       kinds,
		allowedAttributes:  stringSet(traceContract.AttributeKeys),
		allowedEvents:      stringSet(traceContract.EventNames),
		allowedEventFields: eventFields,
		allowedLinks:       stringSet(traceContract.LinkRelations),
		allowedLinkFields:  stringSet(registered.LinkAttributeKeys),
		allowedScopeFields: stringSet(registered.ScopeAttributeKeys),
		requiredAttributes: append([]string(nil), requiredAttributes...),
	}
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sortedMapKeys(values map[string][]string) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func prepareRequiredProjection(
	contract shapeContract,
	envelope projectedEnvelope,
	attributes map[string]any,
	limits Limits,
) []string {
	missing := make([]string, 0, 8)
	kind, present := normalizedSpanKind(envelope.Body["kind"])
	if !present {
		missing = append(missing, "body.kind")
	} else if _, allowed := contract.allowedKinds[kind]; !allowed {
		missing = append(missing, "body.kind")
	}
	if !validSpanName(contract, envelope.SpanName, attributes) {
		missing = append(missing, "span_name")
	}

	attributes["openinference.span.kind"] = contract.oiKind
	if contract.operation != "" && contract.shape != ShapeRetriever {
		attributes["gen_ai.operation.name"] = contract.operation
	}
	if contract.family == "span.guardrail.judge" {
		attributes["defenseclaw.guardrail.judge"] = true
	}
	for _, key := range contract.requiredAttributes {
		requireNonEmptyString(attributes, key, &missing)
	}

	switch contract.shape {
	case ShapeAgent:
		ensureMessages(attributes, "input", "user", contentFallback(attributes, "input", limits), limits)
		ensureMessages(attributes, "output", "assistant", contentFallback(attributes, "output", limits), limits)
	case ShapeLLM:
		ensureMessages(attributes, "input", "user", contentFallback(attributes, "input", limits), limits)
		ensureMessages(attributes, "output", "assistant", contentFallback(attributes, "output", limits), limits)
	case ShapeTool:
		arguments, argumentsOK := boundedCanonicalString(
			attributes["gen_ai.tool.call.arguments"], limits.MaxAttributeValueBytes,
		)
		result, resultOK := boundedCanonicalString(
			attributes["gen_ai.tool.call.result"], limits.MaxAttributeValueBytes,
		)
		delete(attributes, "gen_ai.tool.call.arguments")
		delete(attributes, "gen_ai.tool.call.result")
		if !argumentsOK {
			arguments, argumentsOK = contentScalar(attributes, "input", limits.MaxAttributeValueBytes)
		}
		if !resultOK {
			result, resultOK = contentScalar(attributes, "output", limits.MaxAttributeValueBytes)
		}
		if argumentsOK {
			attributes["gen_ai.tool.call.arguments"] = arguments
		} else {
			missing = append(missing, "gen_ai.tool.call.arguments")
		}
		if resultOK {
			attributes["gen_ai.tool.call.result"] = result
		} else {
			missing = append(missing, "gen_ai.tool.call.result")
		}
		inputReported := ensureMessages(attributes, "input", "user", valueWhen(argumentsOK, arguments), limits)
		outputReported := ensureMessages(attributes, "output", "tool", valueWhen(resultOK, result), limits)
		// Tool arguments and results are the most useful Galileo aliases, but
		// they must honor the same effective reported state as the canonical
		// message view. Otherwise an explicit suppression override could blank
		// gen_ai.*.messages while leaving raw content in input/output.value.
		setOpenInferenceValue(attributes, "input", arguments, argumentsOK && inputReported, "application/json")
		setOpenInferenceValue(attributes, "output", result, resultOK && outputReported, "application/json")
		setContentState(attributes, "arguments", argumentsOK, arguments, limits.MaxAttributeValueBytes)
		setContentState(attributes, "result", resultOK, result, limits.MaxAttributeValueBytes)
	case ShapeRetriever:
		ensureMessages(attributes, "input", "user", contentFallback(attributes, "input", limits), limits)
		ensureMessages(attributes, "output", "assistant", contentFallback(attributes, "output", limits), limits)
	case ShapeWorkflow:
		ensureMessages(attributes, "input", "user", contentFallback(attributes, "input", limits), limits)
		ensureMessages(attributes, "output", "assistant", contentFallback(attributes, "output", limits), limits)
	}

	for _, key := range requiredAttributeKeys(contract) {
		if _, ok := attributes[key]; !ok {
			missing = append(missing, key)
		}
	}
	missing = uniqueSorted(missing)
	return missing
}

func validSpanName(contract shapeContract, name string, attributes map[string]any) bool {
	if !utf8.ValidString(name) || len(name) == 0 || len(name) > 512 || strings.ContainsAny(name, "\r\n\x00") {
		return false
	}
	switch contract.shape {
	case ShapeAgent:
		return name == "invoke_agent" ||
			(strings.HasPrefix(name, "invoke_agent ") && strings.TrimSpace(strings.TrimPrefix(name, "invoke_agent ")) != "")
	case ShapeLLM:
		return name == contract.operation ||
			(strings.HasPrefix(name, contract.operation+" ") && strings.TrimSpace(strings.TrimPrefix(name, contract.operation+" ")) != "")
	case ShapeTool:
		return strings.HasPrefix(name, "execute_tool ") && strings.TrimSpace(strings.TrimPrefix(name, "execute_tool ")) != ""
	case ShapeRetriever:
		return strings.HasPrefix(name, "retrieve ") && strings.TrimSpace(strings.TrimPrefix(name, "retrieve ")) != ""
	case ShapeWorkflow:
		workflowName, ok := canonicalWorkflowName(attributes)
		return ok && name == "workflow "+workflowName
	default:
		return false
	}
}

func normalizedSpanKind(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		kind := strings.ToUpper(strings.TrimSpace(typed))
		switch kind {
		case "INTERNAL", "CLIENT":
			return kind, true
		default:
			return "", false
		}
	case json.Number:
		value, err := strconv.Atoi(typed.String())
		if err != nil {
			return "", false
		}
		return normalizedSpanKind(float64(value))
	case float64:
		if typed != float64(int(typed)) {
			return "", false
		}
		switch int(typed) {
		case 1:
			return "INTERNAL", true
		case 3:
			return "CLIENT", true
		default:
			return "", false
		}
	default:
		return "", false
	}
}

func projectBody(
	input, attributes map[string]any,
	contract shapeContract,
	limits Limits,
) (map[string]any, bool) {
	output := make(map[string]any)
	for _, key := range []string{
		"kind", "parent_span_id", "start_time_unix_nano", "end_time_unix_nano", "duration_nano",
		"dropped_attributes_count", "dropped_events_count", "dropped_links_count",
	} {
		if value, ok := input[key]; ok {
			output[key] = cloneJSON(value)
		}
	}
	if kind, ok := normalizedSpanKind(input["kind"]); ok {
		output["kind"] = kind
	}
	if raw, present := input["flags"]; present {
		flags, valid := raw.(json.Number)
		if !valid || !validUnsignedJSONNumber(flags, 32) {
			return nil, false
		}
		output["flags"] = json.Number(strings.Clone(flags.String()))
	}
	if raw, present := input["trace_state"]; present {
		traceState, valid := raw.(string)
		if !valid || len(traceState) > 512 || !utf8.ValidString(traceState) {
			return nil, false
		}
		if traceState != "" {
			parsed, err := trace.ParseTraceState(traceState)
			if err != nil || parsed.String() != traceState {
				return nil, false
			}
		}
		output["trace_state"] = strings.Clone(traceState)
	}
	output["attributes"] = cloneObject(attributes)
	events, eventsOK := projectEvents(
		input["events"], contract.allowedEvents, contract.allowedEventFields, limits,
	)
	if !eventsOK {
		return nil, false
	}
	if len(events) > 0 {
		output["events"] = events
	}
	links, linksOK := projectLinks(
		input["links"], contract.allowedLinks, contract.allowedLinkFields, limits,
	)
	if !linksOK {
		return nil, false
	}
	if len(links) > 0 {
		output["links"] = links
	}
	if status := projectStatus(input["status"], limits.MaxAttributeValueBytes); len(status) > 0 {
		output["status"] = status
	}
	if resourceValue, present := input["resource"]; present {
		resource, valid := projectResource(resourceValue, limits.MaxAttributeValueBytes)
		if !valid {
			return nil, false
		}
		output["resource"] = resource
	}
	scope, scopeOK := projectScope(
		input["scope"], contract.allowedScopeFields, limits.MaxAttributeValueBytes,
	)
	if !scopeOK {
		return nil, false
	}
	if len(scope) > 0 {
		output["scope"] = scope
	}
	return output, true
}

func projectResource(value any, maximum int) (map[string]any, bool) {
	resource, ok := object(value)
	if !ok {
		return nil, false
	}
	for key := range resource {
		switch key {
		case "attributes", "schema_url", "dropped_attributes_count":
		default:
			return nil, false
		}
	}
	attributes, ok := object(resource["attributes"])
	if !ok {
		return nil, false
	}
	if err := observability.ValidateTelemetryResourceAttributes(attributes); err != nil {
		return nil, false
	}
	projected := make(map[string]any, len(attributes))
	for _, key := range sortedKeys(attributes) {
		text, valid := boundedString(attributes[key], maximum)
		if key == "" || !utf8.ValidString(key) || !valid {
			return nil, false
		}
		projected[strings.Clone(key)] = strings.Clone(text)
	}
	if len(projected) == 0 {
		return nil, false
	}
	output := map[string]any{"attributes": projected}
	if schemaValue, present := resource["schema_url"]; present {
		schemaURL, valid := boundedString(schemaValue, maximum)
		if !valid || strings.TrimSpace(schemaURL) == "" {
			return nil, false
		}
		output["schema_url"] = schemaURL
	}
	if droppedValue, present := resource["dropped_attributes_count"]; present {
		dropped, valid := droppedValue.(json.Number)
		if !valid || !validUnsignedJSONNumber(dropped, 32) {
			return nil, false
		}
		output["dropped_attributes_count"] = json.Number(strings.Clone(dropped.String()))
	}
	return output, true
}

func validUnsignedJSONNumber(value json.Number, bits int) bool {
	if _, err := strconv.ParseUint(value.String(), 10, bits); err == nil {
		return true
	}
	rational, ok := new(big.Rat).SetString(value.String())
	return ok && rational.IsInt() && rational.Sign() >= 0 && rational.Num().BitLen() <= bits
}

func projectScope(value any, allowed map[string]struct{}, maximum int) (map[string]any, bool) {
	if value == nil {
		return nil, true
	}
	scope, ok := object(value)
	if !ok {
		return nil, false
	}
	output := make(map[string]any, 4)
	for _, key := range []string{"name", "version", "schema_url"} {
		if text, ok := boundedString(scope[key], maximum); ok && text != "" {
			output[key] = text
		}
	}
	if attributes, ok := object(scope["attributes"]); ok {
		projected := make(map[string]any)
		for _, key := range sortedKeys(attributes) {
			if _, registered := allowed[key]; !registered &&
				key != "defenseclaw.galileo.compatibility_profile" {
				continue
			}
			if value, exists := attributes[key]; exists && valueWithinLimit(value, maximum) {
				projected[key] = cloneJSON(value)
			}
		}
		if len(projected) > 0 {
			output["attributes"] = projected
		}
	}
	if droppedValue, present := scope["dropped_attributes_count"]; present {
		dropped, valid := droppedValue.(json.Number)
		if !valid || !validUnsignedJSONNumber(dropped, 32) {
			return nil, false
		}
		output["dropped_attributes_count"] = json.Number(strings.Clone(dropped.String()))
	}
	return output, len(output) > 0
}

func projectAttributes(
	input map[string]any,
	allowed map[string]struct{},
	maxValueBytes int,
) map[string]any {
	keys := sortedKeys(input)
	output := make(map[string]any, len(keys))
	for _, key := range keys {
		if _, registered := allowed[key]; !registered && !compatibilityInputAttribute(key) {
			continue
		}
		if !isContentAttribute(key) && !valueWithinLimit(input[key], maxValueBytes) {
			continue
		}
		output[key] = cloneJSON(input[key])
	}
	return output
}

func isContentAttribute(key string) bool {
	switch key {
	case "gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.tool.call.arguments",
		"gen_ai.tool.call.result", "input.value", "output.value":
		return true
	default:
		return false
	}
}

func valueWithinLimit(value any, maximum int) bool {
	encoded, err := json.Marshal(value)
	return err == nil && len(encoded) <= maximum
}

func compatibilityInputAttribute(key string) bool {
	switch key {
	case "openinference.span.kind", "input.value", "input.mime_type",
		"output.value", "output.mime_type":
		return true
	default:
		return false
	}
}

func requiredAttributeKeys(contract shapeContract) []string {
	required := append([]string{
		"openinference.span.kind", "gen_ai.input.messages", "gen_ai.output.messages",
		"input.value", "input.mime_type", "output.value", "output.mime_type",
		"defenseclaw.telemetry.input.reported", "defenseclaw.telemetry.input.state",
		"defenseclaw.telemetry.output.reported", "defenseclaw.telemetry.output.state",
	}, contract.requiredAttributes...)
	switch contract.shape {
	case ShapeAgent:
		return append(required, "gen_ai.operation.name")
	case ShapeLLM:
		return append(required, "gen_ai.operation.name")
	case ShapeTool:
		return append(required,
			"gen_ai.operation.name", "gen_ai.tool.call.arguments", "gen_ai.tool.call.result",
			"defenseclaw.telemetry.arguments.reported", "defenseclaw.telemetry.arguments.state",
			"defenseclaw.telemetry.result.reported", "defenseclaw.telemetry.result.state",
		)
	case ShapeRetriever:
		return append(required, "db.operation.name")
	case ShapeWorkflow:
		return required
	default:
		return nil
	}
}

func trimAttributes(attributes map[string]any, required []string, maximum int) map[string]any {
	if len(attributes) <= maximum {
		return attributes
	}
	requiredSet := make(map[string]struct{}, len(required))
	for _, key := range required {
		requiredSet[key] = struct{}{}
	}
	keys := sortedKeys(attributes)
	output := make(map[string]any, maximum)
	for _, key := range required {
		if value, ok := attributes[key]; ok && len(output) < maximum {
			output[key] = cloneJSON(value)
		}
	}
	for _, key := range keys {
		if len(output) >= maximum {
			break
		}
		if _, required := requiredSet[key]; required {
			continue
		}
		output[key] = cloneJSON(attributes[key])
	}
	return output
}

func ensureMessages(attributes map[string]any, direction, role string, fallback any, limits Limits) bool {
	key := "gen_ai." + direction + ".messages"
	value, supplied := attributes[key]
	reportedKey := "defenseclaw.telemetry." + direction + ".reported"
	reportedOverride, hasReportedOverride := boolAttribute(attributes, reportedKey)
	if !supplied && fallback != nil {
		value = []any{map[string]any{"role": role, "content": fallback}}
		supplied = true
	}
	encoded, state, reported := normalizeMessages(value, supplied, limits)
	if hasReportedOverride && !reportedOverride {
		encoded, state, reported = "[]", "not_reported", false
	}
	attributes[key] = encoded
	attributes[reportedKey] = reported
	attributes["defenseclaw.telemetry."+direction+".state"] = state
	if reported {
		attributes["defenseclaw.telemetry."+direction+".original_bytes"] = len(encoded)
	}
	attributes["defenseclaw.telemetry."+direction+".content_type"] = "application/json"
	// Galileo renders the OpenInference input/output fields in its Messages
	// pane. Keep the complete structured GenAI attributes for interoperability,
	// but flatten their already-redacted text parts into the UI-facing alias.
	// A JSON fallback preserves non-text message shapes without allowing the
	// alias to diverge from or bypass destination redaction.
	aliasValue, mimeType := openInferenceMessageValue(encoded, reported)
	setOpenInferenceValue(attributes, direction, aliasValue, reported, mimeType)
	return reported
}

func setOpenInferenceValue(
	attributes map[string]any,
	direction, value string,
	reported bool,
	mimeType string,
) {
	if reported {
		attributes[direction+".value"] = value
	} else {
		attributes[direction+".value"] = ""
	}
	attributes[direction+".mime_type"] = mimeType
}

func openInferenceMessageValue(encoded string, reported bool) (string, string) {
	if !reported {
		return "", "text/plain"
	}
	var messages []any
	if json.Unmarshal([]byte(encoded), &messages) != nil {
		return encoded, "application/json"
	}
	lines := make([]string, 0, len(messages))
	for _, candidate := range messages {
		message, ok := candidate.(map[string]any)
		if !ok {
			return encoded, "application/json"
		}
		contents := make([]string, 0, 2)
		if content, ok := message["content"].(string); ok && content != "" {
			contents = append(contents, content)
		}
		if parts, ok := message["parts"].([]any); ok {
			for _, candidatePart := range parts {
				part, partOK := candidatePart.(map[string]any)
				if !partOK {
					return encoded, "application/json"
				}
				// Only canonical text parts can be faithfully represented as a
				// text/plain alias. Preserve blob, reasoning, tool-call, URI, and
				// future part shapes as canonical JSON instead of relabeling their
				// content (including base64 or reasoning) as ordinary message text.
				partType, typeOK := part["type"].(string)
				if !typeOK || partType != "text" {
					return encoded, "application/json"
				}
				if content, contentOK := part["content"].(string); contentOK && content != "" {
					contents = append(contents, content)
				}
			}
		}
		if len(contents) == 0 {
			continue
		}
		text := strings.Join(contents, "\n")
		if len(messages) > 1 {
			if role, ok := message["role"].(string); ok && role != "" {
				text = role + ": " + text
			}
		}
		lines = append(lines, text)
	}
	if len(lines) == 0 {
		return encoded, "application/json"
	}
	return strings.Join(lines, "\n"), "text/plain"
}

func normalizeMessages(value any, supplied bool, limits Limits) (string, string, bool) {
	if !supplied {
		return "[]", "not_reported", false
	}
	var messages []any
	switch typed := value.(type) {
	case string:
		decoder := json.NewDecoder(strings.NewReader(typed))
		decoder.UseNumber()
		if err := decoder.Decode(&messages); err != nil {
			return "[]", "failed_closed", true
		}
	case []any:
		messages = cloneArray(typed)
	default:
		return "[]", "failed_closed", true
	}
	state := "preserved"
	if len(messages) > limits.MaxMessageItems {
		messages = messages[:limits.MaxMessageItems]
		state = "truncated"
	}
	encoded, err := json.Marshal(messages)
	if err != nil || len(encoded) > limits.MaxAttributeValueBytes {
		return "[]", "failed_closed", true
	}
	if state == "preserved" {
		state = redactionState(string(encoded))
	}
	return string(encoded), state, true
}

func redactionState(value string) string {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, "<redacted:") || strings.Contains(trimmed, "[REDACTED]") {
		if strings.HasPrefix(trimmed, "<redacted:") || trimmed == "[REDACTED]" {
			return "whole_redacted"
		}
		return "partially_redacted"
	}
	return "preserved"
}

func contentScalar(attributes map[string]any, direction string, maximum int) (string, bool) {
	if value, ok := boundedString(attributes[direction+".value"], maximum); ok {
		return value, true
	}
	value, ok := boundedString(attributes["gen_ai."+direction+".messages"], maximum)
	if !ok {
		return "", false
	}
	var messages []map[string]any
	if json.Unmarshal([]byte(value), &messages) != nil || len(messages) == 0 {
		return "", false
	}
	content, ok := messages[0]["content"].(string)
	if !ok || len(content) > maximum {
		return "", false
	}
	return content, true
}

func boundedCanonicalString(value any, maximum int) (string, bool) {
	if text, ok := boundedString(value, maximum); ok {
		return text, true
	}
	switch value.(type) {
	case map[string]any, []any:
		encoded, err := json.Marshal(value)
		if err != nil || len(encoded) > maximum {
			return "", false
		}
		return string(encoded), true
	default:
		return "", false
	}
}

func contentFallback(attributes map[string]any, direction string, limits Limits) any {
	value, ok := boundedString(attributes[direction+".value"], limits.MaxAttributeValueBytes)
	if !ok {
		return nil
	}
	return value
}

func setContentState(attributes map[string]any, slot string, reported bool, value string, maximum int) {
	attributes["defenseclaw.telemetry."+slot+".reported"] = reported
	if !reported {
		attributes["defenseclaw.telemetry."+slot+".state"] = "not_reported"
		return
	}
	state := redactionState(value)
	if len(value) > maximum {
		state = "failed_closed"
	}
	attributes["defenseclaw.telemetry."+slot+".state"] = state
	attributes["defenseclaw.telemetry."+slot+".original_bytes"] = len(value)
}

func valueWhen(ok bool, value string) any {
	if !ok {
		return nil
	}
	return value
}

func projectEvents(
	value any,
	allowed map[string]struct{},
	allowedFields map[string]map[string]struct{},
	limits Limits,
) ([]any, bool) {
	if value == nil {
		return nil, true
	}
	events, ok := value.([]any)
	if !ok {
		return nil, false
	}
	output := make([]any, 0, min(len(events), limits.MaxEventsPerSpan))
	for _, candidate := range events {
		if len(output) >= limits.MaxEventsPerSpan {
			break
		}
		event, ok := object(candidate)
		if !ok {
			return nil, false
		}
		name, ok := event["name"].(string)
		if !ok {
			return nil, false
		}
		if _, registered := allowed[name]; !registered {
			continue
		}
		projected := map[string]any{"name": name}
		if timestamp, ok := event["time_unix_nano"]; ok {
			projected["time_unix_nano"] = cloneJSON(timestamp)
		}
		if attributes, ok := object(event["attributes"]); ok {
			projected["attributes"] = projectEventAttributes(
				attributes, allowedFields[name], limits.MaxAttributesPerEvent,
				limits.MaxAttributeValueBytes,
			)
		}
		if dropped, present := event["dropped_attributes_count"]; present {
			number, valid := dropped.(json.Number)
			if !valid || !validUnsignedJSONNumber(number, 32) {
				return nil, false
			}
			projected["dropped_attributes_count"] = json.Number(strings.Clone(number.String()))
		}
		output = append(output, projected)
	}
	return output, true
}

func projectEventAttributes(
	input map[string]any,
	allowed map[string]struct{},
	maximum, maxValueBytes int,
) map[string]any {
	keys := sortedKeys(input)
	output := make(map[string]any, min(len(keys), maximum))
	for _, key := range keys {
		if len(output) >= maximum {
			break
		}
		if _, registered := allowed[key]; !registered || key == "" ||
			!utf8.ValidString(key) || !valueWithinLimit(input[key], maxValueBytes) {
			continue
		}
		output[key] = cloneJSON(input[key])
	}
	return output
}

func projectLinks(
	value any,
	allowedRelations map[string]struct{},
	allowedFields map[string]struct{},
	limits Limits,
) ([]any, bool) {
	if value == nil {
		return nil, true
	}
	links, ok := value.([]any)
	if !ok {
		return nil, false
	}
	output := make([]any, 0, min(len(links), limits.MaxLinksPerSpan))
	for _, candidate := range links {
		if len(output) >= limits.MaxLinksPerSpan {
			break
		}
		link, ok := object(candidate)
		if !ok {
			return nil, false
		}
		attributes, attributesOK := object(link["attributes"])
		if !attributesOK {
			return nil, false
		}
		relation, relationOK := attributes["defenseclaw.link.relation"].(string)
		if !relationOK {
			return nil, false
		}
		if _, registered := allowedRelations[relation]; !registered {
			return nil, false
		}
		projected := make(map[string]any)
		for _, key := range []string{"trace_id", "span_id", "trace_state"} {
			if value, ok := link[key]; ok {
				projected[key] = cloneJSON(value)
			}
		}
		projected["attributes"] = projectLinkAttributes(
			attributes, allowedFields, limits.MaxAttributesPerEvent,
			limits.MaxAttributeValueBytes,
		)
		if dropped, present := link["dropped_attributes_count"]; present {
			number, valid := dropped.(json.Number)
			if !valid || !validUnsignedJSONNumber(number, 32) {
				return nil, false
			}
			projected["dropped_attributes_count"] = json.Number(strings.Clone(number.String()))
		}
		if len(projected) > 0 {
			output = append(output, projected)
		}
	}
	return output, true
}

func projectLinkAttributes(
	input map[string]any,
	allowed map[string]struct{},
	maximum, maxValueBytes int,
) map[string]any {
	keys := sortedKeys(input)
	output := make(map[string]any, min(len(keys), maximum))
	for _, key := range keys {
		if len(output) >= maximum {
			break
		}
		if _, registered := allowed[key]; !registered || key == "" ||
			!utf8.ValidString(key) || !valueWithinLimit(input[key], maxValueBytes) {
			continue
		}
		output[key] = cloneJSON(input[key])
	}
	return output
}

func projectStatus(value any, maximum int) map[string]any {
	status, ok := object(value)
	if !ok {
		return nil
	}
	output := make(map[string]any, 2)
	if code, ok := status["code"]; ok {
		output["code"] = cloneJSON(code)
	}
	if message, ok := boundedString(status["message"], maximum); ok {
		output["message"] = message
	}
	if description, ok := boundedString(status["description"], maximum); ok {
		output["description"] = description
	}
	return output
}

func requireNonEmptyString(attributes map[string]any, key string, missing *[]string) {
	if value, ok := stringAttribute(attributes, key); !ok || value == "" {
		*missing = append(*missing, key)
	}
}

func stringAttribute(attributes map[string]any, key string) (string, bool) {
	value, ok := attributes[key].(string)
	if !ok {
		return "", false
	}
	value = strings.TrimSpace(value)
	return value, value != ""
}

func boolAttribute(attributes map[string]any, key string) (bool, bool) {
	value, ok := attributes[key].(bool)
	return value, ok
}

func canonicalWorkflowName(attributes map[string]any) (string, bool) {
	value, ok := attributes["defenseclaw.workflow.name"].(string)
	if !ok || len(value) == 0 || len(value) > 128 {
		return "", false
	}
	for index := range len(value) {
		character := value[index]
		if index == 0 {
			if character < 'a' || character > 'z' {
				if character < '0' || character > '9' {
					return "", false
				}
			}
			continue
		}
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '.' && character != '-' {
			return "", false
		}
	}
	return value, true
}

func boundedString(value any, maximum int) (string, bool) {
	text, ok := value.(string)
	return text, ok && utf8.ValidString(text) && len(text) <= maximum
}

func object(value any) (map[string]any, bool) {
	typed, ok := value.(map[string]any)
	return typed, ok
}

func cloneObject(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[strings.Clone(key)] = cloneJSON(value)
	}
	return output
}

func cloneArray(input []any) []any {
	output := make([]any, len(input))
	for index, value := range input {
		output[index] = cloneJSON(value)
	}
	return output
}

func cloneJSON(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneObject(typed)
	case []any:
		return cloneArray(typed)
	case string:
		return strings.Clone(typed)
	case json.Number:
		return json.Number(strings.Clone(typed.String()))
	default:
		return typed
	}
}

func sortedKeys(input map[string]any) []string {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func uniqueSorted(input []string) []string {
	set := make(map[string]struct{}, len(input))
	for _, value := range input {
		set[value] = struct{}{}
	}
	output := make([]string, 0, len(set))
	for value := range set {
		output = append(output, value)
	}
	sort.Strings(output)
	return output
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}
