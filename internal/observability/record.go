// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	CurrentRecordSchemaVersion = 1
	MaxRecordIDBytes           = 512
	MaxCorrelationIDBytes      = 512
	MaxBinaryVersionBytes      = 256
	MaxSpanNameBytes           = 512
	MaxProvenanceHexBytes      = 128
	MaxImportIdentifierBytes   = 512
	MaxImportForwardHops       = 4
	MaxCanonicalRecordBytes    = 4 * 1024 * 1024
)

var lowerHexPattern = regexp.MustCompile(`^[0-9a-f]+$`)
var provenanceProducerPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
var canonicalUUIDPattern = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
var canonicalCorrelationAttributePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

const maxCanonicalCorrelationAttributeIDBytes = 256

// Correlation is the closed v8 set of optional join keys. An empty value means
// unknown; builders never invent a correlation identifier.
type Correlation struct {
	SemanticEventID     string `json:"semantic_event_id,omitempty"`
	LogicalEventID      string `json:"logical_event_id,omitempty"`
	ConnectorInstanceID string `json:"connector_instance_id,omitempty"`
	RunID               string `json:"run_id,omitempty"`
	RequestID           string `json:"request_id,omitempty"`
	SessionID           string `json:"session_id,omitempty"`
	TurnID              string `json:"turn_id,omitempty"`
	TraceID             string `json:"trace_id,omitempty"`
	SpanID              string `json:"span_id,omitempty"`
	AgentID             string `json:"agent_id,omitempty"`
	AgentInstanceID     string `json:"agent_instance_id,omitempty"`
	PolicyID            string `json:"policy_id,omitempty"`
	PolicyVersion       string `json:"policy_version,omitempty"`
	EvaluationID        string `json:"evaluation_id,omitempty"`
	ScanID              string `json:"scan_id,omitempty"`
	FindingOccurrenceID string `json:"finding_occurrence_id,omitempty"`
	EnforcementActionID string `json:"enforcement_action_id,omitempty"`
	ModelRequestID      string `json:"model_request_id,omitempty"`
	ModelResponseID     string `json:"model_response_id,omitempty"`
	ToolInvocationID    string `json:"tool_invocation_id,omitempty"`
	DestinationID       string `json:"destination_id,omitempty"`
	ConnectorID         string `json:"connector_id,omitempty"`
	SidecarInstanceID   string `json:"sidecar_instance_id,omitempty"`
}

func (correlation Correlation) validate() error {
	canonical := [...]struct{ field, value string }{
		{"semantic event ID", correlation.SemanticEventID},
		{"logical event ID", correlation.LogicalEventID},
		{"connector instance ID", correlation.ConnectorInstanceID},
	}
	for _, identifier := range canonical {
		if identifier.value == "" {
			continue
		}
		if len(identifier.value) > maxCanonicalCorrelationAttributeIDBytes ||
			!canonicalCorrelationAttributePattern.MatchString(identifier.value) {
			return fmt.Errorf("correlation %s is not a canonical identifier", identifier.field)
		}
	}
	values := [...]string{
		correlation.SemanticEventID,
		correlation.LogicalEventID,
		correlation.ConnectorInstanceID,
		correlation.RunID,
		correlation.RequestID,
		correlation.SessionID,
		correlation.TurnID,
		correlation.TraceID,
		correlation.SpanID,
		correlation.AgentID,
		correlation.AgentInstanceID,
		correlation.PolicyID,
		correlation.PolicyVersion,
		correlation.EvaluationID,
		correlation.ScanID,
		correlation.FindingOccurrenceID,
		correlation.EnforcementActionID,
		correlation.ModelRequestID,
		correlation.ModelResponseID,
		correlation.ToolInvocationID,
		correlation.DestinationID,
		correlation.ConnectorID,
		correlation.SidecarInstanceID,
	}
	for _, value := range values {
		if value == "" {
			continue
		}
		if !utf8.ValidString(value) {
			return fmt.Errorf("correlation identifier is not valid UTF-8")
		}
		if len(value) > MaxCorrelationIDBytes {
			return fmt.Errorf("correlation identifier exceeds %d bytes", MaxCorrelationIDBytes)
		}
	}
	return nil
}

// ImportProtocol identifies the accepted-record transport. It is closed in v8.
type ImportProtocol string

const ImportProtocolOTLP ImportProtocol = "otlp"

// ImportMode distinguishes a lossless canonical import from a derived local
// observation. Import-and-derive is used when one inbound leaf produces both.
type ImportMode string

const (
	ImportModeImport          ImportMode = "import"
	ImportModeDerive          ImportMode = "derive"
	ImportModeImportAndDerive ImportMode = "import_and_derive"
)

// ImportDerivation records the exact transformation used for a derived target.
type ImportDerivation string

const (
	ImportDerivationFieldValue      ImportDerivation = "field_value"
	ImportDerivationElapsedTime     ImportDerivation = "elapsed_time"
	ImportDerivationCumulativeDelta ImportDerivation = "cumulative_delta"
	ImportDerivationArithmeticMean  ImportDerivation = "arithmetic_mean"
)

// ImportProvenance is the closed, bounded description of one accepted OTLP
// occurrence. It is informational: local provenance remains authoritative.
// SourceAggregateCount preserves present-versus-absent because zero is not a
// valid arithmetic-mean divisor.
type ImportProvenance struct {
	Protocol                 ImportProtocol
	BindingID                string
	Mode                     ImportMode
	Derivation               ImportDerivation
	SourceAggregateCount     Optional[uint64]
	AuthenticatedSource      string
	UpstreamInstanceID       string
	UpstreamRecordID         string
	UpstreamServiceName      string
	UpstreamRedactionProfile string
	IngressHopCount          uint32
	LastHopInstanceID        string
	LastHopDestination       string
}

func (provenance ImportProvenance) Validate() error {
	if provenance.Protocol != ImportProtocolOTLP {
		return fmt.Errorf("import provenance protocol must be otlp")
	}
	if err := validateRequiredBoundedText("import binding ID", provenance.BindingID, MaxImportIdentifierBytes); err != nil {
		return err
	}
	if err := validateRequiredBoundedText("import authenticated source", provenance.AuthenticatedSource, MaxImportIdentifierBytes); err != nil {
		return err
	}
	for field, value := range map[string]string{
		"import upstream instance ID":  provenance.UpstreamInstanceID,
		"import upstream service name": provenance.UpstreamServiceName,
		"import last-hop instance ID":  provenance.LastHopInstanceID,
		"import last-hop destination":  provenance.LastHopDestination,
	} {
		if value == "" {
			continue
		}
		if err := validateRequiredBoundedText(field, value, MaxImportIdentifierBytes); err != nil {
			return err
		}
	}
	if provenance.UpstreamRecordID != "" &&
		!canonicalUUIDPattern.MatchString(provenance.UpstreamRecordID) &&
		!IsStableToken(provenance.UpstreamRecordID) {
		return fmt.Errorf("import upstream record ID must be a canonical UUID or stable token")
	}
	if provenance.UpstreamRedactionProfile != "" && !IsStableToken(provenance.UpstreamRedactionProfile) {
		return fmt.Errorf("import upstream redaction profile must be a stable token")
	}
	if provenance.IngressHopCount > MaxImportForwardHops {
		return fmt.Errorf("import ingress hop count exceeds %d", MaxImportForwardHops)
	}

	count, hasCount := provenance.SourceAggregateCount.Get()
	switch provenance.Mode {
	case ImportModeImport:
		if provenance.Derivation != "" {
			return fmt.Errorf("import mode forbids derivation")
		}
		if hasCount {
			return fmt.Errorf("import mode forbids source aggregate count")
		}
	case ImportModeDerive, ImportModeImportAndDerive:
		switch provenance.Derivation {
		case ImportDerivationFieldValue,
			ImportDerivationElapsedTime,
			ImportDerivationCumulativeDelta:
			if hasCount {
				return fmt.Errorf("source aggregate count is valid only for arithmetic_mean")
			}
		case ImportDerivationArithmeticMean:
			if !hasCount || count == 0 {
				return fmt.Errorf("arithmetic_mean requires a positive source aggregate count")
			}
		default:
			return fmt.Errorf("deriving import mode requires a canonical derivation")
		}
	default:
		return fmt.Errorf("import provenance mode is not canonical")
	}
	return nil
}

// Provenance records which binary, registry, and effective configuration
// generation constructed the record. Import is optional and never replaces
// these trusted local fields.
type Provenance struct {
	Producer              string            `json:"producer"`
	BinaryVersion         string            `json:"binary_version"`
	RegistrySchemaVersion int               `json:"registry_schema_version"`
	ConfigGeneration      int64             `json:"config_generation"`
	BuildCommit           string            `json:"build_commit,omitempty"`
	ConfigDigest          string            `json:"config_digest,omitempty"`
	Import                *ImportProvenance `json:"import,omitempty"`
}

func (provenance Provenance) Validate() error {
	if !provenanceProducerPattern.MatchString(provenance.Producer) {
		return fmt.Errorf("provenance producer must match the canonical producer syntax")
	}
	if err := validateRequiredBoundedText("binary version", provenance.BinaryVersion, MaxBinaryVersionBytes); err != nil {
		return err
	}
	if provenance.RegistrySchemaVersion <= 0 {
		return fmt.Errorf("registry schema version must be greater than zero")
	}
	if provenance.ConfigGeneration < 0 {
		return fmt.Errorf("config generation must not be negative")
	}
	if provenance.BuildCommit != "" && !lowerHexPattern.MatchString(provenance.BuildCommit) {
		return fmt.Errorf("build commit must be lower-case hexadecimal")
	}
	if len(provenance.BuildCommit) > MaxProvenanceHexBytes {
		return fmt.Errorf("build commit exceeds %d bytes", MaxProvenanceHexBytes)
	}
	if provenance.ConfigDigest != "" && !lowerHexPattern.MatchString(provenance.ConfigDigest) {
		return fmt.Errorf("config digest must be lower-case hexadecimal")
	}
	if len(provenance.ConfigDigest) > MaxProvenanceHexBytes {
		return fmt.Errorf("config digest exceeds %d bytes", MaxProvenanceHexBytes)
	}
	if provenance.Import != nil {
		if err := provenance.Import.Validate(); err != nil {
			return fmt.Errorf("invalid import provenance: %w", err)
		}
	}
	return nil
}

// RecordInput is the mutable construction form. NewRecord snapshots all of its
// maps, pointers, timestamps, and payloads into an immutable Record.
type RecordInput struct {
	Timestamp      time.Time
	ObservedAt     *time.Time
	RecordID       string
	Identity       EventIdentity
	SpanName       string
	Severity       *Severity
	LogLevel       LogLevel
	Source         Source
	Connector      string
	Action         string
	Phase          string
	Outcome        Outcome
	Correlation    Correlation
	Provenance     Provenance
	Body           any
	InstrumentData any
	FieldClasses   map[string]FieldClass
	// projectionPolicy is package-private so imported and ordinary RecordInput
	// callers cannot claim a local projection override. Generated family
	// envelopes are the sole construction path for this in-process marker.
	projectionPolicy ProjectionPolicy
}

// Record is an immutable canonical envelope. All fields are private; accessors
// return values or fresh clones and MarshalJSON constructs a new wire view.
type Record struct {
	data recordData
}

type recordData struct {
	timestamp                 time.Time
	observedAt                time.Time
	hasObservedAt             bool
	recordID                  string
	identity                  EventIdentity
	spanName                  string
	severity                  Severity
	hasSeverity               bool
	logLevel                  LogLevel
	source                    Source
	connector                 string
	action                    string
	phase                     string
	outcome                   Outcome
	mandatory                 bool
	correlation               Correlation
	provenance                Provenance
	body                      Value
	instrumentData            Value
	fieldClasses              map[string]FieldClass
	schemaDerivedFieldClasses bool
	floorOnly                 bool
	projectionPolicy          ProjectionPolicy
}

// NewRecord validates a complete canonical envelope and takes an immutable
// snapshot. The versions are fixed by this implementation and are not accepted
// from callers.
func NewRecord(input RecordInput) (Record, error) {
	return newRecord(input, false, false)
}

// newSchemaDerivedRecord is reserved for generated, registry-backed P5 family
// builders in this package. Keeping this path unexported prevents ordinary
// producers from asserting that an empty field-class map was schema-derived.
func newSchemaDerivedRecord(input RecordInput) (Record, error) {
	return newRecord(input, true, false)
}

// schemaDerivedLogFamilyContract is implemented by generated, registry-backed
// family descriptors. It binds construction to one exact identity and carries
// the mandatory decision already derived from that family's catalog rules.
// Keeping the interface private prevents ordinary producers from substituting a
// boolean mandatory claim at the constructor boundary.
type schemaDerivedLogFamilyContract interface {
	schemaDerivedLogIdentity() EventIdentity
	schemaDerivedLogMandatory() bool
}

// newSchemaDerivedLogRecord is reserved for generated, registry-backed P5 log
// family builders. Identity and mandatory state come from the private family
// contract rather than caller-controlled RecordInput fields or booleans.
func newSchemaDerivedLogRecord(
	input RecordInput,
	contract schemaDerivedLogFamilyContract,
) (Record, error) {
	if nilInterface(contract) {
		return Record{}, fmt.Errorf("schema-derived log record requires a family contract")
	}
	identity := contract.schemaDerivedLogIdentity()
	if identity.Signal != SignalLogs {
		return Record{}, fmt.Errorf("schema-derived log record requires the logs signal")
	}
	if !IsRegisteredEventIdentity(identity) {
		return Record{}, fmt.Errorf("schema-derived log family identity is not registered")
	}
	if input.Identity != identity {
		return Record{}, fmt.Errorf("schema-derived log record identity does not match its family contract")
	}
	return newRecord(input, true, contract.schemaDerivedLogMandatory())
}

func newClassifiedLogRecord(input RecordInput, mandatory, floorOnly bool) (Record, error) {
	return newRecordWithFloor(input, false, mandatory, floorOnly)
}

func newRecord(input RecordInput, schemaDerivedFieldClasses, mandatory bool) (Record, error) {
	return newRecordWithFloor(input, schemaDerivedFieldClasses, mandatory, false)
}

func newRecordWithFloor(input RecordInput, schemaDerivedFieldClasses, mandatory, floorOnly bool) (Record, error) {
	if floorOnly && !mandatory {
		return Record{}, fmt.Errorf("floor-only record must be mandatory")
	}
	if !input.projectionPolicy.valid() {
		return Record{}, fmt.Errorf("record projection policy is not canonical")
	}
	if input.Timestamp.IsZero() {
		return Record{}, fmt.Errorf("record timestamp is required")
	}
	if err := validateRequiredBoundedText("record ID", input.RecordID, MaxRecordIDBytes); err != nil {
		return Record{}, err
	}
	if !IsRegisteredEventIdentity(input.Identity) {
		return Record{}, fmt.Errorf("record identity is not registered")
	}
	if err := validateSignalFields(input, mandatory); err != nil {
		return Record{}, err
	}
	if input.Severity != nil {
		if _, ok := SeverityRank(*input.Severity); !ok {
			return Record{}, fmt.Errorf("record severity is not canonical")
		}
	}
	if input.LogLevel != "" && !isLogLevel(input.LogLevel) {
		return Record{}, fmt.Errorf("record log level is not canonical")
	}
	if err := ValidateStableToken("record source", string(input.Source)); err != nil {
		return Record{}, err
	}
	for field, value := range map[string]string{
		"record connector": input.Connector,
		"record action":    input.Action,
		"record phase":     input.Phase,
	} {
		if value != "" {
			if err := ValidateStableToken(field, value); err != nil {
				return Record{}, err
			}
		}
	}
	if input.Outcome != "" && !IsOutcome(input.Outcome) {
		return Record{}, fmt.Errorf("record outcome is not canonical")
	}
	if err := input.Correlation.validate(); err != nil {
		return Record{}, err
	}
	if err := input.Provenance.Validate(); err != nil {
		return Record{}, fmt.Errorf("invalid record provenance: %w", err)
	}
	if input.Provenance.Import != nil && !input.projectionPolicy.IsDefault() {
		return Record{}, fmt.Errorf("imported record cannot carry a local projection policy")
	}
	body, instrumentData, err := snapshotPayloads(input)
	if err != nil {
		return Record{}, err
	}
	selectedPayload := body
	if input.Identity.Signal == SignalMetrics {
		selectedPayload = instrumentData
	}
	fieldClasses, err := snapshotFieldClasses(
		input.FieldClasses,
		schemaDerivedFieldClasses,
		selectedPayload,
	)
	if err != nil {
		return Record{}, err
	}

	data := recordData{
		timestamp:                 input.Timestamp.UTC(),
		recordID:                  strings.Clone(input.RecordID),
		identity:                  cloneEventIdentity(input.Identity),
		spanName:                  strings.Clone(input.SpanName),
		logLevel:                  LogLevel(strings.Clone(string(input.LogLevel))),
		source:                    Source(strings.Clone(string(input.Source))),
		connector:                 strings.Clone(input.Connector),
		action:                    strings.Clone(input.Action),
		phase:                     strings.Clone(input.Phase),
		outcome:                   Outcome(strings.Clone(string(input.Outcome))),
		mandatory:                 mandatory,
		correlation:               cloneCorrelation(input.Correlation),
		provenance:                cloneProvenance(input.Provenance),
		body:                      body,
		instrumentData:            instrumentData,
		fieldClasses:              fieldClasses,
		schemaDerivedFieldClasses: schemaDerivedFieldClasses,
		floorOnly:                 floorOnly,
		projectionPolicy:          input.projectionPolicy,
	}
	if input.ObservedAt != nil {
		data.observedAt = input.ObservedAt.UTC()
		data.hasObservedAt = true
	}
	if input.Severity != nil {
		data.severity = Severity(strings.Clone(string(*input.Severity)))
		data.hasSeverity = true
	}
	record := Record{data: data}
	if _, err := record.MarshalJSON(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func validateSignalFields(input RecordInput, mandatory bool) error {
	switch input.Identity.Signal {
	case SignalLogs:
		if input.SpanName != "" {
			return fmt.Errorf("log record must not have a span name")
		}
		if input.Body == nil || input.InstrumentData != nil {
			return fmt.Errorf("log record requires exactly the body payload arm")
		}
	case SignalTraces:
		if err := validateRequiredBoundedText("span name", input.SpanName, MaxSpanNameBytes); err != nil {
			return err
		}
		if input.Body == nil || input.InstrumentData != nil {
			return fmt.Errorf("trace record requires exactly the body payload arm")
		}
		if mandatory {
			return fmt.Errorf("mandatory is defined only for log records")
		}
	case SignalMetrics:
		if input.SpanName != "" {
			return fmt.Errorf("metric record must not have a span name")
		}
		if input.Body != nil || input.InstrumentData == nil {
			return fmt.Errorf("metric record requires exactly the instrument_data payload arm")
		}
		if input.Severity != nil {
			return fmt.Errorf("metric record must not have severity")
		}
		if input.LogLevel != "" {
			return fmt.Errorf("metric record must not have a log level")
		}
		if input.Outcome != "" {
			return fmt.Errorf("metric record must not have an outcome")
		}
		if mandatory {
			return fmt.Errorf("mandatory is defined only for log records")
		}
	default:
		return fmt.Errorf("record signal is not canonical")
	}
	return nil
}

func snapshotPayloads(input RecordInput) (Value, Value, error) {
	if input.Identity.Signal == SignalMetrics {
		instrumentData, err := snapshotValue(input.InstrumentData)
		if err != nil {
			return Value{}, Value{}, err
		}
		return Value{}, instrumentData, nil
	}
	body, err := snapshotValue(input.Body)
	if err != nil {
		return Value{}, Value{}, err
	}
	return body, Value{}, nil
}

func snapshotValue(input any) (Value, error) {
	if value, ok := input.(Value); ok {
		if value.IsZero() {
			return Value{}, valueError(ValueErrorInvalidJSON)
		}
		return value.Clone(), nil
	}
	return NewValue(input)
}

func snapshotFieldClasses(
	input map[string]FieldClass,
	schemaDerived bool,
	payload Value,
) (map[string]FieldClass, error) {
	// SchemaDerivedFieldClasses is a trust-boundary assertion, not a runtime
	// schema lookup. P5 generated builders own proof that an empty explicit map
	// is backed by complete registry-derived classifications.
	if len(input) == 0 && !schemaDerived {
		return nil, fmt.Errorf("empty field classes require schema-derived classification")
	}
	object, err := payload.Object()
	if err != nil {
		return nil, err
	}
	result := make(map[string]FieldClass, len(input))
	for pointer, fieldClass := range input {
		if !validJSONPointer(pointer) {
			return nil, fmt.Errorf("field classes contain an invalid JSON Pointer")
		}
		if !IsFieldClass(fieldClass) {
			return nil, fmt.Errorf("field classes contain an unknown class")
		}
		if !jsonPointerResolves(object, pointer) {
			return nil, fmt.Errorf("field classes contain a JSON Pointer that does not resolve")
		}
		result[pointer] = fieldClass
	}
	if !schemaDerived {
		for _, leaf := range payloadLeafPointers(object) {
			if _, covered := result[leaf]; !covered {
				return nil, fmt.Errorf("field classes do not cover every payload leaf")
			}
		}
	}
	return result, nil
}

func payloadLeafPointers(root map[string]any) []string {
	result := make([]string, 0)
	var visit func(any, string)
	visit = func(value any, pointer string) {
		switch typed := value.(type) {
		case map[string]any:
			if len(typed) == 0 {
				result = append(result, pointer)
				return
			}
			for key, child := range typed {
				visit(child, pointer+"/"+encodeJSONPointerToken(key))
			}
		case []any:
			if len(typed) == 0 {
				result = append(result, pointer)
				return
			}
			for index, child := range typed {
				visit(child, pointer+"/"+strconv.Itoa(index))
			}
		default:
			result = append(result, pointer)
		}
	}
	visit(root, "")
	return result
}

func encodeJSONPointerToken(token string) string {
	token = strings.ReplaceAll(token, "~", "~0")
	return strings.ReplaceAll(token, "/", "~1")
}

func validJSONPointer(pointer string) bool {
	if !utf8.ValidString(pointer) {
		return false
	}
	if pointer == "" {
		return true
	}
	if pointer[0] != '/' {
		return false
	}
	for index := 0; index < len(pointer); index++ {
		if pointer[index] != '~' {
			continue
		}
		if index+1 >= len(pointer) || (pointer[index+1] != '0' && pointer[index+1] != '1') {
			return false
		}
		index++
	}
	return true
}

func jsonPointerResolves(root any, pointer string) bool {
	if pointer == "" {
		return true
	}
	current := root
	for _, encodedToken := range stringsAfterFirstSlash(pointer) {
		token := decodeJSONPointerToken(encodedToken)
		switch typed := current.(type) {
		case map[string]any:
			var exists bool
			current, exists = typed[token]
			if !exists {
				return false
			}
		case []any:
			if token == "" || (len(token) > 1 && token[0] == '0') {
				return false
			}
			index, err := strconv.ParseUint(token, 10, 64)
			if err != nil || index >= uint64(len(typed)) {
				return false
			}
			current = typed[index]
		default:
			return false
		}
	}
	return true
}

func stringsAfterFirstSlash(pointer string) []string {
	result := make([]string, 0, 1)
	start := 1
	for index := 1; index <= len(pointer); index++ {
		if index != len(pointer) && pointer[index] != '/' {
			continue
		}
		result = append(result, pointer[start:index])
		start = index + 1
	}
	return result
}

func decodeJSONPointerToken(token string) string {
	decoded := make([]byte, 0, len(token))
	for index := 0; index < len(token); index++ {
		if token[index] == '~' && index+1 < len(token) {
			index++
			if token[index] == '0' {
				decoded = append(decoded, '~')
			} else {
				decoded = append(decoded, '/')
			}
			continue
		}
		decoded = append(decoded, token[index])
	}
	return string(decoded)
}

func validateRequiredBoundedText(field, value string, maximum int) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", field)
	}
	if len(value) > maximum {
		return fmt.Errorf("%s exceeds %d bytes", field, maximum)
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("%s contains a control character", field)
		}
	}
	return nil
}

func isLogLevel(level LogLevel) bool {
	switch level {
	case LogLevelTrace, LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError, LogLevelFatal:
		return true
	default:
		return false
	}
}

// Clone returns a deep immutable copy.
func (record Record) Clone() Record {
	data := record.data
	data.body = record.data.body.Clone()
	data.instrumentData = record.data.instrumentData.Clone()
	data.fieldClasses = cloneFieldClasses(record.data.fieldClasses)
	data.provenance = cloneProvenance(record.data.provenance)
	return Record{data: data}
}

func cloneFieldClasses(input map[string]FieldClass) map[string]FieldClass {
	result := make(map[string]FieldClass, len(input))
	for pointer, fieldClass := range input {
		result[strings.Clone(pointer)] = FieldClass(strings.Clone(string(fieldClass)))
	}
	return result
}

func cloneEventIdentity(input EventIdentity) EventIdentity {
	return EventIdentity{
		Bucket: Bucket(strings.Clone(string(input.Bucket))),
		Signal: Signal(strings.Clone(string(input.Signal))),
		Name:   EventName(strings.Clone(string(input.Name))),
	}
}

func cloneCorrelation(input Correlation) Correlation {
	return Correlation{
		SemanticEventID:     strings.Clone(input.SemanticEventID),
		LogicalEventID:      strings.Clone(input.LogicalEventID),
		ConnectorInstanceID: strings.Clone(input.ConnectorInstanceID),
		RunID:               strings.Clone(input.RunID),
		RequestID:           strings.Clone(input.RequestID),
		SessionID:           strings.Clone(input.SessionID),
		TurnID:              strings.Clone(input.TurnID),
		TraceID:             strings.Clone(input.TraceID),
		SpanID:              strings.Clone(input.SpanID),
		AgentID:             strings.Clone(input.AgentID),
		AgentInstanceID:     strings.Clone(input.AgentInstanceID),
		PolicyID:            strings.Clone(input.PolicyID),
		PolicyVersion:       strings.Clone(input.PolicyVersion),
		EvaluationID:        strings.Clone(input.EvaluationID),
		ScanID:              strings.Clone(input.ScanID),
		FindingOccurrenceID: strings.Clone(input.FindingOccurrenceID),
		EnforcementActionID: strings.Clone(input.EnforcementActionID),
		ModelRequestID:      strings.Clone(input.ModelRequestID),
		ModelResponseID:     strings.Clone(input.ModelResponseID),
		ToolInvocationID:    strings.Clone(input.ToolInvocationID),
		DestinationID:       strings.Clone(input.DestinationID),
		ConnectorID:         strings.Clone(input.ConnectorID),
		SidecarInstanceID:   strings.Clone(input.SidecarInstanceID),
	}
}

func cloneProvenance(input Provenance) Provenance {
	return Provenance{
		Producer:              strings.Clone(input.Producer),
		BinaryVersion:         strings.Clone(input.BinaryVersion),
		RegistrySchemaVersion: input.RegistrySchemaVersion,
		ConfigGeneration:      input.ConfigGeneration,
		BuildCommit:           strings.Clone(input.BuildCommit),
		ConfigDigest:          strings.Clone(input.ConfigDigest),
		Import:                cloneImportProvenance(input.Import),
	}
}

func cloneImportProvenance(input *ImportProvenance) *ImportProvenance {
	if input == nil {
		return nil
	}
	return &ImportProvenance{
		Protocol:                 ImportProtocol(strings.Clone(string(input.Protocol))),
		BindingID:                strings.Clone(input.BindingID),
		Mode:                     ImportMode(strings.Clone(string(input.Mode))),
		Derivation:               ImportDerivation(strings.Clone(string(input.Derivation))),
		SourceAggregateCount:     input.SourceAggregateCount,
		AuthenticatedSource:      strings.Clone(input.AuthenticatedSource),
		UpstreamInstanceID:       strings.Clone(input.UpstreamInstanceID),
		UpstreamRecordID:         strings.Clone(input.UpstreamRecordID),
		UpstreamServiceName:      strings.Clone(input.UpstreamServiceName),
		UpstreamRedactionProfile: strings.Clone(input.UpstreamRedactionProfile),
		IngressHopCount:          input.IngressHopCount,
		LastHopInstanceID:        strings.Clone(input.LastHopInstanceID),
		LastHopDestination:       strings.Clone(input.LastHopDestination),
	}
}

func (record Record) SchemaVersion() int        { return CurrentRecordSchemaVersion }
func (record Record) BucketCatalogVersion() int { return CurrentBucketCatalogVersion }
func (record Record) Timestamp() time.Time      { return record.data.timestamp }
func (record Record) RecordID() string          { return strings.Clone(record.data.recordID) }
func (record Record) Identity() EventIdentity   { return cloneEventIdentity(record.data.identity) }
func (record Record) Bucket() Bucket            { return record.data.identity.Bucket }
func (record Record) Signal() Signal            { return record.data.identity.Signal }
func (record Record) EventName() EventName      { return record.data.identity.Name }
func (record Record) SpanName() string          { return strings.Clone(record.data.spanName) }
func (record Record) LogLevel() LogLevel        { return record.data.logLevel }
func (record Record) Source() Source            { return record.data.source }
func (record Record) Connector() string         { return strings.Clone(record.data.connector) }
func (record Record) Action() string            { return strings.Clone(record.data.action) }
func (record Record) Phase() string             { return strings.Clone(record.data.phase) }
func (record Record) Outcome() Outcome          { return record.data.outcome }
func (record Record) Mandatory() bool           { return record.data.mandatory }
func (record Record) Correlation() Correlation  { return cloneCorrelation(record.data.correlation) }
func (record Record) Provenance() Provenance    { return cloneProvenance(record.data.provenance) }

// WithCorrelationDefaults returns an immutable copy whose missing correlation
// fields are filled from defaults. The occurrence identity triplet must agree
// when both the record and defaults provide it; a mismatch fails closed. Every
// other non-empty record field remains authoritative because a generated record
// can legitimately carry a more specific business identifier than its enclosing
// runtime context. The receiver is never mutated.
func (record Record) WithCorrelationDefaults(defaults Correlation) (Record, error) {
	if record.data.timestamp.IsZero() || record.data.recordID == "" {
		return Record{}, fmt.Errorf("cannot add correlation defaults to a zero or invalid canonical record")
	}
	if err := defaults.validate(); err != nil {
		return Record{}, fmt.Errorf("invalid correlation defaults: %w", err)
	}
	merged, err := mergeCorrelationDefaults(record.data.correlation, defaults)
	if err != nil {
		return Record{}, err
	}
	result := record.Clone()
	result.data.correlation = merged
	return result, nil
}

func mergeCorrelationDefaults(existing, defaults Correlation) (Correlation, error) {
	result := cloneCorrelation(existing)
	fields := []struct {
		name       string
		existing   *string
		defaultVal string
		strict     bool
	}{
		{"semantic_event_id", &result.SemanticEventID, defaults.SemanticEventID, true},
		{"logical_event_id", &result.LogicalEventID, defaults.LogicalEventID, true},
		{"connector_instance_id", &result.ConnectorInstanceID, defaults.ConnectorInstanceID, true},
		{"run_id", &result.RunID, defaults.RunID, false},
		{"request_id", &result.RequestID, defaults.RequestID, false},
		{"session_id", &result.SessionID, defaults.SessionID, false},
		{"turn_id", &result.TurnID, defaults.TurnID, false},
		{"trace_id", &result.TraceID, defaults.TraceID, false},
		{"span_id", &result.SpanID, defaults.SpanID, false},
		{"agent_id", &result.AgentID, defaults.AgentID, false},
		{"agent_instance_id", &result.AgentInstanceID, defaults.AgentInstanceID, false},
		{"policy_id", &result.PolicyID, defaults.PolicyID, false},
		{"policy_version", &result.PolicyVersion, defaults.PolicyVersion, false},
		{"evaluation_id", &result.EvaluationID, defaults.EvaluationID, false},
		{"scan_id", &result.ScanID, defaults.ScanID, false},
		{"finding_occurrence_id", &result.FindingOccurrenceID, defaults.FindingOccurrenceID, false},
		{"enforcement_action_id", &result.EnforcementActionID, defaults.EnforcementActionID, false},
		{"model_request_id", &result.ModelRequestID, defaults.ModelRequestID, false},
		{"model_response_id", &result.ModelResponseID, defaults.ModelResponseID, false},
		{"tool_invocation_id", &result.ToolInvocationID, defaults.ToolInvocationID, false},
		{"destination_id", &result.DestinationID, defaults.DestinationID, false},
		{"connector_id", &result.ConnectorID, defaults.ConnectorID, false},
		{"sidecar_instance_id", &result.SidecarInstanceID, defaults.SidecarInstanceID, false},
	}
	for _, field := range fields {
		if field.defaultVal == "" {
			continue
		}
		if field.strict && *field.existing != "" && *field.existing != field.defaultVal {
			return Correlation{}, fmt.Errorf("correlation default conflicts with existing %s", field.name)
		}
		if *field.existing == "" {
			*field.existing = strings.Clone(field.defaultVal)
		}
	}
	return result, nil
}

// ProjectionPolicy returns the immutable local projection override associated
// with this occurrence. It is intentionally absent from MarshalJSON.
func (record Record) ProjectionPolicy() ProjectionPolicy {
	return record.data.projectionPolicy
}

func (record Record) ObservedAt() (time.Time, bool) {
	return record.data.observedAt, record.data.hasObservedAt
}

func (record Record) Severity() (Severity, bool) {
	return record.data.severity, record.data.hasSeverity
}

func (record Record) Body() (Value, bool) {
	if record.data.body.IsZero() {
		return Value{}, false
	}
	return record.data.body.Clone(), true
}

func (record Record) InstrumentData() (Value, bool) {
	if record.data.instrumentData.IsZero() {
		return Value{}, false
	}
	return record.data.instrumentData.Clone(), true
}

func (record Record) FieldClasses() map[string]FieldClass {
	return cloneFieldClasses(record.data.fieldClasses)
}

func (record Record) SchemaDerivedFieldClasses() bool {
	return record.data.schemaDerivedFieldClasses
}

// IsFloorOnly marks the minimal mandatory-floor form. It is intentionally not
// serialized; admission uses the in-process marker to prevent ordinary records
// from claiming the floor bypass.
func (record Record) IsFloorOnly() bool {
	return record.data.floorOnly
}

func (record Record) MarshalJSON() ([]byte, error) {
	if record.data.timestamp.IsZero() || record.data.recordID == "" {
		return nil, fmt.Errorf("cannot marshal a zero or invalid canonical record")
	}
	wire := map[string]any{
		"schema_version":         CurrentRecordSchemaVersion,
		"bucket_catalog_version": CurrentBucketCatalogVersion,
		"timestamp":              record.data.timestamp,
		"record_id":              record.data.recordID,
		"bucket":                 record.data.identity.Bucket,
		"signal":                 record.data.identity.Signal,
		"event_name":             record.data.identity.Name,
		"source":                 record.data.source,
		"correlation":            correlationWire(record.data.correlation),
		"provenance":             provenanceWire(record.data.provenance),
		"field_classes":          cloneFieldClasses(record.data.fieldClasses),
	}
	if record.data.hasObservedAt {
		wire["observed_at"] = record.data.observedAt
	}
	if record.data.hasSeverity {
		wire["severity"] = record.data.severity
	}
	if record.data.spanName != "" {
		wire["span_name"] = record.data.spanName
	}
	if record.data.logLevel != "" {
		wire["log_level"] = record.data.logLevel
	}
	for key, value := range map[string]string{
		"connector": record.data.connector,
		"action":    record.data.action,
		"phase":     record.data.phase,
		"outcome":   string(record.data.outcome),
	} {
		if value != "" {
			wire[key] = value
		}
	}
	if record.data.identity.Signal == SignalLogs {
		wire["mandatory"] = record.data.mandatory
	}
	if !record.data.body.IsZero() {
		wire["body"] = record.data.body.Clone()
	}
	if !record.data.instrumentData.IsZero() {
		wire["instrument_data"] = record.data.instrumentData.Clone()
	}
	encoded, err := marshalMinimalJSON(wire)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxCanonicalRecordBytes {
		return nil, fmt.Errorf("canonical record exceeds %d encoded bytes", MaxCanonicalRecordBytes)
	}
	return encoded, nil
}

func correlationWire(correlation Correlation) map[string]any {
	wire := make(map[string]any)
	for key, value := range map[string]string{
		"semantic_event_id":     correlation.SemanticEventID,
		"logical_event_id":      correlation.LogicalEventID,
		"connector_instance_id": correlation.ConnectorInstanceID,
		"run_id":                correlation.RunID,
		"request_id":            correlation.RequestID,
		"session_id":            correlation.SessionID,
		"turn_id":               correlation.TurnID,
		"trace_id":              correlation.TraceID,
		"span_id":               correlation.SpanID,
		"agent_id":              correlation.AgentID,
		"agent_instance_id":     correlation.AgentInstanceID,
		"policy_id":             correlation.PolicyID,
		"policy_version":        correlation.PolicyVersion,
		"evaluation_id":         correlation.EvaluationID,
		"scan_id":               correlation.ScanID,
		"finding_occurrence_id": correlation.FindingOccurrenceID,
		"enforcement_action_id": correlation.EnforcementActionID,
		"model_request_id":      correlation.ModelRequestID,
		"model_response_id":     correlation.ModelResponseID,
		"tool_invocation_id":    correlation.ToolInvocationID,
		"destination_id":        correlation.DestinationID,
		"connector_id":          correlation.ConnectorID,
		"sidecar_instance_id":   correlation.SidecarInstanceID,
	} {
		if value != "" {
			wire[key] = value
		}
	}
	return wire
}

func provenanceWire(provenance Provenance) map[string]any {
	wire := map[string]any{
		"producer":                provenance.Producer,
		"binary_version":          provenance.BinaryVersion,
		"registry_schema_version": provenance.RegistrySchemaVersion,
		"config_generation":       provenance.ConfigGeneration,
	}
	if provenance.BuildCommit != "" {
		wire["build_commit"] = provenance.BuildCommit
	}
	if provenance.ConfigDigest != "" {
		wire["config_digest"] = provenance.ConfigDigest
	}
	if provenance.Import != nil {
		wire["import"] = importProvenanceWire(*provenance.Import)
	}
	return wire
}

func importProvenanceWire(provenance ImportProvenance) map[string]any {
	wire := map[string]any{
		"protocol":             provenance.Protocol,
		"binding_id":           provenance.BindingID,
		"mode":                 provenance.Mode,
		"authenticated_source": provenance.AuthenticatedSource,
		"ingress_hop_count":    provenance.IngressHopCount,
	}
	if provenance.Derivation != "" {
		wire["derivation"] = provenance.Derivation
	}
	if count, present := provenance.SourceAggregateCount.Get(); present {
		wire["source_aggregate_count"] = count
	}
	for key, value := range map[string]string{
		"upstream_instance_id":       provenance.UpstreamInstanceID,
		"upstream_record_id":         provenance.UpstreamRecordID,
		"upstream_service_name":      provenance.UpstreamServiceName,
		"upstream_redaction_profile": provenance.UpstreamRedactionProfile,
		"last_hop_instance_id":       provenance.LastHopInstanceID,
		"last_hop_destination":       provenance.LastHopDestination,
	} {
		if value != "" {
			wire[key] = value
		}
	}
	return wire
}

// Bytes returns a fresh deterministic minimal-escape JSON encoding.
func (record Record) Bytes() ([]byte, error) {
	return record.MarshalJSON()
}
