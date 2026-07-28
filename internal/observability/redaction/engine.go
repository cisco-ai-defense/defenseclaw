// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	legacyredaction "github.com/defenseclaw/defenseclaw/internal/redaction"
)

type engineOrigin struct{ identity byte }

// Engine owns one immutable cloned correlation key and projection origin.
// A keyless engine supports none and the fixed unkeyed legacy-v7 compatibility
// profile; keyed redacting profiles fail affected fields closed.
type Engine struct {
	origin       *engineOrigin
	key          [hashV1KeySize]byte
	keyAvailable bool
}

// NewEngine accepts either no key or exactly 32 bytes and always snapshots it.
func NewEngine(key []byte) (*Engine, error) {
	if len(key) != 0 && len(key) != hashV1KeySize {
		return nil, &ProjectionError{Code: ProjectionFailureContext}
	}
	engine := &Engine{origin: &engineOrigin{identity: 1}, keyAvailable: len(key) == hashV1KeySize}
	copy(engine.key[:], key)
	return engine, nil
}

// NewEngineWithCorrelationKey is the key-custody integration boundary. A zero
// key creates a keyless engine so none and legacy-v7 remain available while
// keyed redacting profiles fail affected fields closed.
func NewEngineWithCorrelationKey(key CorrelationKey) (*Engine, error) {
	material, available := key.Material()
	if !available {
		return NewEngine(nil)
	}
	if key.ID() != hashV1KeyID(material[:]) {
		return nil, &ProjectionError{Code: ProjectionFailureContext}
	}
	engine, err := NewEngine(material[:])
	for index := range material {
		material[index] = 0
	}
	return engine, err
}

// Project creates an independent immutable route projection.
func (engine *Engine) Project(record observability.Record, profile Profile) (Projection, SafeReport, error) {
	report := newReportBuilder(profile)
	if engine == nil || engine.origin == nil || !validProfile(profile) {
		report.failRecord(ProjectionFailureContext)
		return Projection{}, report.report(), &ProjectionError{Code: ProjectionFailureContext}
	}
	payload, ok := recordPayload(record)
	if !ok {
		report.failRecord(ProjectionFailureSerialization)
		return Projection{}, report.report(), &ProjectionError{Code: ProjectionFailureSerialization}
	}
	object, err := payload.Object()
	if err != nil {
		report.failRecord(ProjectionFailureSerialization)
		return Projection{}, report.report(), &ProjectionError{Code: ProjectionFailureSerialization}
	}
	classes := record.FieldClasses()
	if err := preflightFieldMap(object, classes); err != nil {
		report.failRecord(ProjectionFailureClassification)
		return Projection{}, report.report(), &ProjectionError{Code: ProjectionFailureClassification}
	}
	if record.Signal() == observability.SignalMetrics {
		if err := validateMetricClasses(classes, record.SchemaDerivedFieldClasses()); err != nil {
			report.failRecord(ProjectionFailureMetricClass)
			return Projection{}, report.report(), &ProjectionError{Code: ProjectionFailureMetricClass}
		}
	}

	projectedPayload := payload.Clone()
	if record.Signal() != observability.SignalMetrics {
		state := projectionWalkState{
			engine: engine, profile: profile, classes: classes,
			report: report, budget: NewRecordMatchBudget(),
		}
		projectedObject, walkErr := state.walkObject(object, "")
		if walkErr != nil {
			report.failRecord(ProjectionFailureSerialization)
			return Projection{}, report.report(), &ProjectionError{Code: ProjectionFailureSerialization}
		}
		projectedPayload, err = observability.NewValue(projectedObject)
		if err != nil {
			report.failRecord(ProjectionFailureOutputLimit)
			return Projection{}, report.report(), &ProjectionError{Code: ProjectionFailureOutputLimit}
		}
	}
	encoded, err := marshalProjectedRecord(record, projectedPayload, report.metadata)
	if err != nil {
		code := ProjectionFailureSerialization
		if IsProjectionError(err, ProjectionFailureOutputLimit) {
			code = ProjectionFailureOutputLimit
		}
		report.failRecord(code)
		return Projection{}, report.report(), &ProjectionError{Code: code}
	}
	keyID := ""
	if engine.keyAvailable {
		keyID = hashV1KeyID(engine.key[:])
	}
	finalReport := report.report()
	projection := Projection{
		payload: projectedPayload.Clone(), metadata: report.metadata, report: finalReport.clone(),
		encoded: append([]byte(nil), encoded...), origin: engine.origin,
		profileFingerprint: profile.fingerprint, keyID: keyID,
		catalogVersion: DetectorCatalogVersion(),
	}
	return projection, finalReport, nil
}

// Reproject is intentionally narrow. It returns a deep clone only for the
// original trusted engine/profile/key/catalog tuple and never retains raw data
// to support changing that tuple.
func (engine *Engine) Reproject(projection Projection, profile Profile) (Projection, SafeReport, error) {
	report := newReportBuilder(profile)
	keyID := ""
	if engine != nil && engine.keyAvailable {
		keyID = hashV1KeyID(engine.key[:])
	}
	if engine == nil || engine.origin == nil || projection.origin != engine.origin ||
		!validProfile(profile) || projection.profileFingerprint != profile.fingerprint ||
		projection.catalogVersion != DetectorCatalogVersion() || projection.keyID != keyID ||
		len(projection.encoded) == 0 || projection.payload.IsZero() {
		report.failRecord(ProjectionFailureContext)
		return Projection{}, report.report(), &ProjectionError{Code: ProjectionFailureContext}
	}
	clone := projection.clone()
	return clone, clone.report.clone(), nil
}

func validProfile(profile Profile) bool {
	if profile.name == "" || profile.fingerprint != profileFingerprint(profile) {
		return false
	}
	if builtIn, ok := BuiltInProfile(profile.name); ok {
		return profile.fingerprint == builtIn.fingerprint
	}
	return validateResolvedProfile(profile, true) == nil
}

func recordPayload(record observability.Record) (observability.Value, bool) {
	if record.Signal() == observability.SignalMetrics {
		return record.InstrumentData()
	}
	return record.Body()
}

func validateMetricClasses(classes map[string]observability.FieldClass, schemaDerived bool) error {
	for _, class := range classes {
		switch class {
		case observability.FieldClassMetadata:
		case observability.FieldClassIdentifier:
			if !schemaDerived {
				return &ProjectionError{Code: ProjectionFailureMetricClass}
			}
		default:
			return &ProjectionError{Code: ProjectionFailureMetricClass}
		}
	}
	return nil
}

type projectionWalkState struct {
	engine  *Engine
	profile Profile
	classes map[string]observability.FieldClass
	report  *reportBuilder
	budget  *RecordMatchBudget
}

func (state *projectionWalkState) walkObject(input map[string]any, pointer string) (map[string]any, error) {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	output := make(map[string]any, len(input))
	for _, key := range keys {
		childPointer := pointer + "/" + encodePointerToken(key)
		child, remove, err := state.walk(input[key], childPointer)
		if err != nil {
			return nil, err
		}
		if !remove {
			output[strings.Clone(key)] = child
		}
	}
	return output, nil
}

func (state *projectionWalkState) walk(input any, pointer string) (any, bool, error) {
	switch typed := input.(type) {
	case map[string]any:
		if len(typed) == 0 {
			return state.transformLeaf(map[string]any{}, pointer)
		}
		object, err := state.walkObject(typed, pointer)
		if err != nil {
			return nil, false, err
		}
		if len(object) == 0 {
			// The descendants already account for their own removals. Count
			// this additional parent property/array-slot structural removal too.
			state.report.removed()
			return nil, true, nil
		}
		return object, false, nil
	case []any:
		if len(typed) == 0 {
			return state.transformLeaf([]any{}, pointer)
		}
		array := make([]any, len(typed))
		for index, child := range typed {
			childPointer := pointer + "/" + strconv.Itoa(index)
			projected, remove, err := state.walk(child, childPointer)
			if err != nil {
				return nil, false, err
			}
			if remove {
				array[index] = nil
			} else {
				array[index] = projected
			}
		}
		return array, false, nil
	default:
		return state.transformLeaf(typed, pointer)
	}
}

func (state *projectionWalkState) transformLeaf(input any, pointer string) (any, bool, error) {
	class, ok := state.classes[pointer]
	if !ok {
		return nil, false, &ProjectionError{Code: ProjectionFailureClassification}
	}
	mode, ok := state.profile.Mode(class)
	if !ok {
		return nil, false, &ProjectionError{Code: ProjectionFailureContext}
	}
	if mode == ModeRemove {
		state.report.removed()
		return nil, true, nil
	}
	// Empty containers are canonical leaves for class-map completeness, but
	// only remove applies to a container; scalar modes retain their shape.
	switch typed := input.(type) {
	case map[string]any:
		return map[string]any{}, false, nil
	case []any:
		return []any{}, false, nil
	case nil:
		return nil, false, nil
	case string:
		return state.transformString(typed, class, mode)
	case bool:
		if mode != ModeWhole && mode != ModeHash {
			return typed, false, nil
		}
		return state.transformString(strconv.FormatBool(typed), class, mode)
	case json.Number:
		if mode != ModeWhole && mode != ModeHash {
			return json.Number(strings.Clone(typed.String())), false, nil
		}
		return state.transformString(typed.String(), class, mode)
	default:
		return nil, false, &ProjectionError{Code: ProjectionFailureSerialization}
	}
}

func (state *projectionWalkState) transformString(
	input string,
	class observability.FieldClass,
	mode TransformationMode,
) (any, bool, error) {
	if state.profile.name == ProfileLegacyV7 {
		return state.transformLegacyV7(input, class), false, nil
	}
	switch mode {
	case ModePreserve:
		return strings.Clone(input), false, nil
	case ModeDetect:
		result, err := DetectAndRedact(input, class, state.profile.DetectorGroups(), state.engine.keyBytes(), state.budget)
		if err != nil {
			code := string(result.Failure)
			if code == "" {
				code = string(FailureValidator)
			}
			state.report.failField(class, mode, code)
			if result.Value != input {
				state.report.transformed(false)
			}
			return strings.Clone(result.Value), false, nil
		}
		if result.Oversize {
			state.report.transformed(true)
		} else if len(result.Matches) > 0 {
			state.report.transformed(false)
		}
		return strings.Clone(result.Value), false, nil
	case ModeWhole:
		token, err := WholeToken(class, input, state.engine.keyBytes())
		if err != nil {
			return state.failedScalar(input, class, mode, fieldFailureCode(err))
		}
		state.report.transformed(false)
		return token, false, nil
	case ModeHash:
		token, err := HashV1(input, class, state.engine.keyBytes())
		if err != nil {
			return state.failedScalar(input, class, mode, hashFailureCode(err))
		}
		state.report.transformed(false)
		return token, false, nil
	default:
		return nil, false, &ProjectionError{Code: ProjectionFailureContext}
	}
}

func (state *projectionWalkState) transformLegacyV7(input string, class observability.FieldClass) string {
	var output string
	switch class {
	case observability.FieldClassMetadata:
		return strings.Clone(input)
	case observability.FieldClassIdentifier:
		output = legacyredaction.LegacyV7Entity(input)
	case observability.FieldClassContent:
		output = legacyredaction.LegacyV7MessageContent(input)
	case observability.FieldClassReason:
		output = legacyredaction.LegacyV7Reason(input)
	case observability.FieldClassEvidence:
		output = legacyredaction.LegacyV7Evidence(input, -1, -1)
	case observability.FieldClassError, observability.FieldClassPath, observability.FieldClassCredential:
		output = legacyredaction.LegacyV7String(input)
	default:
		// Complete class-map preflight makes this unreachable. Retain a safe
		// defensive whole-field placeholder without exposing the input.
		output = legacyredaction.LegacyV7String(input)
	}
	if output != input {
		state.report.transformed(false)
	}
	return output
}

func (state *projectionWalkState) failedScalar(
	input string,
	class observability.FieldClass,
	mode TransformationMode,
	code string,
) (any, bool, error) {
	if !safeFailureCode(code) {
		code = string(FailureValidator)
	}
	state.report.failField(class, mode, code)
	token := fmt.Sprintf("<redacted type=failed_closed v=1 code=%s>", code)
	if token != input {
		state.report.transformed(false)
	}
	return token, false, nil
}

func (engine *Engine) keyBytes() []byte {
	if engine == nil || !engine.keyAvailable {
		return nil
	}
	return append([]byte(nil), engine.key[:]...)
}

func fieldFailureCode(err error) string {
	for _, code := range []FailureCode{
		FailureInvalidUTF8, FailureKeyUnavailable, FailureCandidateLimit,
		FailureFieldMatchLimit, FailureRecordMatchLimit, FailureMatcher, FailureValidator,
	} {
		if IsDetectorError(err, code) {
			return string(code)
		}
	}
	return string(FailureValidator)
}

func hashFailureCode(err error) string {
	switch {
	case IsHashV1Error(err, HashV1ErrorInvalidUTF8):
		return string(FailureInvalidUTF8)
	case IsHashV1Error(err, HashV1ErrorInvalidKey):
		return string(FailureKeyUnavailable)
	case IsHashV1Error(err, HashV1ErrorUnicodeRepertoire):
		return "unicode_repertoire"
	case IsHashV1Error(err, HashV1ErrorNormalization):
		return "normalization_failed"
	default:
		return string(FailureValidator)
	}
}

func safeFailureCode(code string) bool {
	if code == "" || len(code) > 64 || !utf8.ValidString(code) {
		return false
	}
	for index := range code {
		character := code[index]
		if (character < 'a' || character > 'z') && character != '_' && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func preflightFieldMap(root map[string]any, classes map[string]observability.FieldClass) error {
	leaves := leafPointers(root)
	if len(leaves) != len(classes) {
		return &ProjectionError{Code: ProjectionFailureClassification}
	}
	for _, pointer := range leaves {
		class, ok := classes[pointer]
		if !ok || !observability.IsFieldClass(class) {
			return &ProjectionError{Code: ProjectionFailureClassification}
		}
	}
	return nil
}

func leafPointers(root map[string]any) []string {
	result := make([]string, 0)
	var visit func(any, string)
	visit = func(value any, pointer string) {
		switch typed := value.(type) {
		case map[string]any:
			if len(typed) == 0 {
				result = append(result, pointer)
				return
			}
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				visit(typed[key], pointer+"/"+encodePointerToken(key))
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

func encodePointerToken(token string) string {
	token = strings.ReplaceAll(token, "~", "~0")
	return strings.ReplaceAll(token, "/", "~1")
}
