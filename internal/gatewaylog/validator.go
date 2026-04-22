// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gatewaylog

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// embeddedSchemas ships the four JSON-schema files the validator
// compiles against directly in the binary. Having them embedded
// means the sidecar can enable strict validation at boot without
// assuming any on-disk layout of the repo — critical for the
// single-binary distribution promise. The files are kept in sync
// with schemas/*.json at the repo root by TestEmbeddedSchemasMatch.
//
//go:embed schemas/gateway-event-envelope.json
//go:embed schemas/scan-event.json
//go:embed schemas/scan-finding-event.json
//go:embed schemas/activity-event.json
var embeddedSchemas embed.FS

// Validator is the runtime schema gate sitting in front of every
// Writer.Emit. It compiles `schemas/gateway-event-envelope.json` plus
// the three `$ref`d nested schemas (scan / scan_finding / activity)
// at construction time and applies them on a per-event basis.
//
// Validation runs on the marshaled JSON form because that is what
// sinks/fanout actually see — Go-struct-level invariants are not
// sufficient (omitempty, pointer-nil vs zero value, etc).
//
// The zero Validator is a usable no-op (returns nil from Validate),
// which matches the legacy behavior when the operator opts out via
// DEFENSECLAW_SCHEMA_VALIDATION=off.
type Validator struct {
	schema *jsonschema.Schema
}

// ValidationError is returned by Validate when the event payload
// fails the envelope schema. Kept small and operator-facing; the
// underlying jsonschema.ValidationError is available via Unwrap for
// callers that want the rich tree.
type ValidationError struct {
	EventType EventType
	Message   string
	Cause     error
}

func (e *ValidationError) Error() string {
	if e == nil {
		return ""
	}
	if e.EventType == "" {
		return "gatewaylog: schema violation: " + e.Message
	}
	return fmt.Sprintf("gatewaylog: schema violation (%s): %s", e.EventType, e.Message)
}

func (e *ValidationError) Unwrap() error { return e.Cause }

// The envelope references three sibling schemas via absolute URI.
// We resolve the full schema tree from a single directory on disk so
// operators can point the validator at a pinned copy in a container
// image / release bundle.
const (
	schemaEnvelopeID    = "https://defenseclaw.io/schemas/gateway-event-envelope.json"
	schemaScanID        = "https://defenseclaw.io/schemas/scan-event.json"
	schemaScanFindingID = "https://defenseclaw.io/schemas/scan-finding-event.json"
	schemaActivityID    = "https://defenseclaw.io/schemas/activity-event.json"

	schemaEnvelopeFile    = "gateway-event-envelope.json"
	schemaScanFile        = "scan-event.json"
	schemaScanFindingFile = "scan-finding-event.json"
	schemaActivityFile    = "activity-event.json"
)

// NewDefaultValidator builds a Validator from the schemas embedded
// into the binary at build time. This is the constructor the sidecar
// boot should call — it has no filesystem dependencies and cannot
// drift out of sync with the Go structs because a sync test fails
// the build when the embed copies diverge from schemas/*.json.
func NewDefaultValidator() (*Validator, error) {
	files := map[string]string{
		schemaEnvelopeID:    "schemas/" + schemaEnvelopeFile,
		schemaScanID:        "schemas/" + schemaScanFile,
		schemaScanFindingID: "schemas/" + schemaScanFindingFile,
		schemaActivityID:    "schemas/" + schemaActivityFile,
	}
	docs := make(map[string][]byte, len(files))
	for uri, path := range files {
		b, err := embeddedSchemas.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("gatewaylog: validator: read embedded %s: %w", path, err)
		}
		docs[uri] = b
	}
	return newValidatorFromDocs(docs)
}

// NewValidatorFromDir builds a Validator from the `schemas/` directory
// on disk. `dir` must contain the four files named by the schema*File
// constants above. Missing or malformed files return an error —
// callers treat this as fatal and fall back to a no-op Validator only
// if they explicitly opt out of strict mode.
func NewValidatorFromDir(dir string) (*Validator, error) {
	if dir == "" {
		return nil, errors.New("gatewaylog: validator: schema directory is empty")
	}
	files := map[string]string{
		schemaEnvelopeID:    filepath.Join(dir, schemaEnvelopeFile),
		schemaScanID:        filepath.Join(dir, schemaScanFile),
		schemaScanFindingID: filepath.Join(dir, schemaScanFindingFile),
		schemaActivityID:    filepath.Join(dir, schemaActivityFile),
	}
	docs := make(map[string][]byte, len(files))
	for uri, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("gatewaylog: validator: read %s: %w", path, err)
		}
		docs[uri] = b
	}
	return newValidatorFromDocs(docs)
}

// NewValidatorFromDocs is the in-memory constructor primarily used by
// tests. Keys are schema `$id` URIs; values are the raw JSON bytes.
// Exactly the four envelope/scan/scan_finding/activity URIs must be
// provided (a superset is allowed but the envelope URI is required).
func NewValidatorFromDocs(docs map[string][]byte) (*Validator, error) {
	return newValidatorFromDocs(docs)
}

func newValidatorFromDocs(docs map[string][]byte) (*Validator, error) {
	if len(docs) == 0 {
		return nil, errors.New("gatewaylog: validator: no schemas provided")
	}
	env, ok := docs[schemaEnvelopeID]
	if !ok {
		return nil, fmt.Errorf("gatewaylog: validator: missing envelope schema %s", schemaEnvelopeID)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	for uri, raw := range docs {
		if err := compiler.AddResource(uri, bytes.NewReader(raw)); err != nil {
			return nil, fmt.Errorf("gatewaylog: validator: add resource %s: %w", uri, err)
		}
	}
	// AddResource + Compile keeps the envelope's absolute $ref chain
	// working even when the files aren't co-located on disk (tests
	// pass in memory, releases may ship embedded).
	_ = env
	sch, err := compiler.Compile(schemaEnvelopeID)
	if err != nil {
		return nil, fmt.Errorf("gatewaylog: validator: compile envelope: %w", err)
	}
	return &Validator{schema: sch}, nil
}

// Validate marshals the event to JSON and checks it against the
// envelope schema. A nil Validator is a no-op so the Writer can
// embed an optional reference safely.
func (v *Validator) Validate(e Event) error {
	if v == nil || v.schema == nil {
		return nil
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return &ValidationError{
			EventType: e.EventType,
			Message:   "marshal event: " + err.Error(),
			Cause:     err,
		}
	}
	return v.validateBytes(raw, e.EventType)
}

// ValidateBytes validates a raw JSONL line against the envelope
// schema. Used by the `doctor schemas` debug path where the line was
// read from disk and we don't want to round-trip through the Event
// struct.
func (v *Validator) ValidateBytes(raw []byte) error {
	if v == nil || v.schema == nil {
		return nil
	}
	return v.validateBytes(raw, "")
}

func (v *Validator) validateBytes(raw []byte, eventType EventType) error {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return &ValidationError{
			EventType: eventType,
			Message:   "decode event JSON: " + err.Error(),
			Cause:     err,
		}
	}
	if err := v.schema.Validate(doc); err != nil {
		return &ValidationError{
			EventType: eventType,
			Message:   firstValidationMessage(err),
			Cause:     err,
		}
	}
	return nil
}

// firstValidationMessage extracts an operator-friendly one-line
// summary from a jsonschema.ValidationError tree. The library's
// default rendering is tree-shaped and multi-line, which is great
// for humans debugging a schema but noisy in stderr + structured
// EventError payloads. We pull the deepest leaf (the most specific
// violation) and strip the leading pointer prefix.
func firstValidationMessage(err error) string {
	var verr *jsonschema.ValidationError
	if !errors.As(err, &verr) {
		return err.Error()
	}
	leaf := deepestLeaf(verr)
	buf := &bytes.Buffer{}
	if leaf.InstanceLocation != "" {
		fmt.Fprintf(buf, "%s: ", leaf.InstanceLocation)
	}
	msg := strings.TrimSpace(leaf.Message)
	if msg == "" {
		msg = "schema validation failed"
	}
	buf.WriteString(msg)
	// Cap length so the EventError payload does not balloon on a
	// big oneOf failure.
	out := buf.String()
	const cap = 512
	if len(out) > cap {
		out = out[:cap] + "…"
	}
	return out
}

// deepestLeaf walks the Causes tree and returns the most specific
// violation. Mirrors jsonschema.ValidationError.LeafError but the
// library does not export a public walker on v5.
func deepestLeaf(v *jsonschema.ValidationError) *jsonschema.ValidationError {
	for len(v.Causes) > 0 {
		v = v.Causes[0]
	}
	return v
}

// ReadAllFallback is a small helper used by embed-based constructors
// that may ship a *schema package in a future build. Kept here so
// tests can exercise the io.Reader path without pulling in embed
// just for the tests.
func ReadAllFallback(r io.Reader) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	return io.ReadAll(r)
}
