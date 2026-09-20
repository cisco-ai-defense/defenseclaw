// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
	"gopkg.in/yaml.v3"
)

var (
	observabilityV8SemanticLockOnce sync.Once
	observabilityV8SemanticLock     ObservabilityV8SemanticProfileLock
	observabilityV8SemanticLockErr  error
)

type observabilityV8SemanticProfilesDocument struct {
	SchemaVersion    int                                   `yaml:"schema_version"`
	SemanticProfiles []observabilityV8SemanticProfileEntry `yaml:"semantic_profiles"`
}

type observabilityV8SemanticProfileEntry struct {
	ID                          string `yaml:"id"`
	TraceSchemaVersion          string `yaml:"trace_schema_version"`
	GenAISemconvProfile         string `yaml:"gen_ai_semconv_profile"`
	OpenInferenceProfile        string `yaml:"openinference_profile"`
	GalileoCompatibilityProfile string `yaml:"galileo_compatibility_profile"`
}

type observabilityV8SemconvLockDocument struct {
	SchemaVersion int                                    `yaml:"schema_version"`
	Dependencies  []observabilityV8SemconvLockDependency `yaml:"dependencies"`
}

type observabilityV8SemconvLockDependency struct {
	ID               string                                      `yaml:"id"`
	Repository       string                                      `yaml:"repository"`
	Version          string                                      `yaml:"version"`
	ProfileID        string                                      `yaml:"profile_id"`
	Revision         string                                      `yaml:"revision"`
	Snapshot         observabilityV8SemconvLockSnapshot          `yaml:"snapshot"`
	StructuralInputs []observabilityV8SemconvLockStructuralInput `yaml:"structural_inputs,omitempty"`
}

type observabilityV8SemconvLockSnapshot struct {
	Path   string `yaml:"path"`
	Format string `yaml:"format"`
	SHA256 string `yaml:"sha256"`
}

type observabilityV8SemconvLockStructuralInput struct {
	UpstreamPath string `yaml:"upstream_path"`
	Path         string `yaml:"path"`
	SHA256       string `yaml:"sha256"`
}

func resolveObservabilityV8SemanticLock() (ObservabilityV8SemanticProfileLock, error) {
	observabilityV8SemanticLockOnce.Do(func() {
		observabilityV8SemanticLock, observabilityV8SemanticLockErr = resolveObservabilityV8SemanticLockDocuments(
			publicschemas.TelemetryV8Registry(),
			publicschemas.TelemetryV8SemconvLock(),
		)
	})
	return observabilityV8SemanticLock, observabilityV8SemanticLockErr
}

func validateObservabilityV8SemanticLockDocuments(profileBytes, lockBytes []byte) error {
	_, err := resolveObservabilityV8SemanticLockDocuments(profileBytes, lockBytes)
	return err
}

func resolveObservabilityV8SemanticLockDocuments(
	profileBytes, lockBytes []byte,
) (ObservabilityV8SemanticProfileLock, error) {
	selected, err := parseObservabilityV8SemanticProfile(profileBytes)
	if err != nil {
		return ObservabilityV8SemanticProfileLock{}, err
	}
	var lock observabilityV8SemconvLockDocument
	decoder := yaml.NewDecoder(bytes.NewReader(lockBytes))
	decoder.KnownFields(true)
	if err := decoder.Decode(&lock); err != nil {
		return ObservabilityV8SemanticProfileLock{}, fmt.Errorf("decode embedded semantic convention lock: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return ObservabilityV8SemanticProfileLock{}, fmt.Errorf("decode embedded semantic convention lock: %w", err)
		}
		return ObservabilityV8SemanticProfileLock{}, fmt.Errorf("decode embedded semantic convention lock: multiple YAML documents")
	}
	if lock.SchemaVersion != 1 {
		return ObservabilityV8SemanticProfileLock{}, fmt.Errorf("semantic registry/lock schema version mismatch")
	}
	registered := ObservabilityV8SemanticProfileLock{
		TraceSchemaVersion:          selected.TraceSchemaVersion,
		GenAISemconvProfile:         selected.GenAISemconvProfile,
		OpenInferenceProfile:        selected.OpenInferenceProfile,
		GalileoCompatibilityProfile: selected.GalileoCompatibilityProfile,
	}
	dependencies, err := validateObservabilityV8SemconvDependencies(lock.Dependencies)
	if err != nil {
		return ObservabilityV8SemanticProfileLock{}, err
	}
	// Runtime validation derives instrumentation compatibility from the two
	// embedded authorities. Repository and snapshot provenance remain
	// authoritative in semconv.lock.yaml and are integrity-checked by the registry
	// compiler; no external Go module version or copied revision is evidence here.
	core := dependencies["otel_core"]
	genAI := dependencies["otel_genai"]
	openInference := dependencies["openinference"]
	if core.ProfileID != "otel-semconv-"+core.Version ||
		registered.GenAISemconvProfile != genAI.ProfileID ||
		!strings.HasPrefix(registered.GenAISemconvProfile, "otel-genai-") ||
		genAI.Version != genAI.Revision ||
		genAI.Revision != strings.TrimPrefix(registered.GenAISemconvProfile, "otel-genai-") ||
		registered.OpenInferenceProfile != openInference.ProfileID ||
		registered.OpenInferenceProfile != "openinference-semantic-conventions-v"+openInference.Version {
		return ObservabilityV8SemanticProfileLock{}, fmt.Errorf("semantic profile members disagree with semconv.lock.yaml")
	}
	if selected.ID != observability.RuntimeSemanticProfileID ||
		registered.TraceSchemaVersion != observability.RuntimeTraceSchemaVersion ||
		registered.GenAISemconvProfile != observability.RuntimeGenAISemconvProfile ||
		registered.OpenInferenceProfile != observability.RuntimeOpenInferenceProfile ||
		registered.GalileoCompatibilityProfile != observability.RuntimeGalileoCompatibilityProfile {
		return ObservabilityV8SemanticProfileLock{}, fmt.Errorf(
			"semantic profile %s is unsupported by compiled runtime capabilities",
			selected.ID,
		)
	}
	return registered, nil
}

func parseObservabilityV8SemanticProfile(profileBytes []byte) (observabilityV8SemanticProfileEntry, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(profileBytes))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return observabilityV8SemanticProfileEntry{}, fmt.Errorf("decode embedded semantic profiles: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return observabilityV8SemanticProfileEntry{}, fmt.Errorf("decode embedded semantic profiles: %w", err)
		}
		return observabilityV8SemanticProfileEntry{}, fmt.Errorf("decode embedded semantic profiles: multiple YAML documents")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return observabilityV8SemanticProfileEntry{}, fmt.Errorf("decode embedded semantic profiles: registry root must be a mapping")
	}
	root := document.Content[0]
	var schemaVersion int
	hasSchemaVersion := false
	var profileNodes *yaml.Node
	seenRootKeys := make(map[string]struct{}, len(root.Content)/2)
	for index := 0; index < len(root.Content); index += 2 {
		key := root.Content[index].Value
		if _, duplicate := seenRootKeys[key]; duplicate {
			return observabilityV8SemanticProfileEntry{}, fmt.Errorf("decode embedded semantic profiles: duplicate registry key %q", key)
		}
		seenRootKeys[key] = struct{}{}
		value := root.Content[index+1]
		switch key {
		case "schema_version":
			if err := value.Decode(&schemaVersion); err != nil {
				return observabilityV8SemanticProfileEntry{}, fmt.Errorf("decode embedded semantic profiles: schema_version: %w", err)
			}
			hasSchemaVersion = true
		case "semantic_profiles":
			profileNodes = value
		}
	}
	if !hasSchemaVersion || schemaVersion != 1 {
		return observabilityV8SemanticProfileEntry{}, fmt.Errorf("semantic registry/lock schema version mismatch")
	}
	if profileNodes == nil || profileNodes.Kind != yaml.SequenceNode {
		return observabilityV8SemanticProfileEntry{}, fmt.Errorf("semantic profiles must be a sequence")
	}
	expectedKeys := map[string]struct{}{
		"id":                            {},
		"trace_schema_version":          {},
		"gen_ai_semconv_profile":        {},
		"openinference_profile":         {},
		"galileo_compatibility_profile": {},
	}
	var selected observabilityV8SemanticProfileEntry
	selectedCount := 0
	for index, profileNode := range profileNodes.Content {
		if profileNode.Kind != yaml.MappingNode {
			return observabilityV8SemanticProfileEntry{}, fmt.Errorf("semantic profile %d must be a mapping", index)
		}
		fields := make(map[string]*yaml.Node, len(profileNode.Content)/2)
		for fieldIndex := 0; fieldIndex < len(profileNode.Content); fieldIndex += 2 {
			key := profileNode.Content[fieldIndex].Value
			if _, duplicate := fields[key]; duplicate {
				return observabilityV8SemanticProfileEntry{}, fmt.Errorf("semantic profile %d has duplicate member %q", index, key)
			}
			fields[key] = profileNode.Content[fieldIndex+1]
		}
		idNode := fields["id"]
		if idNode == nil || idNode.Value != observabilityV8DefaultSemanticProfile {
			continue
		}
		selectedCount++
		for key := range fields {
			if _, known := expectedKeys[key]; !known {
				return observabilityV8SemanticProfileEntry{}, fmt.Errorf(
					"semantic profile %s has unknown member %q",
					observabilityV8DefaultSemanticProfile,
					key,
				)
			}
		}
		for key := range expectedKeys {
			if fields[key] == nil {
				return observabilityV8SemanticProfileEntry{}, fmt.Errorf(
					"semantic profile %s is missing member %q",
					observabilityV8DefaultSemanticProfile,
					key,
				)
			}
		}
		if err := profileNode.Decode(&selected); err != nil {
			return observabilityV8SemanticProfileEntry{}, fmt.Errorf("decode selected semantic profile: %w", err)
		}
		if selected.TraceSchemaVersion == "" || selected.GenAISemconvProfile == "" ||
			selected.OpenInferenceProfile == "" || selected.GalileoCompatibilityProfile == "" {
			return observabilityV8SemanticProfileEntry{}, fmt.Errorf(
				"semantic profile %s has an empty member",
				observabilityV8DefaultSemanticProfile,
			)
		}
	}
	if selectedCount == 0 {
		if len(profileNodes.Content) == 1 {
			profileNode := profileNodes.Content[0]
			if profileNode.Kind == yaml.MappingNode {
				for fieldIndex := 0; fieldIndex < len(profileNode.Content); fieldIndex += 2 {
					if profileNode.Content[fieldIndex].Value == "id" {
						unsupportedID := profileNode.Content[fieldIndex+1].Value
						if unsupportedID != "" {
							return observabilityV8SemanticProfileEntry{}, fmt.Errorf(
								"semantic profile %s is unsupported by compiled runtime capabilities",
								unsupportedID,
							)
						}
					}
				}
			}
		}
		return observabilityV8SemanticProfileEntry{}, fmt.Errorf(
			"semantic profile %s is absent from the embedded registry",
			observabilityV8DefaultSemanticProfile,
		)
	}
	if selectedCount != 1 {
		return observabilityV8SemanticProfileEntry{}, fmt.Errorf(
			"semantic profile %s is duplicated in the embedded registry",
			observabilityV8DefaultSemanticProfile,
		)
	}
	return selected, nil
}

func validateObservabilityV8SemconvDependencies(
	dependencies []observabilityV8SemconvLockDependency,
) (map[string]observabilityV8SemconvLockDependency, error) {
	expected := map[string]struct{}{
		"otel_core":     {},
		"otel_genai":    {},
		"openinference": {},
	}
	observed := make(map[string]observabilityV8SemconvLockDependency, len(dependencies))
	for index, dependency := range dependencies {
		if dependency.ID == "" {
			return nil, fmt.Errorf("semantic convention dependency %d is missing id", index)
		}
		_, known := expected[dependency.ID]
		if !known {
			return nil, fmt.Errorf("semantic convention dependency %q is unknown", dependency.ID)
		}
		if _, duplicate := observed[dependency.ID]; duplicate {
			return nil, fmt.Errorf("semantic convention dependency %q is duplicated", dependency.ID)
		}
		if dependency.Repository == "" || dependency.Version == "" || dependency.ProfileID == "" ||
			dependency.Revision == "" || dependency.Snapshot.Path == "" ||
			dependency.Snapshot.Format == "" || dependency.Snapshot.SHA256 == "" {
			return nil, fmt.Errorf("semantic convention dependency %q is incomplete", dependency.ID)
		}
		if err := validateObservabilityV8StructuralInputs(dependency); err != nil {
			return nil, err
		}
		observed[dependency.ID] = dependency
	}
	for id := range expected {
		if _, exists := observed[id]; !exists {
			return nil, fmt.Errorf("semantic convention dependency %q is missing", id)
		}
	}
	return observed, nil
}

func validateObservabilityV8StructuralInputs(dependency observabilityV8SemconvLockDependency) error {
	if dependency.ID != "otel_genai" {
		if len(dependency.StructuralInputs) != 0 {
			return fmt.Errorf(
				"semantic convention dependency %q must not declare structural inputs",
				dependency.ID,
			)
		}
		return nil
	}
	if len(dependency.StructuralInputs) == 0 {
		return fmt.Errorf("semantic convention dependency %q is missing structural inputs", dependency.ID)
	}
	upstreamPaths := make(map[string]struct{}, len(dependency.StructuralInputs))
	repositoryPaths := make(map[string]struct{}, len(dependency.StructuralInputs))
	for index, input := range dependency.StructuralInputs {
		if input.UpstreamPath == "" || input.Path == "" || input.SHA256 == "" {
			return fmt.Errorf(
				"semantic convention dependency %q structural input %d is incomplete",
				dependency.ID,
				index,
			)
		}
		if _, duplicate := upstreamPaths[input.UpstreamPath]; duplicate {
			return fmt.Errorf(
				"semantic convention dependency %q structural input upstream path %q is duplicated",
				dependency.ID,
				input.UpstreamPath,
			)
		}
		if _, duplicate := repositoryPaths[input.Path]; duplicate {
			return fmt.Errorf(
				"semantic convention dependency %q structural input path %q is duplicated",
				dependency.ID,
				input.Path,
			)
		}
		upstreamPaths[input.UpstreamPath] = struct{}{}
		repositoryPaths[input.Path] = struct{}{}
	}
	return nil
}
