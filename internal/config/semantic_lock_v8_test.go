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
	"strings"
	"testing"

	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
	"gopkg.in/yaml.v3"
)

func TestObservabilityV8SemanticLockDependencyCatalog(t *testing.T) {
	profiles := publicschemas.TelemetryV8Registry()
	lockBytes := publicschemas.TelemetryV8SemconvLock()
	if err := validateObservabilityV8SemanticLockDocuments(profiles, lockBytes); err != nil {
		t.Fatalf("canonical dependency lock rejected: %v", err)
	}

	var canonical observabilityV8SemconvLockDocument
	if err := yaml.Unmarshal(lockBytes, &canonical); err != nil {
		t.Fatal(err)
	}
	if len(canonical.Dependencies) != 3 {
		t.Fatalf("canonical dependency count = %d", len(canonical.Dependencies))
	}
	if got := len(canonical.Dependencies[1].StructuralInputs); got != 4 {
		t.Fatalf("canonical GenAI structural input count = %d, want 4", got)
	}
	if len(canonical.Dependencies[0].StructuralInputs) != 0 ||
		len(canonical.Dependencies[2].StructuralInputs) != 0 {
		t.Fatal("non-GenAI dependency unexpectedly declares structural inputs")
	}

	tests := []struct {
		name    string
		mutate  func(*observabilityV8SemconvLockDocument)
		message string
	}{
		{
			name: "missing dependency",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies = lock.Dependencies[:len(lock.Dependencies)-1]
			},
			message: "is missing",
		},
		{
			name: "duplicate dependency",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies = append(lock.Dependencies, lock.Dependencies[0])
			},
			message: "is duplicated",
		},
		{
			name: "unknown dependency",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies[0].ID = "unknown_semconv"
			},
			message: "is unknown",
		},
		{
			name: "missing dependency id",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies[0].ID = ""
			},
			message: "is missing id",
		},
		{
			name: "incomplete dependency profile id",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies[1].ProfileID = ""
			},
			message: "is incomplete",
		},
		{
			name: "core version drift",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies[0].Version = "v1.43.0"
			},
			message: "semantic profile members disagree",
		},
		{
			name: "core profile id drift",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies[0].ProfileID = "otel-semconv-v1.43.0"
			},
			message: "semantic profile members disagree",
		},
		{
			name: "genai version drift",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies[1].Version = strings.Repeat("a", 40)
			},
			message: "semantic profile members disagree",
		},
		{
			name: "genai profile id drift",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies[1].ProfileID = "otel-genai-drifted"
			},
			message: "semantic profile members disagree",
		},
		{
			name: "genai revision drift",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies[1].Revision = strings.Repeat("a", 40)
			},
			message: "semantic profile members disagree",
		},
		{
			name: "openinference version drift",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies[2].Version = "0.1.31"
			},
			message: "semantic profile members disagree",
		},
		{
			name: "openinference profile id drift",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies[2].ProfileID = "openinference-semantic-conventions-v0.1.31"
			},
			message: "semantic profile members disagree",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneObservabilityV8SemconvLockDocument(t, canonical)
			test.mutate(&candidate)
			candidateBytes, err := yaml.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			err = validateObservabilityV8SemanticLockDocuments(profiles, candidateBytes)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("dependency lock error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestObservabilityV8SemanticLockRequiresCompleteDependencyMetadata(t *testing.T) {
	profiles := publicschemas.TelemetryV8Registry()
	var canonical observabilityV8SemconvLockDocument
	if err := yaml.Unmarshal(publicschemas.TelemetryV8SemconvLock(), &canonical); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*observabilityV8SemconvLockDependency)
	}{
		{name: "repository", mutate: func(value *observabilityV8SemconvLockDependency) { value.Repository = "" }},
		{name: "version", mutate: func(value *observabilityV8SemconvLockDependency) { value.Version = "" }},
		{name: "profile id", mutate: func(value *observabilityV8SemconvLockDependency) { value.ProfileID = "" }},
		{name: "revision", mutate: func(value *observabilityV8SemconvLockDependency) { value.Revision = "" }},
		{name: "snapshot path", mutate: func(value *observabilityV8SemconvLockDependency) { value.Snapshot.Path = "" }},
		{name: "snapshot format", mutate: func(value *observabilityV8SemconvLockDependency) { value.Snapshot.Format = "" }},
		{name: "snapshot digest", mutate: func(value *observabilityV8SemconvLockDependency) { value.Snapshot.SHA256 = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneObservabilityV8SemconvLockDocument(t, canonical)
			test.mutate(&candidate.Dependencies[0])
			candidateBytes, err := yaml.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			err = validateObservabilityV8SemanticLockDocuments(profiles, candidateBytes)
			if err == nil || !strings.Contains(err.Error(), "is incomplete") {
				t.Fatalf("incomplete %s error = %v", test.name, err)
			}
		})
	}
}

func TestObservabilityV8SemanticLockRequiresClosedStructuralInputMetadata(t *testing.T) {
	profiles := publicschemas.TelemetryV8Registry()
	var canonical observabilityV8SemconvLockDocument
	if err := yaml.Unmarshal(publicschemas.TelemetryV8SemconvLock(), &canonical); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		mutate  func(*observabilityV8SemconvLockDocument)
		message string
	}{
		{
			name: "missing GenAI structural inputs",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies[1].StructuralInputs = nil
			},
			message: "is missing structural inputs",
		},
		{
			name: "structural inputs on core dependency",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies[0].StructuralInputs = append(
					[]observabilityV8SemconvLockStructuralInput(nil),
					lock.Dependencies[1].StructuralInputs[0],
				)
			},
			message: "must not declare structural inputs",
		},
		{
			name: "incomplete structural input",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies[1].StructuralInputs[0].SHA256 = ""
			},
			message: "structural input 0 is incomplete",
		},
		{
			name: "duplicate upstream path",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies[1].StructuralInputs[1].UpstreamPath =
					lock.Dependencies[1].StructuralInputs[0].UpstreamPath
			},
			message: "upstream path",
		},
		{
			name: "duplicate repository path",
			mutate: func(lock *observabilityV8SemconvLockDocument) {
				lock.Dependencies[1].StructuralInputs[1].Path =
					lock.Dependencies[1].StructuralInputs[0].Path
			},
			message: "input path",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneObservabilityV8SemconvLockDocument(t, canonical)
			test.mutate(&candidate)
			candidateBytes, err := yaml.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			err = validateObservabilityV8SemanticLockDocuments(profiles, candidateBytes)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("structural input error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestObservabilityV8SemanticLockLeavesSnapshotIntegrityToRegistryCompiler(t *testing.T) {
	profiles := publicschemas.TelemetryV8Registry()
	var candidate observabilityV8SemconvLockDocument
	if err := yaml.Unmarshal(publicschemas.TelemetryV8SemconvLock(), &candidate); err != nil {
		t.Fatal(err)
	}
	for index := range candidate.Dependencies {
		candidate.Dependencies[index].Repository = "https://example.invalid/dependency"
		candidate.Dependencies[index].Snapshot.Path = "schemas/telemetry/v8/upstream/compiler-owned.json"
		candidate.Dependencies[index].Snapshot.Format = "compiler-owned-format"
		candidate.Dependencies[index].Snapshot.SHA256 = strings.Repeat("c", 64)
	}
	candidate.Dependencies[0].Revision = strings.Repeat("a", 40)
	candidate.Dependencies[2].Revision = strings.Repeat("b", 40)
	candidateBytes, err := yaml.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateObservabilityV8SemanticLockDocuments(profiles, candidateBytes); err != nil {
		t.Fatalf("runtime duplicated compiler-owned snapshot provenance pins: %v", err)
	}
}

func TestObservabilityV8SemanticLockRejectsUnknownStructureAndMultipleDocuments(t *testing.T) {
	profiles := publicschemas.TelemetryV8Registry()
	canonical := publicschemas.TelemetryV8SemconvLock()
	tests := []struct {
		name      string
		candidate []byte
		message   string
	}{
		{
			name:      "unknown root field",
			candidate: append(append([]byte(nil), canonical...), []byte("unknown_root: true\n")...),
			message:   "field unknown_root not found",
		},
		{
			name: "unknown dependency field",
			candidate: bytes.Replace(
				canonical,
				[]byte("  repository:"),
				[]byte("  unknown_dependency_field: true\n  repository:"),
				1,
			),
			message: "field unknown_dependency_field not found",
		},
		{
			name: "unknown snapshot field",
			candidate: bytes.Replace(
				canonical,
				[]byte("    sha256:"),
				[]byte("    unknown_snapshot_field: true\n    sha256:"),
				1,
			),
			message: "field unknown_snapshot_field not found",
		},
		{
			name:      "multiple documents",
			candidate: append(append([]byte(nil), canonical...), []byte("---\n{}\n")...),
			message:   "multiple YAML documents",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateObservabilityV8SemanticLockDocuments(profiles, test.candidate)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("closed lock error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestObservabilityV8SemanticRegistrySelectedProfileIsClosedAndSingleDocument(t *testing.T) {
	canonical := publicschemas.TelemetryV8Registry()
	lock := publicschemas.TelemetryV8SemconvLock()
	tests := []struct {
		name      string
		candidate []byte
		message   string
	}{
		{
			name: "unknown selected profile member",
			candidate: bytes.Replace(
				canonical,
				[]byte("  - id: defenseclaw-genai-rich-v1\n"),
				[]byte("  - id: defenseclaw-genai-rich-v1\n    unknown_profile_member: rejected\n"),
				1,
			),
			message: "unknown member",
		},
		{
			name: "missing selected profile member",
			candidate: bytes.Replace(
				canonical,
				[]byte("    trace_schema_version: defenseclaw-trace-v1\n"),
				nil,
				1,
			),
			message: "is missing member",
		},
		{
			name: "empty selected profile member",
			candidate: bytes.Replace(
				canonical,
				[]byte("    trace_schema_version: defenseclaw-trace-v1\n"),
				[]byte("    trace_schema_version: ''\n"),
				1,
			),
			message: "has an empty member",
		},
		{
			name:      "multiple registry documents",
			candidate: append(append([]byte(nil), canonical...), []byte("---\n{}\n")...),
			message:   "multiple YAML documents",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateObservabilityV8SemanticLockDocuments(test.candidate, lock)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("selected-profile error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestObservabilityV8SemanticLockRejectsSameIDCapabilityDrift(t *testing.T) {
	lock := publicschemas.TelemetryV8SemconvLock()
	var profiles observabilityV8SemanticProfilesDocument
	if err := yaml.Unmarshal(publicschemas.TelemetryV8Registry(), &profiles); err != nil {
		t.Fatal(err)
	}
	if len(profiles.SemanticProfiles) != 1 {
		t.Fatalf("semantic profile count = %d", len(profiles.SemanticProfiles))
	}
	tests := []struct {
		name    string
		mutate  func(*observabilityV8SemanticProfileEntry)
		message string
	}{
		{
			name: "trace schema",
			mutate: func(profile *observabilityV8SemanticProfileEntry) {
				profile.TraceSchemaVersion = "defenseclaw-trace-v2"
			},
			message: "unsupported by compiled runtime capabilities",
		},
		{
			name: "GenAI semantic convention",
			mutate: func(profile *observabilityV8SemanticProfileEntry) {
				profile.GenAISemconvProfile = "otel-genai-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			},
			message: "members disagree with semconv.lock.yaml",
		},
		{
			name: "OpenInference",
			mutate: func(profile *observabilityV8SemanticProfileEntry) {
				profile.OpenInferenceProfile = "openinference-semantic-conventions-v0.1.31"
			},
			message: "members disagree with semconv.lock.yaml",
		},
		{
			name: "galileo",
			mutate: func(profile *observabilityV8SemanticProfileEntry) {
				profile.GalileoCompatibilityProfile = "galileo-rich-v3"
			},
			message: "unsupported by compiled runtime capabilities",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := profiles
			candidate.SemanticProfiles = append([]observabilityV8SemanticProfileEntry(nil), profiles.SemanticProfiles...)
			test.mutate(&candidate.SemanticProfiles[0])
			profileBytes, err := yaml.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolveObservabilityV8SemanticLockDocuments(profileBytes, lock); err == nil ||
				!strings.Contains(err.Error(), test.message) {
				t.Fatalf("same-ID capability drift error = %v", err)
			}
		})
	}

	duplicate := profiles
	duplicate.SemanticProfiles = append(
		append([]observabilityV8SemanticProfileEntry(nil), profiles.SemanticProfiles...),
		profiles.SemanticProfiles[0],
	)
	profileBytes, err := yaml.Marshal(duplicate)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateObservabilityV8SemanticLockDocuments(profileBytes, lock); err == nil ||
		!strings.Contains(err.Error(), "is duplicated") {
		t.Fatalf("duplicate profile error = %v", err)
	}
}

func TestObservabilityV8SemanticLockRequiresNewSupportedIDForRelationalTupleUpdate(t *testing.T) {
	var profiles observabilityV8SemanticProfilesDocument
	if err := yaml.Unmarshal(publicschemas.TelemetryV8Registry(), &profiles); err != nil {
		t.Fatal(err)
	}
	var lock observabilityV8SemconvLockDocument
	if err := yaml.Unmarshal(publicschemas.TelemetryV8SemconvLock(), &lock); err != nil {
		t.Fatal(err)
	}
	genAIRevision := strings.Repeat("d", 40)
	profiles.SemanticProfiles[0].GenAISemconvProfile = genAIRevision
	lock.Dependencies[1].Version = genAIRevision
	lock.Dependencies[1].ProfileID = genAIRevision
	lock.Dependencies[1].Revision = genAIRevision
	profileBytes, err := yaml.Marshal(profiles)
	if err != nil {
		t.Fatal(err)
	}
	lockBytes, err := yaml.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolveObservabilityV8SemanticLockDocuments(profileBytes, lockBytes); err == nil ||
		!strings.Contains(err.Error(), "members disagree with semconv.lock.yaml") {
		t.Fatalf("missing otel-genai- prefix error = %v", err)
	}

	profiles.SemanticProfiles[0].GenAISemconvProfile = "otel-genai-" + genAIRevision
	lock.Dependencies[1].ProfileID = "otel-genai-" + genAIRevision
	profiles.SemanticProfiles[0].OpenInferenceProfile = "openinference-semantic-conventions-v0.1.31"
	lock.Dependencies[2].Version = "0.1.31"
	lock.Dependencies[2].ProfileID = "openinference-semantic-conventions-v0.1.31"
	profileBytes, err = yaml.Marshal(profiles)
	if err != nil {
		t.Fatal(err)
	}
	lockBytes, err = yaml.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolveObservabilityV8SemanticLockDocuments(profileBytes, lockBytes); err == nil ||
		!strings.Contains(err.Error(), "unsupported by compiled runtime capabilities") {
		t.Fatalf("same-ID relational tuple drift error = %v", err)
	}

	profiles.SemanticProfiles[0].ID = "defenseclaw-genai-rich-v2"
	profileBytes, err = yaml.Marshal(profiles)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolveObservabilityV8SemanticLockDocuments(profileBytes, lockBytes); err == nil ||
		!strings.Contains(err.Error(), "semantic profile defenseclaw-genai-rich-v2 is unsupported") {
		t.Fatalf("new unsupported profile ID error = %v", err)
	}
}

func cloneObservabilityV8SemconvLockDocument(
	t *testing.T,
	input observabilityV8SemconvLockDocument,
) observabilityV8SemconvLockDocument {
	t.Helper()
	encoded, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var clone observabilityV8SemconvLockDocument
	if err := yaml.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}
