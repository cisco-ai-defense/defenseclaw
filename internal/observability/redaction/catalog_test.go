// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

type catalogManifest struct {
	CatalogVersion int `yaml:"catalog_version" json:"catalog_version"`
	Groups         []struct {
		Token       DetectorGroup `yaml:"token" json:"token"`
		DetectorIDs []DetectorID  `yaml:"detector_ids" json:"detector_ids"`
	} `yaml:"groups" json:"groups"`
	Detectors []struct {
		Order               int           `yaml:"order" json:"order"`
		Group               DetectorGroup `yaml:"group" json:"group"`
		ID                  DetectorID    `yaml:"id" json:"id"`
		LexicalGrammar      string        `yaml:"lexical_grammar" json:"lexical_grammar"`
		SemanticValidator   string        `yaml:"semantic_validator" json:"semantic_validator"`
		InputContext        string        `yaml:"input_context" json:"input_context"`
		CandidateBound      int           `yaml:"candidate_bound" json:"candidate_bound"`
		ReplacementInterval string        `yaml:"replacement_interval" json:"replacement_interval"`
		FixtureSet          string        `yaml:"fixture_set" json:"fixture_set"`
	} `yaml:"detectors" json:"detectors"`
}

func TestDetectorCatalogManifestSchemaOrderAndGeneratedDrift(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..")
	manifestPath := filepath.Join(root, "schemas", "telemetry", "v8", "redaction", "detector-catalog-v1.yaml")
	schemaPath := filepath.Join(root, "schemas", "telemetry", "v8", "redaction", "detector-catalog.schema.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}

	var generic any
	if err := yaml.Unmarshal(manifestBytes, &generic); err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	var document any
	if err := json.Unmarshal(manifestJSON, &document); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("memory://detector-catalog.schema.json", bytes.NewReader(schemaBytes)); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("memory://detector-catalog.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(document); err != nil {
		t.Fatalf("manifest schema: %v", err)
	}

	var manifest catalogManifest
	decoder := yaml.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.KnownFields(true)
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.CatalogVersion != DetectorCatalogVersion() || len(manifest.Detectors) != 14 {
		t.Fatal("catalog version or detector count drift")
	}
	wantGroups := []DetectorGroup{DetectorGroupCredentials, DetectorGroupSecrets, DetectorGroupPII}
	if got := DetectorGroups(); !reflect.DeepEqual(got, wantGroups) {
		t.Fatalf("group order: got %v, want %v", got, wantGroups)
	}
	entries := DetectorCatalog()
	for index, manifestEntry := range manifest.Detectors {
		entry := entries[index]
		if entry.Order != index+1 || entry.Order != manifestEntry.Order || entry.Group != manifestEntry.Group ||
			entry.ID != manifestEntry.ID || entry.LexicalGrammar != manifestEntry.LexicalGrammar ||
			entry.SemanticValidator != manifestEntry.SemanticValidator || entry.InputContext != manifestEntry.InputContext ||
			entry.CandidateBound != manifestEntry.CandidateBound || entry.ReplacementInterval != manifestEntry.ReplacementInterval ||
			entry.FixtureSet != manifestEntry.FixtureSet {
			t.Fatalf("generated catalog drift at index %d: got %+v, manifest %+v", index, entry, manifestEntry)
		}
	}
	for index, group := range manifest.Groups {
		if group.Token != wantGroups[index] {
			t.Fatalf("manifest group order %d: %q", index, group.Token)
		}
		members, ok := DetectorsForGroup(group.Token)
		if !ok || !reflect.DeepEqual(members, group.DetectorIDs) {
			t.Fatalf("group membership drift for %q: got %v, want %v", group.Token, members, group.DetectorIDs)
		}
	}
}

func TestDetectorCatalogAccessorsReturnCopies(t *testing.T) {
	t.Parallel()
	entries := DetectorCatalog()
	entries[0].ID = "changed"
	if DetectorCatalog()[0].ID != "credentials.api_token" {
		t.Fatal("caller mutated catalog")
	}
	members, _ := DetectorsForGroup(DetectorGroupCredentials)
	members[0] = "changed"
	again, _ := DetectorsForGroup(DetectorGroupCredentials)
	if again[0] != "credentials.api_token" {
		t.Fatal("caller mutated group membership")
	}
}
