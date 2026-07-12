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
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
)

func TestConfigV8SchemaClassifiesEveryTopLevelGoConfigField(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal(publicschemas.DefenseClawConfigV8Schema(), &schema); err != nil {
		t.Fatal(err)
	}
	properties := schema["properties"].(map[string]any)
	intentionallyMigrated := map[string]struct{}{
		"audit_db": {}, "judge_bodies_db": {}, "otel": {}, "audit_sinks": {},
	}
	typeOfConfig := reflect.TypeOf(Config{})
	for index := 0; index < typeOfConfig.NumField(); index++ {
		field := typeOfConfig.Field(index)
		name := strings.Split(field.Tag.Get("yaml"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		if _, migrated := intentionallyMigrated[name]; migrated {
			if _, accepted := properties[name]; accepted {
				t.Errorf("migrated v7 top-level field %q remains accepted by v8 schema", name)
			}
			continue
		}
		if _, accepted := properties[name]; !accepted {
			t.Errorf("current top-level Go config field %q is neither accepted nor classified as migrated", name)
		}
	}
}

func TestConfigV8SchemaAcceptsManagedRuntimeFields(t *testing.T) {
	raw := []byte(`config_version: 8
cloud_auth:
  mode: cmid
  lib_path: /opt/defenseclaw/lib/cloud-auth.dylib
managed:
  socket_path: /var/run/defenseclaw/defenseclaw.sock
  socket_mode: "0660"
  allowed_team_ids:
    - DE8Y96K9QP
  allowed_signing_ids:
    - com.cisco.secureclient.gui
  allowed_bundle_ids:
    - com.cisco.secureclient.gui
`)
	if _, err := ParseV8YAML("managed-v8.yaml", raw); err != nil {
		t.Fatalf("ParseV8YAML rejected current managed runtime fields: %v", err)
	}
}

func TestObservabilityV8SemanticProfileLockRejectsCapabilityAndRelationalDrift(t *testing.T) {
	profiles := publicschemas.TelemetryV8Registry()
	lock := publicschemas.TelemetryV8SemconvLock()
	if err := validateObservabilityV8SemanticLockDocuments(profiles, lock); err != nil {
		t.Fatalf("embedded semantic lock is inconsistent: %v", err)
	}
	driftedProfile := bytes.Replace(profiles, []byte("galileo-rich-v2"), []byte("galileo-rich-v3"), 1)
	if _, err := resolveObservabilityV8SemanticLockDocuments(driftedProfile, lock); err == nil ||
		!strings.Contains(err.Error(), "unsupported by compiled runtime capabilities") {
		t.Fatalf("Galileo capability drift error = %v", err)
	}
	driftedLock := bytes.Replace(lock, []byte("b028dceecdad117461a785c3af35315e7184e813"), []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 1)
	if err := validateObservabilityV8SemanticLockDocuments(profiles, driftedLock); err == nil {
		t.Fatal("semantic convention lock drift was accepted")
	}
}

func TestConfigV8SchemaMatchesTypedObservabilitySourceFields(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal(publicschemas.DefenseClawConfigV8Schema(), &schema); err != nil {
		t.Fatal(err)
	}
	definitions := schema["$defs"].(map[string]any)
	observabilitySchema := definitions["observability"].(map[string]any)
	properties := observabilitySchema["properties"].(map[string]any)
	typeOfSource := reflect.TypeOf(ObservabilityV8Source{})
	seen := make(map[string]struct{}, typeOfSource.NumField())
	for index := 0; index < typeOfSource.NumField(); index++ {
		name := strings.Split(typeOfSource.Field(index).Tag.Get("yaml"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		seen[name] = struct{}{}
		if _, ok := properties[name]; !ok {
			t.Errorf("typed observability source field %q is absent from canonical schema", name)
		}
	}
	for name := range properties {
		if _, ok := seen[name]; !ok {
			t.Errorf("canonical observability schema field %q is dropped by typed decoding", name)
		}
	}
}

func TestConfigV8SchemaRetentionMaximumMatchesCompiler(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal(publicschemas.DefenseClawConfigV8Schema(), &schema); err != nil {
		t.Fatal(err)
	}
	definitions := schema["$defs"].(map[string]any)
	localStore := definitions["localStore"].(map[string]any)
	properties := localStore["properties"].(map[string]any)
	retentionDays := properties["retention_days"].(map[string]any)
	got, ok := retentionDays["maximum"].(float64)
	if !ok || got != float64(ObservabilityV8MaxRetentionDays) {
		t.Fatalf("observability.local.retention_days maximum = %v, want %d", retentionDays["maximum"], ObservabilityV8MaxRetentionDays)
	}
}
