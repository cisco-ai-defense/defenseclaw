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
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
)

func TestV9SchemaErrorDoesNotPointToV8(t *testing.T) {
	err := ValidateV8SchemaBytes("admin.yaml", []byte("config_version: 9\nguardrail:\n  mode: ACTION\n"))
	var schemaErr *V8SchemaError
	if !errors.As(err, &schemaErr) || schemaErr.Version != 9 ||
		strings.Contains(err.Error(), "v8") || !strings.Contains(err.Error(), "config_version 9") {
		t.Fatalf("v9 schema error = %v", err)
	}
}

// GAP-0940: an http_jsonl destination with bearer_env and bearer_credential
// is reported as those two fields, not as the kind of another destination
// type ("kind must be the literal jsonl").
func TestV8SchemaNamesFieldsThatExcludeEachOther(t *testing.T) {
	err := ValidateV8SchemaBytes("admin.yaml", []byte("config_version: 9\nobservability:\n  destinations:\n"+
		"    - name: eo3-http\n      kind: http_jsonl\n      endpoint: https://collector.example.test/ingest\n"+
		"      bearer_credential: eo3-http-token\n      bearer_env: EO3_REF\n"))
	var schemaErr *V8SchemaError
	if !errors.As(err, &schemaErr) || schemaErr.Keyword != "not" || schemaErr.Path != "$.observability.destinations[0]" ||
		schemaErr.Expected != "either bearer_env or bearer_credential, not both" {
		t.Fatalf("both credential fields = %v (%+v)", err, schemaErr)
	}
}

// GAP-0760 (#1099): severity_overrides takes the rule severities block_at
// takes, in any case. INFO, which no rule can have, passed the schema and was
// then refused by the rule composer; the schema now refuses it and names the
// words it takes, as it does for block_at.
func TestV8SchemaRuleSeverityOverrideWords(t *testing.T) {
	override := func(value string) []byte {
		return []byte("config_version: 9\nguardrail:\n  rules:\n    severity_overrides: {SEC-AWS-SECRET: " + value + "}\n")
	}
	for _, value := range []string{"CRITICAL", "high", "Medium", "low"} {
		if err := ValidateV8SchemaBytes("admin.yaml", override(value)); err != nil {
			t.Errorf("severity_overrides %s refused: %v", value, err)
		}
	}
	for _, value := range []string{"INFO", "info", "severe"} {
		err := ValidateV8SchemaBytes("admin.yaml", override(value))
		var schemaErr *V8SchemaError
		if !errors.As(err, &schemaErr) || schemaErr.Keyword != "pattern" ||
			schemaErr.Expected != "one of CRITICAL, HIGH, MEDIUM, LOW in any case" {
			t.Errorf("severity_overrides %s = %v (%+v)", value, err, schemaErr)
		}
	}
	err := ValidateV8SchemaBytes("admin.yaml", []byte("config_version: 9\nguardrail:\n  block_at: severe\n"))
	var schemaErr *V8SchemaError
	if !errors.As(err, &schemaErr) || schemaErr.Expected != "one of CRITICAL, HIGH, MEDIUM, LOW in any case (empty inherits)" {
		t.Errorf("block_at severe = %v (%+v)", err, schemaErr)
	}
}

// GAP-0760 (#1099): hilt.min_severity follows the same case rule as block_at
// and severity_overrides. The Go and Python validators and every gateway
// reader already took any case; only the schema refused lower case.
func TestV8SchemaHILTMinSeverityTakesAnyCase(t *testing.T) {
	hilt := func(value string) []byte {
		return []byte("config_version: 9\nguardrail:\n  hilt: {enabled: true, min_severity: \"" + value + "\"}\n" +
			"  connectors:\n    codex:\n      hilt: {enabled: true, min_severity: \"" + value + "\"}\n")
	}
	for _, value := range []string{"", "CRITICAL", "high", "Medium", "low"} {
		if err := ValidateV8SchemaBytes("admin.yaml", hilt(value)); err != nil {
			t.Errorf("hilt.min_severity %q refused: %v", value, err)
		}
	}
	for _, value := range []string{"INFO", "severe"} {
		err := ValidateV8SchemaBytes("admin.yaml", hilt(value))
		var schemaErr *V8SchemaError
		if !errors.As(err, &schemaErr) || schemaErr.Keyword != "pattern" ||
			schemaErr.Expected != "one of CRITICAL, HIGH, MEDIUM, LOW in any case (empty inherits)" {
			t.Errorf("hilt.min_severity %q = %v (%+v)", value, err, schemaErr)
		}
	}
}

func TestV8SchemaPatternWords(t *testing.T) {
	for pattern, want := range map[string]string{
		"^([Ll][Oo][Ww]|[Hh][Ii][Gg][Hh])$": "one of LOW, HIGH in any case",
		"^(|observe|action)$":               "one of observe, action (empty inherits)",
		"^[a-z0-9][a-z0-9_-]{0,63}$":        "",
		"^agt-[0-9a-f]{16}$":                "",
		"^(a.b|c)$":                         "",
	} {
		if got := v8SchemaPatternWords(pattern); got != want {
			t.Errorf("v8SchemaPatternWords(%q) = %q, want %q", pattern, got, want)
		}
	}
}

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

// A 0.8.x config still carries claw.openclaw_home_original (0.8.x wrote it,
// empty unless the retired standalone sandbox pinned a home): the v8 schema
// keeps accepting it until the v9 migration has dropped it
// (migrateRetiredStandaloneSandbox), as long as the v8 schema validates
// 0.8.x files.
func TestConfigV8SchemaAcceptsTheRetiredOpenClawHomePin(t *testing.T) {
	raw := []byte(`config_version: 8
data_dir: /tmp/defenseclaw
claw:
  mode: codex
  home_dir: /tmp/codex
  config_file: /tmp/codex/config.toml
  workspace_dir: ""
  openclaw_home_original: /tmp/original-openclaw
`)
	_, err := ParseCompileObservabilityV8(
		"claw-custody-v8.yaml",
		raw,
		ObservabilityV8CompileOptions{DefaultDataDir: "/tmp/defenseclaw"},
	)
	if err != nil {
		t.Fatalf("v8 compiler rejected the retired claw.openclaw_home_original: %v", err)
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

func TestConfigV8SchemaRetentionDefaultIsSevenDays(t *testing.T) {
	compiled, err := compileObservabilityV8Local(ObservabilityV8LocalSource{})
	if err != nil {
		t.Fatal(err)
	}
	if compiled.RetentionDays != 7 {
		t.Fatalf("compiled default retention = %d days, want 7", compiled.RetentionDays)
	}

	var schema map[string]any
	if err := json.Unmarshal(publicschemas.DefenseClawConfigV8Schema(), &schema); err != nil {
		t.Fatal(err)
	}
	definitions := schema["$defs"].(map[string]any)
	localStore := definitions["localStore"].(map[string]any)
	properties := localStore["properties"].(map[string]any)
	retentionDays, ok := properties["retention_days"].(map[string]any)
	if !ok {
		t.Fatal("observability.local.retention_days is absent from canonical schema")
	}
	if got := retentionDays["default"]; got != float64(7) {
		t.Fatalf("observability.local.retention_days default = %v, want 7", got)
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

// GAP-0498, GAP-0514: a schema violation names what is wrong: the required
// key an assignment lacks and what it takes, the minimum an empty match
// misses, and a size limit with the size the value has.
func TestV8SchemaNamesMissingKeysAndLimits(t *testing.T) {
	base := "config_version: 9\nguardrail:\n  profiles:\n    engineering: {}\n"
	for _, tc := range []struct{ name, doc, keyword, expected string }{
		{"no match", base + "  profile_assignments:\n    - profile: engineering\n", "required",
			"the required key match: a mapping that sets at least one of agents, connectors, groups, users"},
		{"empty match", base + "  profile_assignments:\n    - profile: engineering\n      match: {}\n", "minProperties",
			"a mapping that sets at least one of agents, connectors, groups, users"},
		{"empty groups", base + "  profile_assignments:\n    - profile: engineering\n      match: {groups: []}\n", "minItems", "a nonempty list"},
		{"long request_access", base + "    contractors:\n      sandbox:\n        request_access: " + strings.Repeat("x", 600) + "\n",
			"maxLength", "a string of at most 512 characters (it has 600)"},
	} {
		err := ValidateV8SchemaBytes("admin.yaml", []byte(tc.doc))
		var schemaErr *V8SchemaError
		if !errors.As(err, &schemaErr) || schemaErr.Keyword != tc.keyword || schemaErr.Expected != tc.expected {
			t.Fatalf("%s: %v (%+v)", tc.name, err, schemaErr)
		}
		if tc.keyword == "required" && !slices.Equal(schemaErr.Missing, []string{"match"}) {
			t.Fatalf("%s: missing = %q", tc.name, schemaErr.Missing)
		}
	}
}

// GAP-0617: `defenseclaw config reference` printed a "v8" reference with
// config_version: 8 on a v9 install. Every embedded reference format and the
// JSON Schema title must name MaxSupportedConfigVersion, the version written.
func TestConfigReferenceNamesCurrentConfigVersion(t *testing.T) {
	version := strconv.Itoa(MaxSupportedConfigVersion)
	yamlRef := string(publicschemas.DefenseClawConfigV8ObservabilityReferenceYAML())
	if !strings.HasPrefix(yamlRef, "# DEFENSECLAW CONFIGURATION v"+version+" — OBSERVABILITY REFERENCE\n") {
		t.Errorf("YAML reference header does not name v%s: %q", version, strings.SplitN(yamlRef, "\n", 2)[0])
	}
	if !strings.Contains(yamlRef, "\nconfig_version: "+version+"\n") {
		t.Errorf("YAML reference does not declare config_version: %s", version)
	}
	mdRef := string(publicschemas.DefenseClawConfigV8ObservabilityReferenceMarkdown())
	if !strings.HasPrefix(mdRef, "# DefenseClaw v"+version+" observability configuration reference\n") ||
		!strings.Contains(mdRef, "`config_version: "+version+"`") {
		t.Errorf("Markdown reference does not name config_version %s: %q", version, strings.SplitN(mdRef, "\n", 2)[0])
	}
	var schema struct {
		Title      string `json:"title"`
		Properties struct {
			ConfigVersion struct {
				Enum []int `json:"enum"`
			} `json:"config_version"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(publicschemas.DefenseClawConfigV8Schema(), &schema); err != nil {
		t.Fatal(err)
	}
	if schema.Title != "DefenseClaw configuration v"+version {
		t.Errorf("schema title = %q", schema.Title)
	}
	if enum := schema.Properties.ConfigVersion.Enum; len(enum) == 0 || slices.Max(enum) != MaxSupportedConfigVersion {
		t.Errorf("schema config_version enum = %v, want max %d", enum, MaxSupportedConfigVersion)
	}
}
