// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// The MDM kit publishes the lifecycle result contract as a JSON Schema.
// These tests keep the schema and the Go type in lockstep: every field the
// type renders is described, every always-rendered field is required, and
// real results round-trip through the schema unchanged.

const lifecycleSchemaPath = "../../packaging/mdm/contract/lifecycle-result.schema.json"

func compileLifecycleSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(lifecycleSchemaPath))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource("lifecycle-result.schema.json", bytes.NewReader(data)); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	schema, err := compiler.Compile("lifecycle-result.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return schema
}

func validateAgainstSchema(t *testing.T, schema *jsonschema.Schema, document []byte) error {
	t.Helper()
	var value any
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode %s: %v", document, err)
	}
	return schema.Validate(value)
}

func sampleResults() map[string]*Result {
	fresh := New("status", "standalone", "linux", "")
	fresh.Finish("linux", 0)

	installed := New("ensure", "standalone", "darwin", "1.4.0")
	installed.InstalledVersion = "1.4.0"
	installed.Installed = true
	installed.Services = []Service{
		{Name: "com.cisco.defenseclaw.gateway", Kind: "gateway", State: "running", PID: 812, Required: true},
		{Name: "com.cisco.defenseclaw.hook-guardian", Kind: "guardian", State: "running", Restarts: 1, Required: true},
		{Name: "com.cisco.defenseclaw.verify", Kind: "timer", State: "loaded", StartMode: "calendar"},
	}
	installed.Readiness = Readiness{Gateway: true, Guardian: true, Enumerator: true, SensorHelper: true}
	installed.Inspection = Inspection{Local: "active", AIDefense: "unavailable:auth_failed"}
	installed.MachinePolicy["codex"] = MachinePolicyState{
		Ownership: "merge", Lock: "enforce", EffectiveLock: "enforce", OwnedEntries: 1, ForeignEntries: 2,
		HigherPrecedence: []string{"mdm_managed_preferences"}, Conflicts: []string{}, LiveVerifiedAt: "2026-09-26T18:00:00Z",
	}
	installed.Enrollment = Enrollment{Targets: 3, Pending: 1, Exempt: 1}
	installed.Destinations = []Destination{
		{Name: "local-sqlite", Kind: "local_sqlite", Enabled: true, Signals: []string{"logs"}, RedactionProfiles: []string{"none"}},
		{Name: "galileo", Kind: "otlp", Enabled: true, Preset: "galileo", Signals: []string{"traces"}, RedactionProfiles: []string{"strict"}},
	}
	installed.CoverageComplete = true
	installed.SecurityComplete = true
	installed.AddWarning("not_started", "installed with --no-start")
	installed.LogPath = "/Library/Logs/Cisco/DefenseClaw/enterprise-lifecycle.log"
	installed.Finish("darwin", 0)

	noop := New("ensure", "standalone", "windows", "1.4.0")
	noop.Installed, noop.InstalledVersion = true, "1.4.0"
	noop.Noop, noop.NoopReason = true, "installed deployment matches the payload and config"
	noop.Inspection = Inspection{Local: "active", AIDefense: "disabled"}
	noop.Finish("windows", 0)

	busy := New("ensure", "standalone", "windows", "1.4.0")
	busy.AddError("lifecycle_busy", "another lifecycle run holds the lock")
	busy.Finish("windows", BusyExitCode("windows"))

	failed := New("upgrade", "standalone", "linux", "1.5.0")
	failed.Installed, failed.InstalledVersion = true, "1.4.0"
	failed.AddError("gateway_not_ready", "gateway did not report ready")
	failed.AddError("rolled_back", "the previous deployment was restored")
	failed.Finish("linux", 0)

	invalid := New("install", "standalone", "linux", "")
	invalid.AddError("invalid_arguments", "--payload and --from-package are exclusive")
	invalid.Finish("linux", InvalidArgsExitCode("linux"))

	notRoot := New("ensure", "standalone", "linux", "1.4.0")
	notRoot.AddError("not_root", "run this command as root (sudo or the MDM agent)")
	notRoot.Finish("linux", 0)

	return map[string]*Result{
		"fresh": fresh, "installed": installed, "noop": noop, "busy": busy, "failed": failed, "invalid": invalid,
		"not_root": notRoot,
	}
}

func TestLifecycleSchemaAcceptsAndRoundTripsResults(t *testing.T) {
	schema := compileLifecycleSchema(t)
	for name, result := range sampleResults() {
		document, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		if err := validateAgainstSchema(t, schema, document); err != nil {
			t.Fatalf("%s: schema rejected a real result: %v\n%s", name, err, document)
		}
		var decoded Result
		decoder := json.NewDecoder(bytes.NewReader(document))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&decoded); err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		again, err := json.Marshal(decoded)
		if err != nil {
			t.Fatalf("%s: re-marshal: %v", name, err)
		}
		if !bytes.Equal(document, again) {
			t.Fatalf("%s: result did not round-trip:\n%s\n%s", name, document, again)
		}
	}
}

func TestLifecycleSchemaRejectsContractViolations(t *testing.T) {
	schema := compileLifecycleSchema(t)
	base := func() map[string]any {
		document, err := json.Marshal(sampleResults()["installed"])
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(document, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	cases := map[string]func(map[string]any){
		"unknown top-level field": func(v map[string]any) { v["extra"] = true },
		"failure without errors":  func(v map[string]any) { v["ok"] = false; v["exit_code"] = 1 },
		"windows code on unix": func(v map[string]any) {
			v["ok"] = false
			v["exit_code"] = 1603
			v["errors"] = []any{map[string]any{"code": "x", "message": "y"}}
		},
	}
	for name, mutate := range cases {
		value := base()
		mutate(value)
		document, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateAgainstSchema(t, schema, document); err == nil {
			t.Fatalf("%s: schema accepted %s", name, document)
		}
	}
}

// TestLifecycleSchemaDescribesEveryField walks the Go types and requires the
// schema to name exactly their JSON fields, requiring the ones rendered
// without omitempty.
func anySlice(value any) []any {
	items, _ := value.([]any)
	return items
}

func TestLifecycleSchemaDescribesEveryField(t *testing.T) {

	data, err := os.ReadFile(filepath.FromSlash(lifecycleSchemaPath))
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	defs := root["$defs"].(map[string]any)
	properties := root["properties"].(map[string]any)
	objects := map[string]struct {
		typ    reflect.Type
		schema map[string]any
	}{
		"result":        {reflect.TypeOf(Result{}), root},
		"service":       {reflect.TypeOf(Service{}), defs["service"].(map[string]any)},
		"machinePolicy": {reflect.TypeOf(MachinePolicyState{}), defs["machinePolicy"].(map[string]any)},
		"message":       {reflect.TypeOf(Message{}), defs["message"].(map[string]any)},
		"portHolder":    {reflect.TypeOf(PortHolder{}), defs["portHolder"].(map[string]any)},
		"policyState":   {reflect.TypeOf(PolicyState{}), defs["policyState"].(map[string]any)},
		"readiness":     {reflect.TypeOf(Readiness{}), properties["readiness"].(map[string]any)},
		"inspection":    {reflect.TypeOf(Inspection{}), properties["inspection"].(map[string]any)},
		"enrollment":    {reflect.TypeOf(Enrollment{}), properties["enrollment"].(map[string]any)},
	}
	for name, object := range objects {
		var fields, required []string
		for i := 0; i < object.typ.NumField(); i++ {
			tag := object.typ.Field(i).Tag.Get("json")
			parts := strings.Split(tag, ",")
			if parts[0] == "" || parts[0] == "-" {
				continue
			}
			fields = append(fields, parts[0])
			if len(parts) == 1 {
				required = append(required, parts[0])
			}
		}
		var described []string
		for key := range object.schema["properties"].(map[string]any) {
			described = append(described, key)
		}
		var schemaRequired []string
		for _, key := range object.schema["required"].([]any) {
			schemaRequired = append(schemaRequired, key.(string))
		}
		if name == "result" {
			// The deployment state fields are required of every result but
			// a not_root one, which leaves them out (GAP-0279).
			for _, clause := range root["allOf"].([]any) {
				if otherwise, ok := clause.(map[string]any)["else"].(map[string]any); ok {
					for _, key := range anySlice(otherwise["required"]) {
						schemaRequired = append(schemaRequired, key.(string))
					}
				}
			}
		}
		if object.schema["additionalProperties"] != false {
			t.Errorf("%s: schema must set additionalProperties: false", name)
		}
		sort.Strings(fields)
		sort.Strings(required)
		sort.Strings(described)
		sort.Strings(schemaRequired)
		if !reflect.DeepEqual(fields, described) {
			t.Errorf("%s: schema properties %v, Go fields %v", name, described, fields)
		}
		if !reflect.DeepEqual(required, schemaRequired) {
			t.Errorf("%s: schema required %v, always-rendered Go fields %v", name, schemaRequired, required)
		}
	}
	if properties["schema_version"].(map[string]any)["const"] != float64(SchemaVersion) {
		t.Errorf("schema_version const must equal SchemaVersion %d", SchemaVersion)
	}
}
