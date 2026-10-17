// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

// Package contracttest validates documents against the management agent
// contract schemas (packaging/mdm/contract/management-agent.md) for the tests
// of every package that prints them, so they all check one contract under
// the same rules.
package contracttest

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// Dir is the contract folder relative to a package directory under
// internal/, the working directory of that package's tests.
const Dir = "../../packaging/mdm/contract"

// Schemas are the compiled contract schemas by file name.
type Schemas map[string]*jsonschema.Schema

// Compile compiles every schema of the contract folder under its $id, so the
// cross-file $refs resolve without a network loader, with formats asserted.
func Compile(t testing.TB) Schemas {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(filepath.FromSlash(Dir), "*.schema.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("contract schemas: %v (%d found)", err, len(paths))
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	ids := map[string]string{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var head struct {
			ID string `json:"$id"`
		}
		if err := json.Unmarshal(data, &head); err != nil || head.ID == "" {
			t.Fatalf("%s: no $id (%v)", path, err)
		}
		if err := compiler.AddResource(head.ID, bytes.NewReader(data)); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		ids[filepath.Base(path)] = head.ID
	}
	schemas := Schemas{}
	for name, id := range ids {
		schema, err := compiler.Compile(id)
		if err != nil {
			t.Fatalf("compile %s: %v", name, err)
		}
		schemas[name] = schema
	}
	return schemas
}

// Validate requires document to be exactly one JSON value that schema name
// accepts, and returns it decoded (nil when it is not an object).
func (s Schemas) Validate(t testing.TB, name string, document []byte) map[string]any {
	t.Helper()
	schema, ok := s[name]
	if !ok {
		t.Fatalf("no contract schema %s", name)
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("%s: not JSON: %v\n%s", name, err, document)
	}
	if decoder.More() {
		t.Fatalf("%s: more than one JSON document:\n%s", name, document)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("%s rejects a real document: %v\n%s", name, err, document)
	}
	object, _ := value.(map[string]any)
	return object
}

// ValidateValue validates the JSON encoding of value as Validate does.
func (s Schemas) ValidateValue(t testing.TB, name string, value any) map[string]any {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return s.Validate(t, name, document)
}
