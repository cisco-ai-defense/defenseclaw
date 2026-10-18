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
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// Dir is the contract folder relative to a package directory under
// internal/, the working directory of that package's tests.
const Dir = "../../packaging/mdm/contract"

// Schemas are the compiled contract schemas. A schema is named by its file
// name, or by "<file>#<JSON pointer>" for one definition of that file, such
// as "bundle-status.schema.json#/$defs/ref".
type Schemas struct {
	compiler *jsonschema.Compiler
	ids      map[string]string
	mu       *sync.Mutex
	compiled map[string]*jsonschema.Schema
}

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
	s := Schemas{compiler: compiler, ids: map[string]string{}, mu: &sync.Mutex{}, compiled: map[string]*jsonschema.Schema{}}
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
		s.ids[filepath.Base(path)] = head.ID
	}
	for name := range s.ids {
		s.schema(t, name)
	}
	return s
}

// schema is the compiled schema name names, compiled on first use.
func (s Schemas) schema(t testing.TB, name string) *jsonschema.Schema {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if schema, ok := s.compiled[name]; ok {
		return schema
	}
	file, pointer, _ := strings.Cut(name, "#")
	id, ok := s.ids[file]
	if !ok {
		t.Fatalf("no contract schema %s", name)
	}
	if pointer != "" {
		id += "#" + pointer
	}
	schema, err := s.compiler.Compile(id)
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	s.compiled[name] = schema
	return schema
}

// Validate requires document to be exactly one JSON value that schema name
// accepts, and returns it decoded (nil when it is not an object).
func (s Schemas) Validate(t testing.TB, name string, document []byte) map[string]any {
	t.Helper()
	schema := s.schema(t, name)
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("%s: not JSON: %v\n%s", name, err, document)
	}
	// Decoder.More misses a stray "]" or "}" after a top-level value, so
	// require the end of the input instead.
	switch err := decoder.Decode(new(any)); {
	case err == nil:
		t.Fatalf("%s: more than one JSON document:\n%s", name, document)
	case !errors.Is(err, io.EOF):
		t.Fatalf("%s: data after the JSON document: %v\n%s", name, err, document)
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

// RequireMembers fails unless the closed object schema name (as Validate
// names it) describes exactly the JSON members of the struct type typ: a
// property for every json tag and no other, required exactly for the members
// without omitempty, and additionalProperties false. A run validates only the
// members its path sets, so this catches a Go field the schema rejects on
// every path at once.
func RequireMembers(t testing.TB, name string, typ reflect.Type) {
	t.Helper()
	file, pointer, _ := strings.Cut(name, "#")
	data, err := os.ReadFile(filepath.Join(filepath.FromSlash(Dir), file))
	if err != nil {
		t.Fatal(err)
	}
	var node any
	if err := json.Unmarshal(data, &node); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	for _, token := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		if token == "" {
			continue
		}
		object, _ := node.(map[string]any)
		node = object[strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")]
	}
	object, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("%s: not an object schema", name)
	}
	if object["additionalProperties"] != false {
		t.Errorf("%s: the schema must set additionalProperties: false", name)
	}
	properties, _ := object["properties"].(map[string]any)
	var described, schemaRequired []string
	for key := range properties {
		described = append(described, key)
	}
	for _, key := range anys(object["required"]) {
		schemaRequired = append(schemaRequired, key.(string))
	}
	members, required := jsonMembers(typ)
	for _, list := range [][]string{described, schemaRequired, members, required} {
		slices.Sort(list)
	}
	if !slices.Equal(members, described) {
		t.Errorf("%s: schema properties %v, Go members of %s %v", name, described, typ, members)
	}
	if !slices.Equal(required, schemaRequired) {
		t.Errorf("%s: schema required %v, always-rendered Go members of %s %v", name, schemaRequired, typ, required)
	}
}

func anys(value any) []any {
	list, _ := value.([]any)
	return list
}

// jsonMembers are the JSON member names encoding/json writes for typ, and
// those it writes always (no omitempty). An untagged embedded struct
// contributes its own members.
func jsonMembers(typ reflect.Type) (members, required []string) {
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag, tagged := field.Tag.Lookup("json")
		if field.Anonymous && !tagged {
			embedded := field.Type
			if embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct {
				m, r := jsonMembers(embedded)
				members, required = append(members, m...), append(required, r...)
				continue
			}
		}
		if !field.IsExported() {
			continue
		}
		parts := strings.Split(tag, ",")
		if parts[0] == "-" && len(parts) == 1 {
			continue
		}
		member := parts[0]
		if member == "" {
			member = field.Name
		}
		members = append(members, member)
		if !slices.Contains(parts[1:], "omitempty") && !slices.Contains(parts[1:], "omitzero") {
			required = append(required, member)
		}
	}
	return members, required
}
