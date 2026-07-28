// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

const observabilityV8ConfigSchemaID = "https://schemas.defenseclaw.dev/config/v8/defenseclaw-config.schema.json"

var (
	observabilityV8SchemaOnce sync.Once
	observabilityV8Schema     *jsonschema.Schema
	observabilityV8SchemaDoc  map[string]any
	observabilityV8SchemaErr  error
)

var observabilityV8AdditionalPropertyPattern = regexp.MustCompile(`additionalProperties '((?:\\'|[^'])+)' not allowed`)

type V8SchemaError struct {
	Source        string
	Path          string
	Line          int
	Column        int
	Keyword       string
	ReceivedClass string
	Expected      string
	Suggestion    string
	Summary       string
	Action        string
}

func (e *V8SchemaError) Error() string {
	if e == nil {
		return ""
	}
	source := strings.TrimSpace(e.Source)
	if source == "" {
		source = "<config>"
	}
	if e.Line > 0 {
		source += ":" + strconv.Itoa(e.Line)
		if e.Column > 0 {
			source += ":" + strconv.Itoa(e.Column)
		}
	}
	message := fmt.Sprintf("%s: [config_schema_invalid]", source)
	if e.Path != "" {
		message += " " + e.Path + ":"
	}
	message += " " + e.Summary
	if e.ReceivedClass != "" {
		message += " (received " + e.ReceivedClass + ")"
	}
	if e.Expected != "" {
		message += "; expected " + e.Expected
	}
	if e.Suggestion != "" {
		message += "; did you mean " + e.Suggestion + "?"
	}
	if e.Action != "" {
		message += "; " + e.Action
	}
	return message
}

func validateV8Schema(source string, document *V8YAMLDocument) error {
	schema, err := compiledObservabilityV8Schema()
	if err != nil {
		return fmt.Errorf("config: initialize embedded v8 schema: %w", err)
	}
	if document == nil {
		return &V8SchemaError{Source: source, Path: "$", Summary: "configuration document is unavailable", Action: "parse the v8 YAML source before schema validation"}
	}
	if err := schema.Validate(document.Plain); err != nil {
		var validation *jsonschema.ValidationError
		if !errors.As(err, &validation) {
			return &V8SchemaError{
				Source:  source,
				Path:    "$",
				Summary: "configuration does not satisfy the canonical v8 schema",
				Action:  "correct the configuration and retry",
			}
		}
		leaf := deepestV8SchemaError(validation)
		path := v8SchemaDisplayPath(leaf.InstanceLocation)
		keyword := leaf.KeywordLocation
		if index := strings.LastIndex(keyword, "/"); index >= 0 {
			keyword = keyword[index+1:]
		}
		if keyword == "" {
			keyword = "schema"
		}
		unknown := v8SchemaUnknownProperty(leaf)
		if unknown != "" {
			path = v8YAMLChildPath(path, unknown)
		}
		node := v8SchemaYAMLNode(document.Document, leaf.InstanceLocation, unknown)
		expected, suggestion := v8SchemaExpectation(leaf, unknown)
		result := &V8SchemaError{
			Source:        source,
			Path:          path,
			Keyword:       keyword,
			ReceivedClass: v8SchemaNodeClass(node),
			Expected:      expected,
			Suggestion:    suggestion,
			Summary:       "configuration violates the " + keyword + " constraint",
			Action:        "inspect the canonical v8 schema or generated reference and correct this field",
		}
		if node != nil {
			result.Line, result.Column = node.Line, node.Column
		}
		return result
	}
	return nil
}

func compiledObservabilityV8Schema() (*jsonschema.Schema, error) {
	observabilityV8SchemaOnce.Do(func() {
		raw := publicschemas.DefenseClawConfigV8Schema()
		if err := json.Unmarshal(raw, &observabilityV8SchemaDoc); err != nil {
			observabilityV8SchemaErr = err
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.Draft = jsonschema.Draft2020
		if err := compiler.AddResource(
			observabilityV8ConfigSchemaID,
			bytes.NewReader(raw),
		); err != nil {
			observabilityV8SchemaErr = err
			return
		}
		observabilityV8Schema, observabilityV8SchemaErr = compiler.Compile(observabilityV8ConfigSchemaID)
	})
	return observabilityV8Schema, observabilityV8SchemaErr
}

func deepestV8SchemaError(root *jsonschema.ValidationError) *jsonschema.ValidationError {
	best := root
	var visit func(*jsonschema.ValidationError, int)
	bestDepth := -1
	visit = func(current *jsonschema.ValidationError, depth int) {
		locationDepth := strings.Count(current.InstanceLocation, "/")
		score := locationDepth*1_000 + depth
		if len(current.Causes) == 0 && score > bestDepth {
			best, bestDepth = current, score
		}
		for _, cause := range current.Causes {
			visit(cause, depth+1)
		}
	}
	visit(root, 0)
	return best
}

func v8SchemaDisplayPath(pointer string) string {
	path := "$"
	for _, segment := range v8SchemaPointerSegments(pointer) {
		if _, err := strconv.Atoi(segment); err == nil {
			path += "[" + segment + "]"
		} else {
			path = v8YAMLChildPath(path, segment)
		}
	}
	return path
}

func v8SchemaYAMLNode(document *yaml.Node, pointer, unknown string) *yaml.Node {
	current := v8DocumentRoot(document)
	for _, segment := range v8SchemaPointerSegments(pointer) {
		if current == nil {
			return nil
		}
		switch current.Kind {
		case yaml.MappingNode:
			current = v8YAMLMapValue(current, segment)
		case yaml.SequenceNode:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(current.Content) {
				return current
			}
			current = current.Content[index]
		default:
			return current
		}
	}
	if unknown != "" && current != nil && current.Kind == yaml.MappingNode {
		if child := v8YAMLMapValue(current, unknown); child != nil {
			return child
		}
	}
	return current
}

func v8SchemaPointerSegments(pointer string) []string {
	pointer = strings.TrimPrefix(pointer, "#")
	pointer = strings.TrimPrefix(pointer, "/")
	if pointer == "" {
		return nil
	}
	parts := strings.Split(pointer, "/")
	for index := range parts {
		parts[index] = strings.ReplaceAll(strings.ReplaceAll(parts[index], "~1", "/"), "~0", "~")
	}
	return parts
}

func v8SchemaUnknownProperty(validation *jsonschema.ValidationError) string {
	if validation == nil || !strings.HasSuffix(validation.KeywordLocation, "/additionalProperties") {
		return ""
	}
	match := observabilityV8AdditionalPropertyPattern.FindStringSubmatch(validation.Message)
	if len(match) != 2 {
		return ""
	}
	return strings.ReplaceAll(match[1], `\'`, `'`)
}

func v8SchemaExpectation(validation *jsonschema.ValidationError, unknown string) (string, string) {
	if unknown == "" {
		if expected := v8SchemaDeclaredExpectation(validation); expected != "" {
			return expected, ""
		}
		switch {
		case strings.HasSuffix(validation.KeywordLocation, "/required"):
			return "all required fields", ""
		case strings.HasSuffix(validation.KeywordLocation, "/type"):
			return "the schema-declared value type", ""
		case strings.HasSuffix(validation.KeywordLocation, "/enum"), strings.HasSuffix(validation.KeywordLocation, "/const"):
			return "one of the schema-declared values", ""
		default:
			return "the canonical v8 field contract", ""
		}
	}
	location := validation.AbsoluteKeywordLocation
	if marker := strings.Index(location, "#"); marker >= 0 {
		location = location[marker+1:]
	}
	if location == "" {
		location = validation.KeywordLocation
	}
	properties := v8SchemaSiblingProperties(location)
	return "a declared field name", v8SchemaNearestName(unknown, properties)
}

func v8SchemaDeclaredExpectation(validation *jsonschema.ValidationError) string {
	location := validation.AbsoluteKeywordLocation
	if marker := strings.Index(location, "#"); marker >= 0 {
		location = location[marker+1:]
	}
	segments := v8SchemaPointerSegments(location)
	var current any = observabilityV8SchemaDoc
	for _, segment := range segments {
		mapping, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = mapping[segment]
	}
	keyword := ""
	if len(segments) > 0 {
		keyword = segments[len(segments)-1]
	}
	switch keyword {
	case "const":
		raw, _ := json.Marshal(current)
		return "the literal " + string(raw)
	case "enum":
		raw, _ := json.Marshal(current)
		return "one of " + string(raw)
	case "type":
		if value, ok := current.(string); ok {
			return "a value of type " + value
		}
	case "pattern":
		return "a value matching the schema-declared pattern"
	case "minimum":
		return "a number at or above the declared minimum"
	case "maximum":
		return "a number at or below the declared maximum"
	case "minLength", "minItems", "minProperties":
		return "a nonempty value meeting the declared minimum"
	case "maxLength", "maxItems", "maxProperties":
		return "a value within the declared size limit"
	}
	return ""
}

func v8SchemaSiblingProperties(keywordLocation string) []string {
	segments := v8SchemaPointerSegments(strings.TrimSuffix(keywordLocation, "/additionalProperties"))
	var current any = observabilityV8SchemaDoc
	for _, segment := range segments {
		mapping, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = mapping[segment]
	}
	mapping, ok := current.(map[string]any)
	if !ok {
		return nil
	}
	properties, ok := mapping["properties"].(map[string]any)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}
	return names
}

func v8SchemaNearestName(value string, candidates []string) string {
	best, bestDistance := "", len(value)+4
	for _, candidate := range candidates {
		distance := v8SchemaEditDistance(value, candidate)
		if distance < bestDistance || distance == bestDistance && candidate < best {
			best, bestDistance = candidate, distance
		}
	}
	if bestDistance > 3 {
		return ""
	}
	return best
}

func v8SchemaEditDistance(left, right string) int {
	previous := make([]int, len(right)+1)
	for index := range previous {
		previous[index] = index
	}
	for leftIndex, leftRune := range []rune(left) {
		current := make([]int, len([]rune(right))+1)
		current[0] = leftIndex + 1
		for rightIndex, rightRune := range []rune(right) {
			cost := 0
			if leftRune != rightRune {
				cost = 1
			}
			current[rightIndex+1] = min(
				current[rightIndex]+1,
				previous[rightIndex+1]+1,
				previous[rightIndex]+cost,
			)
		}
		previous = current
	}
	return previous[len(previous)-1]
}

func v8SchemaNodeClass(node *yaml.Node) string {
	if node == nil {
		return ""
	}
	switch node.Kind {
	case yaml.MappingNode:
		return "object"
	case yaml.SequenceNode:
		return "array"
	case yaml.ScalarNode:
		switch node.ShortTag() {
		case "!!bool":
			return "boolean"
		case "!!int":
			return "integer"
		case "!!float":
			return "number"
		case "!!null":
			return "null"
		default:
			return "string"
		}
	default:
		return "value"
	}
}
