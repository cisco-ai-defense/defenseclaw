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
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

// The schema file keeps its v8 directory; its $id names the version it
// describes, config_version 9 (GAP-1651).
const observabilityV8ConfigSchemaID = "https://schemas.defenseclaw.dev/config/v9/defenseclaw-config.schema.json"

var (
	observabilityV8SchemaOnce sync.Once
	observabilityV8Schema     *jsonschema.Schema
	observabilityV8SchemaDoc  map[string]any
	observabilityV8SchemaErr  error
)

var (
	observabilityV8AdditionalPropertyPattern = regexp.MustCompile(`additionalProperties ((?:'(?:\\'|[^'])+'(?:, )?)+) not allowed`)
	observabilityV8QuotedPropertyPattern     = regexp.MustCompile(`'((?:\\'|[^'])+)'`)
)

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
	// Value is the rejected scalar of an enum violation (at most 60 bytes),
	// so the CLI can say 'mode is "x"; allowed values: ...' as config validate
	// does (GAP-1914). Error() never prints it.
	Value string
	// Missing names the keys a required violation found absent, in the
	// schema's order, so a message can name them (GAP-0498).
	Missing []string
	Version int
}

// EnumChoices returns the values an enum violation allows, in the schema's
// order, for a message that names them. An empty string in the enum means
// "unset" (a per-connector key that inherits the global value), not a value
// to type, so it is left out (GAP-2213, as config validate does for GAP-0199).
// ok is false when the violation is not an enum or names no value.
func (e *V8SchemaError) EnumChoices() (names []string, ok bool) {
	if e == nil || e.Keyword != "enum" || !strings.HasPrefix(e.Expected, "one of ") {
		return nil, false
	}
	var choices []any
	if json.Unmarshal([]byte(strings.TrimPrefix(e.Expected, "one of ")), &choices) != nil {
		return nil, false
	}
	for _, choice := range choices {
		if name := fmt.Sprint(choice); name != "" {
			names = append(names, name)
		}
	}
	return names, len(names) > 0
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
	if e.Version >= 9 {
		key := strings.TrimPrefix(e.Path, "$.")
		key = regexp.MustCompile(`\[[^]]+\]`).ReplaceAllString(key, "")
		if key == "" || key == "$" {
			key = "config.yaml"
		}
		message := fmt.Sprintf("config_version %d: %s is invalid", e.Version, key)
		if e.Expected != "" && !strings.Contains(e.Expected, "canonical v8") {
			message += "; expected " + e.Expected
		}
		if e.Suggestion != "" {
			message += "; did you mean " + e.Suggestion + "?"
		}
		return message + "; see defenseclaw config reference --format json-schema."
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

// ValidateV8SchemaBytes checks raw against the embedded v8 schema only,
// without decoding it into a Config. A wrong-type value fails the typed
// decode with a plain unmarshal error, so callers that need the schema
// violation (its path and keyword) check the schema first (GAP-2118).
func ValidateV8SchemaBytes(source string, raw []byte) error {
	document, err := ParseV8YAML(source, raw)
	if err != nil {
		return err
	}
	return validateV8Schema(source, document)
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
			summary := "configuration does not satisfy the canonical v8 schema"
			if v8SchemaDocumentVersion(document) >= 9 {
				summary = "configuration does not satisfy the config_version 9 schema"
			}
			return &V8SchemaError{
				Source:  source,
				Path:    "$",
				Summary: summary,
				Version: v8SchemaDocumentVersion(document),
				Action:  "correct the configuration and retry",
			}
		}
		leaf := firstUnknownV8SchemaError(validation, document.Document)
		if leaf == nil {
			leaf = deepestV8SchemaError(validation)
		}
		path := v8SchemaDisplayPath(leaf.InstanceLocation)
		keyword := leaf.KeywordLocation
		if index := strings.LastIndex(keyword, "/"); index >= 0 {
			keyword = keyword[index+1:]
		}
		if keyword == "" {
			keyword = "schema"
		}
		unknown := v8SchemaUnknownProperty(leaf, document.Document)
		if unknown != "" {
			path = v8YAMLChildPath(path, unknown)
		}
		node := v8SchemaYAMLNode(document.Document, leaf.InstanceLocation, unknown)
		expected, suggestion := v8SchemaExpectation(leaf, unknown)
		if v8SchemaDocumentVersion(document) >= 9 && expected == "the canonical v8 field contract" {
			expected = "a valid value for this setting"
		}
		action := "inspect the canonical v8 schema or generated reference and correct this field"
		if v8SchemaDocumentVersion(document) >= 9 {
			action = "inspect the config_version 9 settings reference and correct this field"
		}
		result := &V8SchemaError{
			Source:        source,
			Path:          path,
			Keyword:       keyword,
			ReceivedClass: v8SchemaNodeClass(node),
			Expected:      expected,
			Suggestion:    suggestion,
			Summary:       "configuration violates the " + keyword + " constraint",
			Action:        action,
			Version:       v8SchemaDocumentVersion(document),
		}
		if key := v8SchemaUnknownKeyNode(document.Document, leaf.InstanceLocation, unknown); key != nil {
			// The line of the key itself: an unknown section's value
			// starts on the line of its first child (GAP-2235).
			result.Line, result.Column = key.Line, key.Column
		} else if node != nil {
			result.Line, result.Column = node.Line, node.Column
		}
		if keyword == "required" {
			result.Missing = v8SchemaMissingKeys(leaf)
			if hint := v8SchemaRequiredExpectation(leaf, result.Missing); hint != "" {
				result.Expected = hint
			}
		}
		if size := v8SchemaNodeSize(node, keyword); size >= 0 {
			// The size the value has, next to the limit (GAP-0514).
			result.Expected += fmt.Sprintf(" (it has %d)", size)
		}
		if node != nil {
			if keyword == "enum" && node.Kind == yaml.ScalarNode {
				result.Value = node.Value
				if len(result.Value) > 60 {
					result.Value = strings.ToValidUTF8(result.Value[:57], "") + "..."
				}
			}
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
		for _, cause := range v8SchemaMatchingBranches(current) {
			visit(cause, depth+1)
		}
	}
	visit(root, 0)
	return best
}

// v8SchemaMatchingBranches is the causes of a oneOf failure without the
// branches whose kind or value type does not match: an http_jsonl
// destination that set both bearer_env and bearer_credential was reported as
// "kind must be the literal jsonl", the deeper error of a branch that never
// applied (GAP-0940), and an admission action mapping without runtime as
// "expected a value of type string" (GAP-1290). Other errors keep all their
// causes.
func v8SchemaMatchingBranches(current *jsonschema.ValidationError) []*jsonschema.ValidationError {
	if !strings.HasSuffix(current.KeywordLocation, "/oneOf") {
		return current.Causes
	}
	matching := make([]*jsonschema.ValidationError, 0, len(current.Causes))
	for _, branch := range current.Causes {
		if !v8SchemaKindMismatch(branch) && !v8SchemaTypeMismatch(branch, current.InstanceLocation) {
			matching = append(matching, branch)
		}
	}
	if len(matching) == 0 {
		return current.Causes
	}
	return matching
}

// v8SchemaTypeMismatch reports a oneOf branch that fails only because the
// value at the location of the oneOf has another type (a string branch for
// a mapping).
func v8SchemaTypeMismatch(validation *jsonschema.ValidationError, instance string) bool {
	if len(validation.Causes) == 0 {
		return validation.InstanceLocation == instance && strings.HasSuffix(validation.KeywordLocation, "/type")
	}
	for _, cause := range validation.Causes {
		if !v8SchemaTypeMismatch(cause, instance) {
			return false
		}
	}
	return true
}

func v8SchemaKindMismatch(validation *jsonschema.ValidationError) bool {
	if strings.HasSuffix(validation.KeywordLocation, "/properties/kind/const") {
		return true
	}
	for _, cause := range validation.Causes {
		if v8SchemaKindMismatch(cause) {
			return true
		}
	}
	return false
}

// firstUnknownV8SchemaError is the undeclared-key error whose key comes
// first in the file, or nil when there is none. The validator's causes come
// in map order, so with undeclared keys in several sections the deepest
// error named a different key on each run, and an unknown top-level section
// lost to a deeper key (GAP-2234). Errors inside a oneOf or anyOf branch are
// skipped: a key may be undeclared only in the branch that does not apply.
func firstUnknownV8SchemaError(root *jsonschema.ValidationError, document *yaml.Node) *jsonschema.ValidationError {
	var best *jsonschema.ValidationError
	bestLine, bestColumn := 0, 0
	var visit func(*jsonschema.ValidationError)
	visit = func(current *jsonschema.ValidationError) {
		location := current.KeywordLocation + "/"
		if strings.Contains(location, "/oneOf/") || strings.Contains(location, "/anyOf/") {
			return
		}
		if len(current.Causes) == 0 {
			unknown := v8SchemaUnknownProperty(current, document)
			if key := v8SchemaUnknownKeyNode(document, current.InstanceLocation, unknown); key != nil &&
				(best == nil || key.Line < bestLine || key.Line == bestLine && key.Column < bestColumn) {
				best, bestLine, bestColumn = current, key.Line, key.Column
			}
		}
		for _, cause := range current.Causes {
			visit(cause)
		}
	}
	visit(root)
	return best
}

// v8SchemaUnknownKeyNode is the key node of the undeclared key unknown in
// the mapping at pointer, or nil.
func v8SchemaUnknownKeyNode(document *yaml.Node, pointer, unknown string) *yaml.Node {
	if unknown == "" {
		return nil
	}
	mapping := v8SchemaYAMLNode(document, pointer, "")
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if key := mapping.Content[index]; key.Kind == yaml.ScalarNode && key.Value == unknown {
			return key
		}
	}
	return nil
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

// v8SchemaUnknownProperty names the undeclared key of an additionalProperties
// violation. With several (two typos in one section) it is the first one in
// the file, so the error names a key, not its section (GAP-2173).
func v8SchemaUnknownProperty(validation *jsonschema.ValidationError, document *yaml.Node) string {
	if validation == nil || !strings.HasSuffix(validation.KeywordLocation, "/additionalProperties") {
		return ""
	}
	match := observabilityV8AdditionalPropertyPattern.FindStringSubmatch(validation.Message)
	if len(match) != 2 {
		return ""
	}
	var names []string
	for _, quoted := range observabilityV8QuotedPropertyPattern.FindAllStringSubmatch(match[1], -1) {
		names = append(names, strings.ReplaceAll(quoted[1], `\'`, `'`))
	}
	if len(names) == 0 {
		return ""
	}
	if mapping := v8SchemaYAMLNode(document, validation.InstanceLocation, ""); mapping != nil && mapping.Kind == yaml.MappingNode {
		for index := 0; index+1 < len(mapping.Content); index += 2 {
			if key := mapping.Content[index].Value; slices.Contains(names, key) {
				return key
			}
		}
	}
	return names[0]
}

func v8SchemaExpectation(validation *jsonschema.ValidationError, unknown string) (string, string) {
	if unknown == "" {
		if expected := v8SchemaDeclaredExpectation(validation); expected != "" {
			return expected, ""
		}
		switch {
		case strings.HasSuffix(validation.KeywordLocation, "/required"):
			var missing []string
			for _, quoted := range observabilityV8QuotedPropertyPattern.FindAllStringSubmatch(validation.Message, -1) {
				missing = append(missing, quoted[1])
			}
			if len(missing) > 0 {
				return "all required fields (missing " + strings.Join(missing, ", ") + ")", ""
			}
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

// v8SchemaKeywordValue is the value of the schema keyword validation failed
// (current), the schema object that holds it (parent) and the keyword's
// name; ok is false when the location does not resolve.
func v8SchemaKeywordValue(validation *jsonschema.ValidationError) (current any, parent map[string]any, keyword string, ok bool) {
	location := validation.AbsoluteKeywordLocation
	if marker := strings.Index(location, "#"); marker >= 0 {
		location = location[marker+1:]
	}
	segments := v8SchemaPointerSegments(location)
	current = observabilityV8SchemaDoc
	for _, segment := range segments {
		// allOf, anyOf and oneOf are arrays (GAP-0940).
		if list, isList := current.([]any); isList {
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(list) {
				return nil, nil, "", false
			}
			current = list[index]
			continue
		}
		mapping, isMap := current.(map[string]any)
		if !isMap {
			return nil, nil, "", false
		}
		parent, current = mapping, mapping[segment]
	}
	if len(segments) > 0 {
		keyword = segments[len(segments)-1]
	}
	return current, parent, keyword, true
}

func v8SchemaDeclaredExpectation(validation *jsonschema.ValidationError) string {
	current, parent, keyword, ok := v8SchemaKeywordValue(validation)
	if !ok {
		return ""
	}
	switch keyword {
	case "not":
		// {"not": {"required": [a, b]}}: two fields that exclude each other.
		if rule, ok := current.(map[string]any); ok {
			if fields, ok := rule["required"].([]any); ok && len(fields) == 2 {
				return fmt.Sprintf("either %v or %v, not both", fields[0], fields[1])
			}
		}
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
		if current == "^agt-[0-9a-f]{16}$" {
			// An agent identity (GAP-0829).
			return "an agent identity: agt- followed by 16 lowercase hexadecimal digits"
		}
		if words := v8SchemaPatternWords(current); words != "" {
			// A severity or level spelled in any case (GAP-0760).
			return words
		}
		if v8SchemaPathPatterns[fmt.Sprint(current)] {
			// openshell.trusted_ca_bundle and pack_dir (rel-1-0-4 GAP-0590).
			return "an absolute path or one starting with ~/"
		}
		return "a value matching the schema-declared pattern"
	case "minimum", "maximum":
		return v8SchemaNumberRange(parent)
	case "minLength", "minItems", "minProperties", "maxLength", "maxItems", "maxProperties":
		// The limit itself, not "the declared minimum" (GAP-0498, GAP-0514).
		if limit, isNumber := current.(float64); isNumber {
			return v8SchemaSizeExpectation(keyword, int(limit), parent)
		}
		if strings.HasPrefix(keyword, "min") {
			return "a nonempty value meeting the declared minimum"
		}
		return "a value within the declared size limit"
	}
	return ""
}

// v8SchemaPathPatterns are the patterns of the path settings.
var v8SchemaPathPatterns = map[string]bool{
	`^(|~/.+|/.+)$`:                        true,
	`^(|~|~/.*|[/\\].*|[A-Za-z]:[/\\].*)$`: true,
}

// v8SchemaPatternWords names the words a ^(a|b|c)$ pattern allows, as the
// Python validator does: [Cc][Rr]... spellings mean any case and an empty
// alternative means an empty value inherits. It is "" for any other pattern.
func v8SchemaPatternWords(value any) string {
	pattern, _ := value.(string)
	inner, ok := strings.CutPrefix(pattern, "^(")
	if !ok {
		return ""
	}
	if inner, ok = strings.CutSuffix(inner, ")$"); !ok {
		return ""
	}
	var words []string
	anyCase, empty := false, false
	for _, part := range strings.Split(inner, "|") {
		switch {
		case part == "":
			empty = true
		case v8SchemaAnyCaseWord.MatchString(part):
			var word strings.Builder
			for i := 2; i < len(part); i += 4 {
				word.WriteByte(part[i])
			}
			words = append(words, strings.ToUpper(word.String()))
			anyCase = true
		case v8SchemaPlainWord.MatchString(part):
			words = append(words, part)
		default:
			return ""
		}
	}
	if len(words) == 0 {
		return ""
	}
	out := "one of " + strings.Join(words, ", ")
	if anyCase {
		out += " in any case"
	}
	if empty {
		out += " (empty inherits)"
	}
	return out
}

var (
	v8SchemaAnyCaseWord = regexp.MustCompile(`^(?:\[[A-Za-z][A-Za-z]\])+$`)
	v8SchemaPlainWord   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// v8SchemaSizeExpectation words a length, item or key count limit: "a string
// of at most 512 characters", "a mapping that sets at least one of agents,
// connectors, groups, users".
func v8SchemaSizeExpectation(keyword string, limit int, schema map[string]any) string {
	bound := "at least"
	if strings.HasPrefix(keyword, "max") {
		bound = "at most"
	}
	switch strings.TrimPrefix(strings.TrimPrefix(keyword, "min"), "max") {
	case "Length":
		if bound == "at least" && limit == 1 {
			return "a nonempty string"
		}
		return fmt.Sprintf("a string of %s %d characters", bound, limit)
	case "Items":
		if bound == "at least" && limit == 1 {
			return "a nonempty list"
		}
		return fmt.Sprintf("a list of %s %d items", bound, limit)
	}
	if names := v8SchemaPropertyNames(schema); bound == "at least" && len(names) > 0 {
		count := strconv.Itoa(limit)
		if limit == 1 {
			count = "one"
		}
		return fmt.Sprintf("a mapping that sets %s %s of %s", bound, count, strings.Join(names, ", "))
	}
	return fmt.Sprintf("a mapping of %s %d keys", bound, limit)
}

// v8SchemaPropertyNames lists the declared keys of an object schema, sorted;
// a $ref to a local definition is followed once.
func v8SchemaPropertyNames(schema map[string]any) []string {
	if ref, ok := schema["$ref"].(string); ok {
		target, resolved := v8SchemaDefinition(ref)
		if !resolved {
			return nil
		}
		schema = target
	}
	properties, _ := schema["properties"].(map[string]any)
	names := make([]string, 0, len(properties))
	for name := range properties {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// v8SchemaDefinition resolves a local "#/$defs/name" reference.
func v8SchemaDefinition(ref string) (map[string]any, bool) {
	name, ok := strings.CutPrefix(ref, "#/$defs/")
	if !ok {
		return nil, false
	}
	defs, _ := observabilityV8SchemaDoc["$defs"].(map[string]any)
	target, ok := defs[name].(map[string]any)
	return target, ok
}

// v8SchemaMissingKeys names the keys a required violation reports absent
// (the validator's "missing properties: 'a', 'b'").
func v8SchemaMissingKeys(validation *jsonschema.ValidationError) []string {
	_, list, found := strings.Cut(validation.Message, "missing properties:")
	if !found {
		return nil
	}
	var names []string
	for _, quoted := range observabilityV8QuotedPropertyPattern.FindAllStringSubmatch(list, -1) {
		names = append(names, strings.ReplaceAll(quoted[1], `\'`, `'`))
	}
	return names
}

// v8SchemaRequiredExpectation names the missing required keys and, for one
// key whose schema is a mapping of declared keys, what it takes: "the
// required key match: a mapping that sets at least one of agents, ...".
func v8SchemaRequiredExpectation(validation *jsonschema.ValidationError, missing []string) string {
	if len(missing) == 0 {
		return ""
	}
	expected := "the required key " + missing[0]
	if len(missing) > 1 {
		return "the required keys " + strings.Join(missing, ", ")
	}
	_, parent, _, ok := v8SchemaKeywordValue(validation)
	if !ok {
		return expected
	}
	properties, _ := parent["properties"].(map[string]any)
	schema, _ := properties[missing[0]].(map[string]any)
	if ref, isRef := schema["$ref"].(string); isRef {
		schema, _ = v8SchemaDefinition(ref)
	}
	if names := v8SchemaPropertyNames(schema); len(names) > 0 {
		if minimum, _ := schema["minProperties"].(float64); minimum >= 1 {
			return expected + ": " + v8SchemaSizeExpectation("minProperties", int(minimum), schema)
		}
		return expected + ": a mapping of " + strings.Join(names, ", ")
	}
	return expected
}

// v8SchemaNodeSize is the size a maxLength, maxItems or maxProperties
// violation counts in node, or -1.
func v8SchemaNodeSize(node *yaml.Node, keyword string) int {
	if node == nil {
		return -1
	}
	switch {
	case keyword == "maxLength" && node.Kind == yaml.ScalarNode:
		return utf8.RuneCountInString(node.Value)
	case keyword == "maxItems" && node.Kind == yaml.SequenceNode:
		return len(node.Content)
	case keyword == "maxProperties" && node.Kind == yaml.MappingNode:
		return len(node.Content) / 2
	}
	return -1
}

// v8SchemaNumberRange names the bounds a schema number declares (its
// minimum and maximum, the schema's own values, never the rejected one):
// "a number between 0 and 1048576".
func v8SchemaNumberRange(schema map[string]any) string {
	bound := func(key string) (string, bool) {
		value, ok := schema[key].(float64)
		if !ok {
			return "", false
		}
		return strconv.FormatFloat(value, 'f', -1, 64), true
	}
	low, hasLow := bound("minimum")
	high, hasHigh := bound("maximum")
	switch {
	case hasLow && hasHigh:
		return "a number between " + low + " and " + high
	case hasLow:
		return "a number at or above " + low
	case hasHigh:
		return "a number at or below " + high
	}
	return "a number within the declared bounds"
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

func v8SchemaDocumentVersion(document *V8YAMLDocument) int {
	if document == nil {
		return 0
	}
	version, _ := strconv.Atoi(fmt.Sprint(document.Plain["config_version"]))
	return version
}
