// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	V8YAMLMaxSourceBytes    = ObservabilityV8MaxSourceBytes
	V8YAMLMaxNodes          = ObservabilityV8MaxYAMLNodes
	V8YAMLMaxDepth          = ObservabilityV8MaxYAMLDepth
	V8YAMLMaxMappingEntries = ObservabilityV8MaxMappingEntries
	v8YAMLConfigVersion     = ObservabilityV8ConfigVersion
)

// V8YAMLErrorCode is a stable machine-readable preflight failure category.
type V8YAMLErrorCode string

const (
	V8YAMLErrorSourceTooLarge      V8YAMLErrorCode = "yaml_source_too_large"
	V8YAMLErrorInvalidUTF8         V8YAMLErrorCode = "yaml_invalid_utf8"
	V8YAMLErrorSyntax              V8YAMLErrorCode = "yaml_syntax_invalid"
	V8YAMLErrorMultipleDocuments   V8YAMLErrorCode = "yaml_multiple_documents"
	V8YAMLErrorRootMappingRequired V8YAMLErrorCode = "yaml_root_mapping_required"
	V8YAMLErrorNodeLimit           V8YAMLErrorCode = "yaml_node_limit"
	V8YAMLErrorDepthLimit          V8YAMLErrorCode = "yaml_depth_limit"
	V8YAMLErrorMappingEntriesLimit V8YAMLErrorCode = "yaml_mapping_entries_limit"
	V8YAMLErrorDuplicateKey        V8YAMLErrorCode = "yaml_duplicate_key"
	V8YAMLErrorAliasForbidden      V8YAMLErrorCode = "yaml_alias_forbidden"
	V8YAMLErrorMergeKeyForbidden   V8YAMLErrorCode = "yaml_merge_key_forbidden"
	V8YAMLErrorCustomTagForbidden  V8YAMLErrorCode = "yaml_custom_tag_forbidden"
	V8YAMLErrorMappingKeyInvalid   V8YAMLErrorCode = "yaml_mapping_key_invalid"
	V8YAMLErrorScalarInvalid       V8YAMLErrorCode = "yaml_scalar_invalid"
	V8YAMLErrorVersionRequired     V8YAMLErrorCode = "config_version_required"
	V8YAMLErrorVersionInvalid      V8YAMLErrorCode = "config_version_invalid"
	V8YAMLErrorVersionUpgrade      V8YAMLErrorCode = "config_version_upgrade_required"
	V8YAMLErrorVersionUnsupported  V8YAMLErrorCode = "config_version_unsupported"
	V8YAMLErrorLegacyKeyForbidden  V8YAMLErrorCode = "legacy_config_key_forbidden"
)

// V8YAMLError never renders a mapping value or scalar payload. Paths retain
// mapping-key names so operators can locate a failure without exposing secrets.
type V8YAMLError struct {
	Code    V8YAMLErrorCode
	Source  string
	Path    string
	Line    int
	Column  int
	Summary string
	Action  string
}

func (e *V8YAMLError) Error() string {
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
	path := ""
	if e.Path != "" {
		path = " " + e.Path + ":"
	}
	message := fmt.Sprintf("%s: [%s]%s %s", source, e.Code, path, e.Summary)
	if e.Action != "" {
		message += "; " + e.Action
	}
	return message
}

// V8YAMLDocument retains the yaml.Node tree for source diagnostics and a plain
// JSON-schema-friendly projection for the later schema/compiler stages.
type V8YAMLDocument struct {
	Source   string
	Document *yaml.Node
	Plain    map[string]any
}

// ParseV8YAML performs source-safety, exact-version, and targeted legacy-key
// checks. It does not apply defaults, migrations, environment overrides, schema
// validation, or observability compilation.
func ParseV8YAML(source string, data []byte) (*V8YAMLDocument, error) {
	if len(data) > V8YAMLMaxSourceBytes {
		return nil, v8Error(source, V8YAMLErrorSourceTooLarge, "$", nil,
			"configuration source exceeds the 4 MiB limit", "reduce the source to 4 MiB or less")
	}
	if !utf8.Valid(data) {
		return nil, v8Error(source, V8YAMLErrorInvalidUTF8, "$", nil,
			"configuration source is not valid UTF-8", "save the file as UTF-8 and retry")
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil && !errors.Is(err, io.EOF) {
		return nil, v8SyntaxError(source, err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, v8SyntaxError(source, err)
		}
		return nil, v8Error(source, V8YAMLErrorMultipleDocuments, "$", v8DocumentRoot(&extra),
			"exactly one YAML document is allowed", "remove every document after the first")
	}

	root := v8DocumentRoot(&document)
	if root == nil || root.Kind != yaml.MappingNode {
		return nil, v8Error(source, V8YAMLErrorRootMappingRequired, "$", root,
			"the YAML document root must be a mapping",
			"define config_version and configuration sections as top-level keys")
	}

	walker := v8YAMLWalker{source: source}
	if err := walker.validate(root, "$", 1); err != nil {
		return nil, err
	}
	if err := validateV8YAMLVersion(source, root); err != nil {
		return nil, err
	}
	if err := rejectV8YAMLLegacyKeys(source, root); err != nil {
		return nil, err
	}
	plainValue, err := projectV8YAML(source, root, "$")
	if err != nil {
		return nil, err
	}
	plain, ok := plainValue.(map[string]any)
	if !ok { // Defensive: root shape was already checked.
		return nil, v8Error(source, V8YAMLErrorRootMappingRequired, "$", root,
			"the YAML root must project to an object", "use top-level string keys")
	}
	return &V8YAMLDocument{Source: source, Document: &document, Plain: plain}, nil
}

type v8YAMLWalker struct {
	source string
	nodes  int
}

func (w *v8YAMLWalker) validate(node *yaml.Node, path string, depth int) error {
	if node == nil {
		return nil
	}
	w.nodes++
	if w.nodes > V8YAMLMaxNodes {
		return v8Error(w.source, V8YAMLErrorNodeLimit, path, node,
			"parsed YAML exceeds the 65,536-node limit", "reduce repeated mappings and sequences")
	}
	if node.Kind == yaml.AliasNode {
		return v8Error(w.source, V8YAMLErrorAliasForbidden, path, node,
			"YAML aliases are not allowed in v8 configuration", "replace the alias with explicit configuration")
	}
	if v8YAMLIsMerge(node) {
		return v8Error(w.source, V8YAMLErrorMergeKeyForbidden, path, node,
			"YAML merge keys are not allowed in v8 configuration", "write every merged key explicitly")
	}
	if !v8YAMLTagAllowed(node) {
		return v8Error(w.source, V8YAMLErrorCustomTagForbidden, path, node,
			"custom or unsupported YAML tags are not allowed in v8 configuration",
			"use ordinary mappings, sequences, and scalar values")
	}

	switch node.Kind {
	case yaml.MappingNode:
		if depth > V8YAMLMaxDepth {
			return v8Error(w.source, V8YAMLErrorDepthLimit, path, node,
				"YAML nesting exceeds the depth limit of 32", "flatten the configuration structure")
		}
		entries := len(node.Content) / 2
		if entries > V8YAMLMaxMappingEntries {
			return v8Error(w.source, V8YAMLErrorMappingEntriesLimit, path, node,
				"a YAML mapping exceeds the 1,024-entry limit", "reduce the number of entries in this mapping")
		}
		seen := make(map[string]*yaml.Node, entries)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			if v8YAMLIsMerge(key) {
				return v8Error(w.source, V8YAMLErrorMergeKeyForbidden, path, key,
					"YAML merge keys are not allowed in v8 configuration", "write every merged key explicitly")
			}
			// Report aliases/custom tags with their specific code before the
			// more general string-key diagnostic.
			if key.Kind == yaml.AliasNode || !v8YAMLTagAllowed(key) {
				if err := w.validate(key, path, depth); err != nil {
					return err
				}
			}
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" {
				return v8Error(w.source, V8YAMLErrorMappingKeyInvalid, path, key,
					"configuration mapping keys must be strings", "replace the key with a plain or quoted string")
			}
			keyPath := v8YAMLChildPath(path, key.Value)
			if err := w.validate(key, keyPath, depth); err != nil {
				return err
			}
			if first, exists := seen[key.Value]; exists {
				return v8Error(w.source, V8YAMLErrorDuplicateKey, keyPath, key,
					fmt.Sprintf("duplicate mapping key; the first definition is at line %d, column %d", first.Line, first.Column),
					"remove one definition so precedence is unambiguous")
			}
			seen[key.Value] = key
			childDepth := depth
			if v8YAMLContainer(value) {
				childDepth++
			}
			if err := w.validate(value, keyPath, childDepth); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		if depth > V8YAMLMaxDepth {
			return v8Error(w.source, V8YAMLErrorDepthLimit, path, node,
				"YAML nesting exceeds the depth limit of 32", "flatten the configuration structure")
		}
		for index, child := range node.Content {
			childDepth := depth
			if v8YAMLContainer(child) {
				childDepth++
			}
			if err := w.validate(child, fmt.Sprintf("%s[%d]", path, index), childDepth); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		// Scalar domain constraints belong to the later JSON Schema stage.
	default:
		return v8Error(w.source, V8YAMLErrorSyntax, path, node,
			"unsupported YAML node kind", "use ordinary mappings, sequences, and scalar values")
	}
	return nil
}

func validateV8YAMLVersion(source string, root *yaml.Node) error {
	value := v8YAMLMapValue(root, "config_version")
	if value == nil {
		return v8Error(source, V8YAMLErrorVersionRequired, "$.config_version", root,
			"config_version is required by the v8 configuration entrypoint",
			"run defenseclaw upgrade to create a config_version: 8 source")
	}
	if value.Kind != yaml.ScalarNode || value.ShortTag() != "!!int" {
		return v8Error(source, V8YAMLErrorVersionInvalid, "$.config_version", value,
			"config_version must be the integer 8",
			"set config_version: 8 only after completing the DefenseClaw upgrade")
	}
	var version int64
	if err := value.Decode(&version); err != nil {
		return v8Error(source, V8YAMLErrorVersionInvalid, "$.config_version", value,
			"config_version must be the integer 8", "run defenseclaw upgrade to create a valid v8 source")
	}
	switch {
	case version == v8YAMLConfigVersion:
		return nil
	case version >= 0 && version < v8YAMLConfigVersion:
		return v8Error(source, V8YAMLErrorVersionUpgrade, "$.config_version", value,
			"this configuration requires the v7-to-v8 upgrade", "run defenseclaw upgrade before starting a v8 gateway")
	case version > v8YAMLConfigVersion:
		return v8Error(source, V8YAMLErrorVersionUnsupported, "$.config_version", value,
			"this configuration version is newer than the supported v8 contract",
			"use a DefenseClaw build that supports the newer configuration")
	default:
		return v8Error(source, V8YAMLErrorVersionInvalid, "$.config_version", value,
			"config_version must be the integer 8", "run defenseclaw upgrade to create a valid v8 source")
	}
}

func rejectV8YAMLLegacyKeys(source string, root *yaml.Node) error {
	for _, legacy := range []struct{ key, target string }{
		{"otel", "observability resource, policies, and destinations"},
		{"audit_sinks", "observability.destinations"},
		{"audit_db", "observability.local.path"},
		{"judge_bodies_db", "observability.local.judge_bodies_path"},
	} {
		if node := v8YAMLMapValue(root, legacy.key); node != nil {
			return v8YAMLLegacyError(source, v8YAMLChildPath("$", legacy.key), node, legacy.target)
		}
	}
	if privacy := v8YAMLMapValue(root, "privacy"); privacy != nil && privacy.Kind == yaml.MappingNode {
		if node := v8YAMLMapValue(privacy, "disable_redaction"); node != nil {
			return v8YAMLLegacyError(source, "$.privacy.disable_redaction", node,
				"observability defaults, bucket policies, and destination routes")
		}
	}
	if discovery := v8YAMLMapValue(root, "ai_discovery"); discovery != nil && discovery.Kind == yaml.MappingNode {
		if node := v8YAMLMapValue(discovery, "emit_otel"); node != nil {
			return v8YAMLLegacyError(source, "$.ai_discovery.emit_otel", node,
				"the ai.discovery bucket and destination routing policy")
		}
	}
	if node := v8YAMLMapValue(root, "splunk"); node != nil {
		return v8YAMLLegacyError(source, "$.splunk", node, "an observability destination with kind: splunk_hec")
	}

	observability := v8YAMLMapValue(root, "observability")
	if observability == nil || observability.Kind != yaml.MappingNode {
		return nil
	}
	connectors := v8YAMLMapValue(observability, "connectors")
	if connectors == nil || connectors.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(connectors.Content); index += 2 {
		name, connector := connectors.Content[index], connectors.Content[index+1]
		if name.Kind != yaml.ScalarNode || connector.Kind != yaml.MappingNode {
			continue
		}
		if node := v8YAMLMapValue(connector, "audit_sinks"); node != nil {
			path := v8YAMLChildPath("$.observability.connectors", name.Value) + ".audit_sinks"
			return v8YAMLLegacyError(source, path, node, "observability destinations with connector selectors")
		}
	}
	return nil
}

func v8YAMLLegacyError(source, path string, node *yaml.Node, target string) error {
	return v8Error(source, V8YAMLErrorLegacyKeyForbidden, path, node,
		"a legacy v7 configuration key is not accepted by the v8 entrypoint",
		"run defenseclaw upgrade; use "+target)
}

func projectV8YAML(source string, node *yaml.Node, path string) (any, error) {
	switch node.Kind {
	case yaml.MappingNode:
		result := make(map[string]any, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			childPath := v8YAMLChildPath(path, key.Value)
			projected, err := projectV8YAML(source, value, childPath)
			if err != nil {
				return nil, err
			}
			result[key.Value] = projected
		}
		return result, nil
	case yaml.SequenceNode:
		result := make([]any, len(node.Content))
		for index, child := range node.Content {
			projected, err := projectV8YAML(source, child, fmt.Sprintf("%s[%d]", path, index))
			if err != nil {
				return nil, err
			}
			result[index] = projected
		}
		return result, nil
	case yaml.ScalarNode:
		return projectV8YAMLScalar(source, node, path)
	default:
		return nil, v8Error(source, V8YAMLErrorSyntax, path, node,
			"unsupported YAML node kind", "use ordinary mappings, sequences, and scalar values")
	}
}

func projectV8YAMLScalar(source string, node *yaml.Node, path string) (any, error) {
	switch node.ShortTag() {
	case "!!null":
		return nil, nil
	case "!!str", "!!timestamp", "!!binary":
		return node.Value, nil
	case "!!bool":
		var value bool
		if err := node.Decode(&value); err == nil {
			return value, nil
		}
	case "!!int":
		var value any
		if err := node.Decode(&value); err == nil {
			switch value.(type) {
			case int, int64, uint64:
				return value, nil
			}
		}
	case "!!float":
		var value float64
		if err := node.Decode(&value); err == nil && !math.IsNaN(value) && !math.IsInf(value, 0) {
			return value, nil
		}
	}
	return nil, v8Error(source, V8YAMLErrorScalarInvalid, path, node,
		"YAML scalar cannot be represented safely for schema validation",
		"use a finite string, Boolean, integer, number, or null value")
}

func v8YAMLTagAllowed(node *yaml.Node) bool {
	if node == nil || node.Kind == yaml.DocumentNode || node.Kind == yaml.AliasNode {
		return true
	}
	switch node.ShortTag() {
	case "!!map", "!!seq", "!!str", "!!null", "!!bool", "!!int", "!!float", "!!timestamp", "!!binary":
		return true
	default:
		return false
	}
}

func v8YAMLIsMerge(node *yaml.Node) bool {
	return node != nil && (node.ShortTag() == "!!merge" || (node.Kind == yaml.ScalarNode && node.Value == "<<"))
}

func v8YAMLContainer(node *yaml.Node) bool {
	return node != nil && (node.Kind == yaml.MappingNode || node.Kind == yaml.SequenceNode)
}

func v8DocumentRoot(document *yaml.Node) *yaml.Node {
	if document == nil {
		return nil
	}
	if document.Kind != yaml.DocumentNode {
		return document
	}
	if len(document.Content) == 0 {
		return nil
	}
	return document.Content[0]
}

func v8YAMLMapValue(mapping *yaml.Node, key string) *yaml.Node {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Kind == yaml.ScalarNode && mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	return nil
}

func v8YAMLChildPath(parent, key string) string {
	if v8YAMLSimplePathKey(key) {
		return parent + "." + key
	}
	return parent + "[" + strconv.Quote(key) + "]"
}

func v8YAMLSimplePathKey(key string) bool {
	if key == "" {
		return false
	}
	for index, char := range key {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char == '_' ||
			(index > 0 && char >= '0' && char <= '9') || (index > 0 && char == '-') {
			continue
		}
		return false
	}
	return true
}

func v8Error(source string, code V8YAMLErrorCode, path string, node *yaml.Node, summary, action string) *V8YAMLError {
	result := &V8YAMLError{Code: code, Source: source, Path: path, Summary: summary, Action: action}
	if node != nil {
		result.Line, result.Column = node.Line, node.Column
	}
	return result
}

var v8YAMLSyntaxLine = regexp.MustCompile(`(?:^|[ :])line ([0-9]+)(?:[ :]|$)`)

func v8SyntaxError(source string, cause error) error {
	line := 0
	if cause != nil {
		if match := v8YAMLSyntaxLine.FindStringSubmatch(cause.Error()); len(match) == 2 {
			line, _ = strconv.Atoi(match[1])
		}
	}
	return &V8YAMLError{
		Code: V8YAMLErrorSyntax, Source: source, Path: "$", Line: line,
		Summary: "configuration source is not valid YAML", Action: "correct the YAML syntax and retry",
	}
}
