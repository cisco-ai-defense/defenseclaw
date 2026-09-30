// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package packs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// decodeStrict decodes exactly one YAML document into out after checking the
// node tree against out's type. Like the guardrail rule-pack loader it closes
// what yaml.v3 leaves open: unknown keys, duplicate keys, scalar coercions
// (an integer into a string field), null values, and anchors, aliases and
// merge keys (which also rules out alias-expansion bombs).
func decodeStrict(data []byte, source string, out any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return packErr(source, "", "yaml_empty", "the file contains no YAML document")
		}
		return packErr(source, "", "yaml_invalid", "%s", strings.TrimPrefix(err.Error(), "yaml: "))
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return packErr(source, "", "yaml_documents", "the file must contain exactly one YAML document")
	}
	root := &document
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	if err := checkNode(root, reflect.TypeOf(out).Elem(), "", source); err != nil {
		return err
	}
	if err := root.Decode(out); err != nil {
		return packErr(source, "", "yaml_invalid", "%s", strings.TrimPrefix(err.Error(), "yaml: "))
	}
	return nil
}

func checkNode(node *yaml.Node, expected reflect.Type, path, source string) error {
	fail := func(code, format string, args ...any) error {
		field := path
		return packErr(source, field, code, "line %d: %s", node.Line, fmt.Sprintf(format, args...))
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return fail("yaml_alias", "anchors and aliases are not allowed")
	}
	for expected.Kind() == reflect.Pointer {
		expected = expected.Elem()
	}
	if node.Kind == yaml.ScalarNode && node.ShortTag() == "!!null" {
		return fail("yaml_type", "must not be null")
	}
	switch expected.Kind() {
	case reflect.Struct:
		if node.Kind != yaml.MappingNode {
			return fail("yaml_type", "must be a mapping")
		}
		fields := make(map[string]reflect.Type, expected.NumField())
		for i := 0; i < expected.NumField(); i++ {
			field := expected.Field(i)
			if !field.IsExported() {
				continue
			}
			name := strings.Split(field.Tag.Get("yaml"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			fields[name] = field.Type
		}
		seen := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			child := joinPath(path, key.Value)
			if key.Kind == yaml.ScalarNode && (key.ShortTag() == "!!merge" || key.Value == "<<") {
				return packErr(source, child, "yaml_alias", "line %d: merge keys are not allowed", key.Line)
			}
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" {
				return packErr(source, path, "yaml_type", "line %d: keys must be strings", key.Line)
			}
			if _, dup := seen[key.Value]; dup {
				return packErr(source, child, "yaml_duplicate", "line %d: key is repeated", key.Line)
			}
			seen[key.Value] = struct{}{}
			fieldType, ok := fields[key.Value]
			if !ok {
				return packErr(source, child, "unknown_field", "line %d: unknown key", key.Line)
			}
			if err := checkNode(value, fieldType, child, source); err != nil {
				return err
			}
		}
		return nil
	case reflect.Slice:
		if node.Kind != yaml.SequenceNode {
			return fail("yaml_type", "must be a list")
		}
		for i, item := range node.Content {
			if err := checkNode(item, expected.Elem(), fmt.Sprintf("%s[%d]", path, i), source); err != nil {
				return err
			}
		}
		return nil
	case reflect.String:
		if node.Kind != yaml.ScalarNode || node.ShortTag() != "!!str" {
			return fail("yaml_type", "must be a string")
		}
		return nil
	case reflect.Bool:
		if node.Kind != yaml.ScalarNode || node.ShortTag() != "!!bool" {
			return fail("yaml_type", "must be true or false")
		}
		return nil
	case reflect.Int:
		if node.Kind != yaml.ScalarNode || node.ShortTag() != "!!int" {
			return fail("yaml_type", "must be an integer")
		}
		return nil
	default:
		return fail("yaml_type", "has an unsupported type")
	}
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}
