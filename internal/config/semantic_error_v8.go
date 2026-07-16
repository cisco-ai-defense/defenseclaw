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
	"errors"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var observabilityV8SemanticPathPattern = regexp.MustCompile(`^(observability(?:\.[A-Za-z0-9_.-]+|\[[0-9]+\])*)`)

type V8SemanticError struct {
	Source        string
	Path          string
	Line          int
	Column        int
	ReceivedClass string
	Expected      string
	Summary       string
	Action        string
	cause         error
}

func (e *V8SemanticError) Error() string {
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
	message := source + ": [config_semantic_invalid]"
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
	if e.Action != "" {
		message += "; " + e.Action
	}
	return message
}

func (e *V8SemanticError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func annotateObservabilityV8SemanticError(document *V8YAMLDocument, err error) error {
	if err == nil {
		return nil
	}
	var schemaError *V8SchemaError
	var yamlError *V8YAMLError
	var semanticError *V8SemanticError
	if errors.As(err, &schemaError) || errors.As(err, &yamlError) || errors.As(err, &semanticError) {
		return err
	}
	path := observabilityV8SemanticErrorPath(err)
	node := observabilityV8YAMLNodeAtPath(document, path)
	result := &V8SemanticError{
		Path:          path,
		ReceivedClass: v8SchemaNodeClass(node),
		Expected:      "the documented semantic constraint at this path",
		Summary:       "configuration violates a semantic v8 constraint",
		Action:        "inspect the effective-plan validation rule and correct this field",
		cause:         err,
	}
	if document != nil {
		result.Source = document.Source
	}
	if node != nil {
		result.Line, result.Column = node.Line, node.Column
	}
	return result
}

func observabilityV8SemanticErrorPath(err error) string {
	var secretError *V8SecretReferenceError
	if errors.As(err, &secretError) {
		return "$." + secretError.Path
	}
	match := observabilityV8SemanticPathPattern.FindStringSubmatch(err.Error())
	if len(match) != 2 {
		if strings.Contains(err.Error(), "data_dir") || strings.Contains(err.Error(), "DefaultDataDir") {
			return "$.data_dir"
		}
		return "$"
	}
	return "$." + match[1]
}

func observabilityV8YAMLNodeAtPath(document *V8YAMLDocument, displayPath string) *yaml.Node {
	if document == nil || document.Document == nil {
		return nil
	}
	current := v8DocumentRoot(document.Document)
	path := strings.TrimPrefix(displayPath, "$")
	path = strings.TrimPrefix(path, ".")
	for path != "" && current != nil {
		if path[0] == '[' {
			end := strings.IndexByte(path, ']')
			if end < 0 {
				return current
			}
			if current.Kind == yaml.MappingNode {
				key, err := strconv.Unquote(path[1:end])
				if err != nil {
					return current
				}
				next := v8YAMLMapValue(current, key)
				if next == nil {
					return current
				}
				current = next
				path = strings.TrimPrefix(path[end+1:], ".")
				continue
			}
			if current.Kind != yaml.SequenceNode {
				return current
			}
			index, err := strconv.Atoi(path[1:end])
			if err != nil || index < 0 || index >= len(current.Content) {
				return current
			}
			current = current.Content[index]
			path = strings.TrimPrefix(path[end+1:], ".")
			continue
		}
		if current.Kind != yaml.MappingNode {
			return current
		}
		next, consumed := observabilityV8YAMLMapValueAtPath(current, path)
		if next == nil {
			return current
		}
		current = next
		path = strings.TrimPrefix(path[consumed:], ".")
	}
	return current
}

func observabilityV8YAMLMapValueAtPath(mapping *yaml.Node, path string) (*yaml.Node, int) {
	if mapping == nil || mapping.Kind != yaml.MappingNode || path == "" {
		return nil, 0
	}
	bestLength := 0
	var best *yaml.Node
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		key := mapping.Content[index]
		if key.Kind != yaml.ScalarNode || len(key.Value) <= bestLength || !strings.HasPrefix(path, key.Value) {
			continue
		}
		if len(path) > len(key.Value) && path[len(key.Value)] != '.' && path[len(key.Value)] != '[' {
			continue
		}
		bestLength = len(key.Value)
		best = mapping.Content[index+1]
	}
	return best, bestLength
}
