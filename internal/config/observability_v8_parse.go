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
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type ObservabilityV8CompileOptions struct {
	DefaultDataDir      string
	ConfiguredFilePaths []string
	Secrets             ObservabilityV8SecretResolver
}

type ObservabilityV8CompiledConfig struct {
	DataDir       string
	Observability ObservabilityV8Source
	Plan          *ObservabilityV8Plan
}

type observabilityV8ConfigEnvelope struct {
	ConfigVersion int                    `yaml:"config_version"`
	DataDir       string                 `yaml:"data_dir,omitempty"`
	Observability *ObservabilityV8Source `yaml:"observability,omitempty"`
}

func ParseCompileObservabilityV8(
	sourceName string,
	data []byte,
	options ObservabilityV8CompileOptions,
) (*ObservabilityV8CompiledConfig, error) {
	document, err := ParseV8YAML(sourceName, data)
	if err != nil {
		return nil, err
	}
	if err := validateV8Schema(sourceName, document); err != nil {
		return nil, err
	}
	var envelope observabilityV8ConfigEnvelope
	if err := document.Document.Decode(&envelope); err != nil {
		return nil, annotateObservabilityV8SemanticError(document, fmt.Errorf("config: typed v8 decode failed: %w", err))
	}
	dataDir := strings.TrimSpace(envelope.DataDir)
	if dataDir == "" {
		dataDir = strings.TrimSpace(options.DefaultDataDir)
	}
	if dataDir == "" {
		return nil, annotateObservabilityV8SemanticError(document, fmt.Errorf("config: v8 compilation requires a data_dir or explicit DefaultDataDir option"))
	}
	dataDir, err = normalizeObservabilityV8FilePath("data_dir", dataDir)
	if err != nil {
		return nil, annotateObservabilityV8SemanticError(document, err)
	}
	source := ObservabilityV8Source{}
	if envelope.Observability != nil {
		source = *envelope.Observability
	}
	if source.Local.Path == "" {
		source.Local.Path = filepath.Join(dataDir, DefaultAuditDBName)
		source.localPathDefaulted = true
	}
	if source.Local.JudgeBodiesPath == "" {
		source.Local.JudgeBodiesPath = filepath.Join(dataDir, DefaultJudgeBodiesDBName)
		source.judgePathDefaulted = true
	}
	configuredFiles := append([]string(nil), options.ConfiguredFilePaths...)
	if observabilityV8SourceNameIsPath(sourceName) {
		configuredFiles = append(configuredFiles, sourceName)
	}
	if err := validateObservabilityV8FilePaths(&source, configuredFiles); err != nil {
		return nil, annotateObservabilityV8SemanticError(document, err)
	}
	if err := normalizeObservabilityV8EffectiveFilePaths(&source); err != nil {
		return nil, annotateObservabilityV8SemanticError(document, err)
	}
	if err := validateObservabilityV8Secrets(&source, options.Secrets); err != nil {
		return nil, annotateObservabilityV8SemanticError(document, err)
	}
	plan, err := CompileObservabilityV8(&source)
	if err != nil {
		return nil, annotateObservabilityV8SemanticError(document, err)
	}
	plan, err = addObservabilityV8SourceProvenance(plan, document)
	if err != nil {
		return nil, annotateObservabilityV8SemanticError(document, err)
	}
	return &ObservabilityV8CompiledConfig{
		DataDir:       dataDir,
		Observability: source,
		Plan:          plan,
	}, nil
}

func addObservabilityV8SourceProvenance(
	plan *ObservabilityV8Plan,
	document *V8YAMLDocument,
) (*ObservabilityV8Plan, error) {
	if plan == nil || document == nil {
		return plan, nil
	}
	effective := cloneObservabilityV8EffectivePlan(plan.effective)
	baseProvenance := make([]ObservabilityV8Provenance, 0, len(effective.Provenance))
	for _, provenance := range effective.Provenance {
		if provenance.ValuePath == "" {
			baseProvenance = append(baseProvenance, provenance)
		}
	}
	effective.Provenance = baseProvenance
	existing := make(map[string]int, len(effective.Provenance))
	for index := range effective.Provenance {
		existing[effective.Provenance[index].Path] = index
	}
	root := v8DocumentRoot(document.Document)
	observabilityNode := v8YAMLMapValue(root, "observability")
	var walk func(*yaml.Node, string)
	walk = func(node *yaml.Node, path string) {
		if node == nil {
			return
		}
		switch node.Kind {
		case yaml.MappingNode:
			for index := 0; index+1 < len(node.Content); index += 2 {
				key, value := node.Content[index], node.Content[index+1]
				walk(value, v8YAMLChildPath(path, key.Value))
			}
		case yaml.SequenceNode:
			for index, value := range node.Content {
				walk(value, fmt.Sprintf("%s[%d]", path, index))
			}
		case yaml.ScalarNode:
			provenance := ObservabilityV8Provenance{
				Path: path, Origin: "source", Source: document.Source,
				Line: node.Line, Column: node.Column,
			}
			if index, ok := existing[path]; ok {
				effective.Provenance[index].Source = provenance.Source
				effective.Provenance[index].Line = provenance.Line
				effective.Provenance[index].Column = provenance.Column
				if effective.Provenance[index].Origin == "compiled-default" {
					effective.Provenance[index].Origin = "source"
				}
				return
			}
			existing[path] = len(effective.Provenance)
			effective.Provenance = append(effective.Provenance, provenance)
		}
	}
	walk(observabilityNode, "observability")
	sort.SliceStable(effective.Provenance, func(left, right int) bool {
		if effective.Provenance[left].Path != effective.Provenance[right].Path {
			return effective.Provenance[left].Path < effective.Provenance[right].Path
		}
		return effective.Provenance[left].Origin < effective.Provenance[right].Origin
	})
	return newObservabilityV8Plan(effective)
}

func observabilityV8SourceNameIsPath(sourceName string) bool {
	trimmed := strings.TrimSpace(sourceName)
	return trimmed != "" && !strings.HasPrefix(trimmed, "<") && !strings.Contains(trimmed, "://")
}
