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

package config

import (
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ValidateCandidate runs the canonical validator on candidate config bytes
// for configFile before any writer installs them: the strict YAML and JSON
// Schema pass, the observability compiler and the runtime decode (which
// includes the guardrail profile checks). It reads nothing but raw.
func ValidateCandidate(configFile string, raw []byte) error {
	document, err := ParseV8YAML(configFile, raw)
	if err != nil {
		return err
	}
	dataDir := DefaultDataPath()
	if value, ok := document.Plain["data_dir"].(string); ok && strings.TrimSpace(value) != "" {
		dataDir = strings.TrimSpace(value)
	}
	if _, err := ParseCompileObservabilityV8(configFile, raw, ObservabilityV8CompileOptions{DefaultDataDir: dataDir}); err != nil {
		return err
	}
	_, err = LoadRuntimeV8InspectionCandidateFromBytes(configFile, raw)
	return err
}

// StandaloneManagedSource reports whether config bytes describe a managed
// deployment on the standalone enterprise profile. The document and the
// DEFENSECLAW_DEPLOYMENT_MODE environment each count: an environment value
// can not turn a managed document back into a local one. Unparseable bytes
// report false; the validator rejects them anyway.
func StandaloneManagedSource(raw []byte) bool {
	var document yaml.Node
	if err := yaml.Unmarshal(raw, &document); err != nil {
		return standaloneManagedDocument(runtime.GOOS, &yaml.Node{Kind: yaml.MappingNode})
	}
	root := v8DocumentRoot(&document)
	if root == nil || root.Kind != yaml.MappingNode {
		root = &yaml.Node{Kind: yaml.MappingNode}
	}
	if standaloneManagedDocument(runtime.GOOS, root) {
		return true
	}
	mode := normalizeDeploymentMode(yamlScalarValue(v8YAMLMapValue(root, "deployment_mode")))
	if !managed.IsManagedEnterprise(mode) {
		return false
	}
	declared := yamlScalarValue(v8YAMLMapValue(v8YAMLMapValue(root, "enterprise"), "profile"))
	profile, err := managed.ResolveEnterpriseProfile(runtime.GOOS, mode, "", declared)
	return err == nil && managed.IsStandaloneProfile(profile)
}
