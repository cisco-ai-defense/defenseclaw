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

package inventory

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed ai_signatures.json
var aiSignatureFS embed.FS

const aiSignatureCatalogVersion = 1

// AISignature describes one known AI surface or provider family. It is the
// shared source used by the continuous sidecar scanner and the Python CLI
// rendering/tests. Keep the JSON shape intentionally primitive so other
// runtimes can consume it without linking Go code.
type AISignature struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Vendor             string   `json:"vendor"`
	Category           string   `json:"category"`
	Confidence         float64  `json:"confidence"`
	SupportedConnector string   `json:"supported_connector,omitempty"`
	BinaryNames        []string `json:"binary_names,omitempty"`
	ProcessNames       []string `json:"process_names,omitempty"`
	ApplicationNames   []string `json:"application_names,omitempty"`
	ConfigPaths        []string `json:"config_paths,omitempty"`
	ExtensionIDs       []string `json:"extension_ids,omitempty"`
	MCPPaths           []string `json:"mcp_paths,omitempty"`
	PackageNames       []string `json:"package_names,omitempty"`
	EnvVarNames        []string `json:"env_var_names,omitempty"`
	DomainPatterns     []string `json:"domain_patterns,omitempty"`
	HistoryPatterns    []string `json:"history_patterns,omitempty"`
	LocalEndpoints     []string `json:"local_endpoints,omitempty"`
}

type aiSignatureCatalog struct {
	Version   int           `json:"version"`
	Signature []AISignature `json:"signatures"`
}

// LoadAISignatures returns the embedded catalog after basic validation.
func LoadAISignatures() ([]AISignature, error) {
	raw, err := aiSignatureFS.ReadFile("ai_signatures.json")
	if err != nil {
		return nil, fmt.Errorf("ai signature catalog: read embedded catalog: %w", err)
	}
	var cat aiSignatureCatalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		return nil, fmt.Errorf("ai signature catalog: parse: %w", err)
	}
	if cat.Version != aiSignatureCatalogVersion {
		return nil, fmt.Errorf("ai signature catalog: unsupported version %d", cat.Version)
	}
	seen := map[string]bool{}
	for i := range cat.Signature {
		normalizeAISignature(&cat.Signature[i])
		if err := validateAISignature(cat.Signature[i]); err != nil {
			return nil, err
		}
		if seen[cat.Signature[i].ID] {
			return nil, fmt.Errorf("ai signature catalog: duplicate id %q", cat.Signature[i].ID)
		}
		seen[cat.Signature[i].ID] = true
	}
	return cat.Signature, nil
}

func normalizeAISignature(sig *AISignature) {
	sig.ID = normalizeAIID(sig.ID)
	sig.Category = normalizeAIID(sig.Category)
	sig.SupportedConnector = normalizeAIID(sig.SupportedConnector)
	sig.Name = strings.TrimSpace(sig.Name)
	sig.Vendor = strings.TrimSpace(sig.Vendor)
	if sig.Confidence <= 0 {
		sig.Confidence = 0.5
	}
	if sig.Confidence > 1 {
		sig.Confidence = 1
	}
}

func validateAISignature(sig AISignature) error {
	if sig.ID == "" {
		return fmt.Errorf("ai signature catalog: id is required")
	}
	if sig.Name == "" {
		return fmt.Errorf("ai signature catalog: %s: name is required", sig.ID)
	}
	if sig.Vendor == "" {
		return fmt.Errorf("ai signature catalog: %s: vendor is required", sig.ID)
	}
	if sig.Category == "" {
		return fmt.Errorf("ai signature catalog: %s: category is required", sig.ID)
	}
	return nil
}

func normalizeAIID(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.ReplaceAll(value, "_", "-")
	return value
}
