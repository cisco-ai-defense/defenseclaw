// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package configs

import (
	_ "embed"
	"encoding/json"
)

//go:embed providers.json
var providersJSON []byte

// Provider describes a single LLM provider: its canonical name, the domain
// substrings used to identify outbound requests, and the OpenClaw
// auth-profiles.json profile ID used to look up the API key.
type Provider struct {
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	ProfileID *string  `json:"profile_id"` // nil when no auth-profile exists (e.g. bedrock)
	EnvKeys   []string `json:"env_keys"`   // env var names for the API key, checked in order
}

// ProvidersConfig is the top-level structure of providers.json.
type ProvidersConfig struct {
	Providers  []Provider `json:"providers"`
	OllamaPorts []int     `json:"ollama_ports"`
}

// LoadProviders parses the embedded providers.json.
func LoadProviders() (*ProvidersConfig, error) {
	var cfg ProvidersConfig
	if err := json.Unmarshal(providersJSON, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
