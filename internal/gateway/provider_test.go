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

package gateway

import (
	"testing"
)

func TestSplitModelKnownPrefixes(t *testing.T) {
	tests := []struct {
		input     string
		wantProv  string
		wantModel string
	}{
		{"openai/gpt-4o", "openai", "gpt-4o"},
		{"anthropic/claude-opus-4-5", "anthropic", "claude-opus-4-5"},
		{"openrouter/anthropic/claude-opus-4-5", "openrouter", "anthropic/claude-opus-4-5"},
		{"azure/gpt-4o", "azure", "gpt-4o"},
		{"gemini/gemini-2.0-flash", "gemini", "gemini-2.0-flash"},
		{"gemini-openai/gemini-2.0-flash", "gemini-openai", "gemini-2.0-flash"},
		{"unknown/foo", "", "unknown/foo"},
		{"gpt-4o", "", "gpt-4o"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			prov, model := splitModel(tt.input)
			if prov != tt.wantProv || model != tt.wantModel {
				t.Errorf("splitModel(%q) = (%q, %q), want (%q, %q)",
					tt.input, prov, model, tt.wantProv, tt.wantModel)
			}
		})
	}
}

func TestInferProviderNew(t *testing.T) {
	tests := []struct {
		model  string
		apiKey string
		want   string
	}{
		{"claude-opus-4-5", "", "anthropic"},
		{"gpt-4o", "", "openai"},
		{"gemini-2.0-flash", "", "gemini"},
		{"anything", "AIzaSyExample", "gemini"},
		{"anything", "sk-ant-api123", "anthropic"},
		{"anything", "sk-proj-abc", "openai"},
	}
	for _, tt := range tests {
		t.Run(tt.model+"_"+tt.apiKey, func(t *testing.T) {
			got := inferProvider(tt.model, tt.apiKey)
			if got != tt.want {
				t.Errorf("inferProvider(%q, %q) = %q, want %q", tt.model, tt.apiKey, got, tt.want)
			}
		})
	}
}
