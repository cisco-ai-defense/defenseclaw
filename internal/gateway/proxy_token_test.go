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
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestNewGuardrailProxyUsesResolvedSidecarTokenWithoutDotenvMutation(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")

	proxy, err := NewGuardrailProxy(
		&config.GuardrailConfig{ScannerMode: "local"},
		&config.CiscoAIDefenseConfig{},
		nil,
		NewSidecarHealth(),
		nil,
		dataDir,
		"resolved-inline-token",
		"",
		nil,
		nil,
		config.LLMConfig{},
		nil,
	)
	if err != nil {
		t.Fatalf("NewGuardrailProxy: %v", err)
	}
	if got := proxy.gatewayToken; got != "resolved-inline-token" {
		t.Fatalf("proxy gateway token = %q, want resolved sidecar token", got)
	}
	if _, err := os.Stat(filepath.Join(dataDir, ".env")); !os.IsNotExist(err) {
		t.Fatalf("proxy constructor created or could not inspect dotenv: %v", err)
	}
}

func TestNewGuardrailProxyRejectsMissingResolvedToken(t *testing.T) {
	_, err := NewGuardrailProxy(
		&config.GuardrailConfig{ScannerMode: "local"},
		&config.CiscoAIDefenseConfig{},
		nil,
		NewSidecarHealth(),
		nil,
		t.TempDir(),
		"  ",
		"",
		nil,
		nil,
		config.LLMConfig{},
		nil,
	)
	if err == nil {
		t.Fatal("NewGuardrailProxy accepted an empty resolved gateway token")
	}
}
