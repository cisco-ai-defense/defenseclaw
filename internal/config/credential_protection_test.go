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

import "testing"

func TestCredentialProtectionDefaultsDisabled(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.CredentialProtection.Enabled {
		t.Fatal("CredentialProtection.Enabled = true, want false")
	}
}

func TestCredentialProtectionV8Decode(t *testing.T) {
	raw := []byte("config_version: 8\ncredential_protection:\n  enabled: true\nobservability: {}\n")
	cfg, err := LoadRuntimeV8FromBytes("config.yaml", raw)
	if err != nil {
		t.Fatalf("LoadRuntimeV8FromBytes: %v", err)
	}
	if !cfg.CredentialProtection.Enabled {
		t.Fatal("CredentialProtection.Enabled = false, want true")
	}
}
