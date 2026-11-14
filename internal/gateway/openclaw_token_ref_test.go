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
)

// OC review 3 P1-1: an openclaw.json SecretRef must not make the gateway
// send one of its own credentials to OpenClaw.
func TestOpenClawEnvRefRefusesDefenseClawCredentials(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("CUSTOM_JUDGE_TOKEN=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	openClawDataDir.Store(&dir)
	t.Cleanup(func() { empty := ""; openClawDataDir.Store(&empty) })
	for name, want := range map[string]bool{
		"OPENCLAW_GATEWAY_TOKEN":    true,
		"MY_OPENCLAW_TOKEN":         true,
		"DEFENSECLAW_GATEWAY_TOKEN": false,
		"ANTHROPIC_API_KEY":         false,
		"AWS_SECRET_ACCESS_KEY":     false,
		"CUSTOM_JUDGE_TOKEN":        false,
		"bad name":                  false,
	} {
		if got := openClawEnvRefAllowed(name); got != want {
			t.Errorf("openClawEnvRefAllowed(%q) = %v, want %v", name, got, want)
		}
	}
	account := "openclaw"
	openClawListenerAccount.Store(&account)
	t.Cleanup(func() { empty := ""; openClawListenerAccount.Store(&empty) })
	if openClawEnvRefAllowed("MY_OPENCLAW_TOKEN") {
		t.Fatal("a reference was resolved in the separate-user layout")
	}
}
