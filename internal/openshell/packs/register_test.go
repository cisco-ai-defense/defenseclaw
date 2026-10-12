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

//go:build !windows

package packs

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestProfilePackCheckIsTheConfigHook pins the registration: every process
// that links the resolver checks profile packs at configuration load, and
// the hook refuses a profile pack looser than the base pack.
func TestProfilePackCheckIsTheConfigHook(t *testing.T) {
	if config.SandboxProfilePackCheck == nil {
		t.Fatal("config.SandboxProfilePackCheck is not registered")
	}
	if err := config.SandboxProfilePackCheck(testConfig(nil), "balanced", "open", ""); err == nil {
		t.Fatal("the registered hook accepts a profile pack looser than the base pack")
	}
	if err := config.SandboxProfilePackCheck(testConfig(nil), "balanced", "strict", ""); err != nil {
		t.Fatalf("the registered hook refuses a tighter profile pack: %v", err)
	}
}
