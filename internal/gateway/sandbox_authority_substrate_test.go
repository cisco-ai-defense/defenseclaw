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

package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// A Substrate-only floor refuses an OpenShell sandbox on the computer with
// the launcher command, and explain names the runtimes.
func TestSandboxAuthoritySubstrateOnlyRefusesASandboxHere(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-devs")
	p := f.cfg.Guardrail.Profiles["engineering"]
	p.Sandbox = &config.SandboxAdminConfig{RequiredFor: []string{"claudecode"}, Runtimes: []string{config.SandboxRuntimeSubstrate}}
	f.cfg.Guardrail.Profiles["engineering"] = p
	rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, claudeResolve(),
		map[string]string{sandboxrelay.ConnectorHeader: "claudecode"})
	var body struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusForbidden || errorReason(t, rec) != sandboxrelay.ReasonNotAllowed ||
		body.Message != sandboxapi.SandboxRunSubstrateOnly("claudecode", "engineering") {
		t.Fatalf("resolve under runtimes [substrate]: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(body.Message, "defenseclaw substrate run claude") {
		t.Fatalf("refusal lacks the launcher command: %q", body.Message)
	}
}
