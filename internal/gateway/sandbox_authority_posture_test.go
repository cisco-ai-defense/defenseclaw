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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// postureCarol is in no group: the default profile (offline-floor) applies.
var postureCarol = managedHookPeer{UID: 94404099, Name: "ent-carol"}

// postureFixture is a managed computer whose contractors profile requires
// the strict pack, whose default profile (offline-floor) requires at least
// the strict profile, and whose engineering profile asks for skip-permissions
// under a base that forbids it.
func postureFixture(t *testing.T) *sandboxFixture {
	t.Helper()
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	off, on := false, true
	f.cfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	f.cfg.OpenShell.Admin.AllowYolo = &off
	f.cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"contractors":   {Description: "Contractors", Sandbox: &config.OpenShellAdminConfig{RequiredPack: "strict"}},
		"engineering":   {Description: "Engineering", Sandbox: &config.OpenShellAdminConfig{AllowYolo: &on, EgressAllowOnly: []string{"github.com"}}},
		"offline-floor": {Description: "Offline floor", Sandbox: &config.OpenShellAdminConfig{MinProfile: "strict"}},
	}
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	f.setGroups(sbxBob, "dc-sbx-devs")
	f.setGroups(postureCarol)
	return f
}

func postureExplain(t *testing.T, f *sandboxFixture, peer managedHookPeer, req sandboxrelay.ExplainRequest) sandboxapi.ManagedExplain {
	t.Helper()
	req.V, req.Connector = 1, "claudecode"
	rec := f.do(peer, http.MethodPost, sandboxrelay.PathPolicyExplain, req, nil)
	var out sandboxapi.ManagedExplain
	if err := json.Unmarshal(rec.Body.Bytes(), &out); rec.Code != http.StatusOK || err != nil || out.Posture == nil {
		t.Fatalf("explain for %s: %d %s", peer.Name, rec.Code, rec.Body.String())
	}
	return out
}

// GAP-0179, GAP-0438, GAP-0487: the explain of a new run carries the
// authoritative posture under the caller's own floor: the required pack,
// the profile minimum, and balanced where the profile names no pack.
func TestSandboxExplainPostureIsTheCallersFloor(t *testing.T) {
	f := postureFixture(t)
	for _, tc := range []struct {
		peer                    managedHookPeer
		pack, profile, approval string
	}{
		{sbxAlice, "strict", "strict", "manual"},
		{sbxBob, "balanced", "balanced", "triage"},
		{postureCarol, "balanced", "strict", "manual"},
	} {
		p := postureExplain(t, f, tc.peer, sandboxrelay.ExplainRequest{}).Posture
		if p.Pack != tc.pack || p.Profile != tc.profile || p.Approvals != tc.approval || p.PackSource != "builtin:"+tc.pack {
			t.Errorf("%s: pack %s (%s) profile %s approvals %s", tc.peer.Name, p.Pack, p.PackSource, p.Profile, p.Approvals)
		}
	}
	// A looser --pack under the required pack refuses the run with the
	// profile's name (GAP-0537).
	p := postureExplain(t, f, sbxAlice, sandboxrelay.ExplainRequest{Flags: &sandboxrelay.RunFlags{Pack: "open"}}).Posture
	if len(p.Violations) == 0 || !p.Violations[0].Fatal || p.Violations[0].Key != "pack" {
		t.Fatalf("--pack open: %+v", p.Violations)
	}
	// A repository's live mount is clamped to copy (SPEC D2).
	p = postureExplain(t, f, sbxBob, sandboxrelay.ExplainRequest{RepoOverlay: []byte("version: 1\nworkspace: {mode: mount}\n")}).Posture
	if len(p.Violations) != 1 || p.Violations[0].Fatal || p.Violations[0].Constraint != "defenseclaw.managed.copy_only" {
		t.Fatalf("repo mount: %+v", p.Violations)
	}
}

// GAP-0518: a profile value the organization's base clamps is the
// organization's, and allow_mount is named.
func TestSandboxExplainSourcesNameTheClamp(t *testing.T) {
	f := postureFixture(t)
	src := postureExplain(t, f, sbxBob, sandboxrelay.ExplainRequest{Sources: true}).Sources
	for key, want := range map[string]string{
		"allow_yolo": sandboxapi.ExplainSourceOrganization, "allow_mount": sandboxapi.ExplainSourceOrganization,
		"egress_allow_only": sandboxapi.ExplainSourceProfile, "egress_block": sandboxapi.ExplainSourceOrganization,
	} {
		if src[key] != want {
			t.Errorf("source of %s = %q, want %q", key, src[key], want)
		}
	}
}

// GAP-0438: a policy test without a sandbox judges the caller's own policy
// for a new run: the strict minimum keeps carol's sandbox off the web.
func TestSandboxPolicyTestOfANewRun(t *testing.T) {
	f := postureFixture(t)
	body := sandboxrelay.PolicyTestRequest{V: 1, Checks: []sandboxapi.PolicyCheck{{Host: "example.org", Port: 443}}}
	rec := f.do(postureCarol, http.MethodPost, sandboxrelay.PathPolicyTest, body, map[string]string{sandboxrelay.ConnectorHeader: "claudecode"})
	var out sandboxapi.PolicyTestResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); rec.Code != http.StatusOK || err != nil {
		t.Fatalf("policy test: %d %s", rec.Code, rec.Body.String())
	}
	if out.Profile != "strict" || out.NetworkMode != "deny" || len(out.Decisions) != 1 || out.Decisions[0].Allowed {
		t.Fatalf("carol's new run: %+v", out)
	}
}
