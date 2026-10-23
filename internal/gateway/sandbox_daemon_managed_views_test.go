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

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// contractorsExplain is the managed gateway's answer for a contractor: an
// allow-only list and the organization's base block.
func contractorsExplain(seen *[]sandboxrelay.ExplainRequest) func(sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
	return func(r sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
		*seen = append(*seen, r)
		return sandboxapi.ManagedExplain{Profile: "contractors", Description: "Contractors.", Match: "group", Allowed: true,
			EgressAllowOnly: []string{"*.github.com", "pastebin.com"}, EgressBlock: []string{"pastebin.com"}, AllowUnblock: true,
			PolicyDigest: "sha256:abc", RequestAccess: "it-help@example.com", Posture: contractorsPosture()}, nil
	}
}

// contractorsPosture is the managed gateway's resolution of a contractor's
// run: the required contractors pack and its manual approvals.
func contractorsPosture() *sandboxapi.ManagedPosture {
	return &sandboxapi.ManagedPosture{Pack: "contractors", PackSource: "organization", PackDigest: "sha256:c0",
		Profile: "balanced", NetworkMode: "allowlist", Approvals: "manual",
		Settings: []sandboxapi.Setting{{Key: "pack", Value: "contractors", Source: "admin", Origin: "openshell.admin.required_pack"}}}
}

// A run's preflight (an explain of a new run) is answered with the floor the
// managed gateway names for the caller, never the daemon's closed floor: a
// valid user is not refused before the create resolves, and an explain with
// no harness still claims a connector, so the user view is the caller's own
// policy (GAP-0197, GAP-0227, GAP-0179).
func TestManagedExplainUsesTheGatewaysFloor(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	var seen []sandboxrelay.ExplainRequest
	f.relay.explain = contractorsExplain(&seen)
	f.run(t)
	client := sandboxapi.NewUnixClient(f.socket)
	ctx := context.Background()
	for _, req := range []sandboxapi.ExplainRequest{{Harness: "claudecode", Project: t.TempDir()}, {Sources: true}} {
		ex, err := client.Explain(ctx, req)
		if err != nil {
			t.Fatalf("explain %+v: %v", req, err)
		}
		for _, v := range ex.Violations {
			if v.Fatal {
				t.Fatalf("explain %+v refuses a valid user: %+v", req, v)
			}
		}
		if ex.Managed == nil || ex.Managed.Profile != "contractors" {
			t.Fatalf("managed part = %+v", ex.Managed)
		}
		// The posture is the gateway's, with the required pack the daemon
		// cannot read itself (GAP-0179, GAP-0438).
		if ex.Pack != "contractors" || ex.PackSource != "organization" || ex.Approvals != "manual" || len(ex.Settings) != 1 || ex.Managed.Posture != nil {
			t.Fatalf("posture: pack %s (%s) approvals %s settings %+v", ex.Pack, ex.PackSource, ex.Approvals, ex.Settings)
		}
	}
	if len(seen) != 2 || seen[0].Connector != "claudecode" || seen[0].ProjectReal == "" || seen[1].Connector != defaultManagedConnector || !seen[1].Sources {
		t.Fatalf("explain requests = %+v", seen)
	}

	// The organization's refusal is the gateway's floor, not the closed one.
	f.relay.explain = func(sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
		p := contractorsPosture()
		p.Violations = []sandboxapi.Violation{{Key: "sandbox", Constraint: "openshell.admin.allowed", Fatal: true, Admin: true}}
		return sandboxapi.ManagedExplain{Profile: "blocked", Allowed: false, Posture: p}, nil
	}
	ex, err := client.Explain(ctx, sandboxapi.ExplainRequest{Harness: "claudecode"})
	if err != nil || !hasFatal(ex.Violations, "openshell.admin.allowed") {
		t.Fatalf("a disallowed caller: %+v, %v", ex, err)
	}

	// An answer without a posture is a policy the daemon cannot know: no
	// answer from its own resolution.
	f.relay.explain = func(sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
		return sandboxapi.ManagedExplain{Profile: "contractors", Allowed: true}, nil
	}
	if _, err := client.Explain(ctx, sandboxapi.ExplainRequest{Harness: "claudecode"}); !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) {
		t.Fatalf("no posture: %v", err)
	}

	// A gateway that does not answer fails the explain; no closed-floor answer.
	f.relay.explain = func(sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
		return sandboxapi.ManagedExplain{}, sandboxrelay.ErrGatewayUnreachable
	}
	if _, err := client.Explain(ctx, sandboxapi.ExplainRequest{Harness: "claudecode"}); !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) {
		t.Fatalf("unreachable gateway: %v", err)
	}
}

func hasFatal(list []sandboxapi.Violation, constraint string) bool {
	for _, v := range list {
		if v.Fatal && v.Constraint == constraint {
			return true
		}
	}
	return false
}

// A status before any sandbox registered names the caller's own profile, as
// the managed gateway matches it (GAP-0179).
func TestManagedStatusNamesTheCallersProfile(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	var seen []sandboxrelay.ExplainRequest
	f.relay.explain = contractorsExplain(&seen)
	f.run(t)
	st, err := sandboxapi.NewUnixClient(f.socket).Status(context.Background())
	if err != nil || st.Managed == nil || st.Managed.Profile != "contractors" || st.Managed.Description != "Contractors." ||
		st.Managed.EffectiveDigest != "sha256:abc" {
		t.Fatalf("status = %+v, %v", st, err)
	}
	// Its pack and profile are the gateway's posture (GAP-0179).
	if st.Pack != "contractors" || st.Profile != "balanced" {
		t.Fatalf("status pack %q profile %q", st.Pack, st.Profile)
	}
}

// `policy test` without a sandbox judges the caller's own policy for a new
// run (GAP-0228) at the managed gateway, which resolves it under the
// caller's floor, its required pack and profile minimum included
// (GAP-0438): the daemon sends the run's connector, project and repository
// policy, and relays the answer.
func TestManagedPolicyTestWithoutASandbox(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	var seen []sandboxrelay.PolicyTestRequest
	f.relay.test = func(r sandboxrelay.PolicyTestRequest) (sandboxapi.PolicyTestResult, error) {
		seen = append(seen, r)
		return sandboxapi.PolicyTestResult{Pack: "contractors", Profile: "balanced", NetworkMode: "allowlist",
			Decisions: []sandboxapi.PolicyDecision{{PolicyCheck: r.Checks[0], Rule: "admin_allow_only"}}}, nil
	}
	f.run(t)
	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, ".defenseclaw"), 0o755); err != nil {
		t.Fatal(err)
	}
	overlay := []byte("version: 1\nnetwork: {mode: deny}\n")
	if err := os.WriteFile(filepath.Join(project, ".defenseclaw", "sandbox.yaml"), overlay, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := sandboxapi.NewUnixClient(f.socket).PolicyTest(context.Background(), sandboxapi.PolicyTestRequest{
		Project: project, Harness: "codex", Checks: []sandboxapi.PolicyCheck{{Host: "example.org", Port: 443}},
	})
	if err != nil || len(res.Decisions) != 1 || res.Pack != "contractors" || res.Decisions[0].Rule != "admin_allow_only" {
		t.Fatalf("policy test: %+v, %v", res, err)
	}
	real, _ := filepath.EvalSymlinks(project)
	if len(seen) != 1 || seen[0].Connector != "codex" || seen[0].Registration != "" || seen[0].ProjectReal != real ||
		string(seen[0].RepoOverlay) != string(overlay) {
		t.Fatalf("policy test requests = %+v", seen)
	}
}

// pack list and show are the managed gateway's view of the caller's own
// chain; a pack outside it is not found (GAP-0181, GAP-0241).
func TestManagedPackRoutes(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	type call struct{ registration, connector, name string }
	var calls []call
	f.relay.packs = func(registration, connector, name string) ([]sandboxrelay.PackView, error) {
		calls = append(calls, call{registration, connector, name})
		if name == "contractors" {
			return nil, &sandboxrelay.Error{Status: http.StatusNotFound, Reason: "pack_unknown", Message: "No pack of that name is part of your sandbox policy."}
		}
		return []sandboxrelay.PackView{{Name: "strict", Source: "builtin", Digest: "sha256:1", Content: "name: strict\n"}}, nil
	}
	f.run(t)
	client := sandboxapi.NewUnixClient(f.socket)
	ctx := context.Background()
	list, err := client.ListManagedPacks(ctx)
	if err != nil || len(list) != 1 || list[0].Name != "strict" {
		t.Fatalf("pack list: %+v, %v", list, err)
	}
	p, err := client.GetManagedPack(ctx, "strict")
	if err != nil || p.Content != "name: strict\n" {
		t.Fatalf("pack show: %+v, %v", p, err)
	}
	if _, err := client.GetManagedPack(ctx, "contractors"); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) ||
		!strings.Contains(err.Error(), "not part of your sandbox policy") && !strings.Contains(err.Error(), "No pack of that name") {
		t.Fatalf("another profile's pack: %v", err)
	}
	if len(calls) != 3 || calls[0].connector != defaultManagedConnector || calls[0].registration != "" {
		t.Fatalf("relay calls = %+v", calls)
	}
}

// The availability a status shows follows the managed gateway within
// sandboxDaemonSettingsTTL, without restarting the daemon (GAP-0256).
func TestManagedStatusRereadsStaleSettings(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	reads := 0
	f.relay.settings = func() (sandboxrelay.DaemonSettings, error) {
		reads++
		s := f.d.currentSettings()
		s.Available, s.Unavailable = true, ""
		return s, nil
	}
	f.run(t)
	f.d.settingsMu.Lock()
	f.d.settings.Available, f.d.settings.Unavailable = false, "this computer has no KVM"
	f.d.settingsMu.Unlock()
	client := sandboxapi.NewUnixClient(f.socket)
	st, err := client.Status(context.Background())
	if err != nil || st.Managed.Unavailable == "" || reads != 0 {
		t.Fatalf("fresh settings were read again: %+v, %v (reads %d)", st.Managed, err, reads)
	}
	f.d.settingsAt.Store(time.Now().Add(-sandboxDaemonSettingsTTL - time.Second).UnixNano())
	st, err = client.Status(context.Background())
	if err != nil || st.Managed.Unavailable != "" || reads != 1 {
		t.Fatalf("stale settings kept: %+v, %v (reads %d)", st.Managed, err, reads)
	}
	f.relay.settings = func() (sandboxrelay.DaemonSettings, error) { return sandboxrelay.DaemonSettings{}, errors.New("down") }
	f.d.settingsAt.Store(0)
	if st, err = client.Status(context.Background()); err != nil || st.Managed.Unavailable != "" {
		t.Fatalf("a failed read dropped the settings: %+v, %v", st.Managed, err)
	}
}

// #1200: the MCP row of a new run's explain counted only the caller's own
// servers; a project's .mcp.json server, which the pack keeps from
// starting, was in no view. The daemon counts the project's servers.
func TestManagedExplainCountsTheProjectsMCPServers(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	var seen []sandboxrelay.ExplainRequest
	f.relay.explain = contractorsExplain(&seen)
	f.run(t)
	client := sandboxapi.NewUnixClient(f.socket)
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, ".mcp.json"), []byte(`{"mcpServers":{"site-docs":{"type":"http","url":"https://example.invalid/mcp"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ex, err := client.Explain(context.Background(), sandboxapi.ExplainRequest{Harness: "claudecode", Project: project})
	if err != nil || ex.Managed == nil {
		t.Fatalf("explain: %+v, %v", ex, err)
	}
	if ex.Managed.MCPProjectCount != 1 || !ex.Managed.MCPProjectBlocked {
		t.Fatalf("project MCP = %d blocked %t, want 1 blocked", ex.Managed.MCPProjectCount, ex.Managed.MCPProjectBlocked)
	}
	// An explain of a sandbox already made is its registration's: no project read.
	if ex, err := client.Explain(context.Background(), sandboxapi.ExplainRequest{Harness: "claudecode"}); err != nil || ex.Managed.MCPProjectCount != 0 {
		t.Fatalf("explain without a project: %+v, %v", ex, err)
	}
}
