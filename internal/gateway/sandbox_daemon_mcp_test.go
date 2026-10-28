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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// A managed run brings the user's own MCP servers along as the managed
// gateway judged them: the daemon claims them in the resolve, and the run
// imports the claimed servers the gateway kept; the blocked ones stay
// behind with the organization's reason (GAP-0475). A start asks again.
func TestManagedRunBringsTheUsersMCPServersAsTheGatewayJudged(t *testing.T) {
	entries := []config.MCPServerEntry{
		{Name: "ok-srv", Command: "npx", Args: []string{"-y", "ok"}},
		{Name: "blocked-srv", Command: "npx"},
		{Name: "user-srv", URL: "https://mcp.example/u"},
		{Name: "ok-srv", Command: "other"},
		{Name: "srv-é", Command: "x"},
		{Name: "codex_apps", URL: "https://example.com/apps", Bundled: true},
		{Name: "off", Command: "y", Disabled: true},
	}
	regs, err := loadDaemonRegistrations(filepath.Join(t.TempDir(), "registrations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	relay := &fakeRelay{}
	d := &SandboxDaemon{regs: regs, logf: t.Logf, relay: relay, opts: SandboxDaemonOptions{goos: "linux",
		mcpRead: func(c string) ([]config.MCPServerEntry, error) { asked = append(asked, c); return entries, nil }}}

	mcp := d.userMCPServers("claudecode", false)
	req, err := d.resolveRequest(sandboxapi.CreateRequest{Harness: "claudecode"}, openshell.DriverChoice{Driver: openshell.DriverDocker}, mcp)
	if err != nil {
		t.Fatal(err)
	}
	var claimed []string
	for _, c := range req.MCP {
		claimed = append(claimed, c.Name)
	}
	if !slices.Equal(claimed, []string{"ok-srv", "blocked-srv", "user-srv"}) || !slices.Equal(asked, []string{"claudecode"}) ||
		req.MCP[0].Command != "npx" {
		t.Fatalf("claims %+v (read %v)", req.MCP, asked)
	}
	if d.userMCPServers("claudecode", true) != nil {
		t.Fatal("--no-mcp read the user's servers")
	}

	names := func(kept []config.MCPServerEntry) []string {
		var out []string
		for _, e := range kept {
			out = append(out, e.Name)
		}
		return out
	}
	resp := sandboxrelay.ResolveResponse{MCPKept: []string{"ok-srv", "user-srv", "srv-é"},
		MCPSkipped: []sandboxrelay.MCPSkip{{Name: "blocked-srv", Reason: sandboxrelay.MCPSkipOrganizationBlock}}}
	ctx := withManagedMCPJudge(context.Background(), fixedMCPJudge(resolveMCPDecision("claudecode", mcp, resp)))
	kept, skipped, err := daemonMCPInventory{}.SandboxMCPServers(ctx, "claudecode")
	if err != nil || !slices.Equal(names(kept), []string{"ok-srv", "user-srv", "codex_apps", "off"}) || kept[0].Command != "npx" {
		t.Fatalf("kept %v (%v)", names(kept), err)
	}
	want := []string{"blocked-srv|blocked by your organization|organization_block", "srv-é|your organization's policy did not check it|"}
	var got []string
	for _, s := range skipped {
		got = append(got, s.Name+"|"+s.Reason+"|"+s.Code)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("skipped %v, want %v", got, want)
	}
	// Nothing comes along without the gateway's answer, or for another harness.
	if kept, _, _ := (daemonMCPInventory{}).SandboxMCPServers(context.Background(), "claudecode"); kept != nil {
		t.Fatalf("no judge kept %v", names(kept))
	}
	if kept, _, _ := (daemonMCPInventory{}).SandboxMCPServers(ctx, "codex"); kept != nil {
		t.Fatalf("another harness kept %v", names(kept))
	}

	// A start asks the gateway again, for its registration.
	var sent sandboxrelay.ExplainRequest
	relay.explain = func(r sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
		sent = r
		return sandboxapi.ManagedExplain{MCPIncluded: []string{"ok-srv"}, MCPBlocked: []sandboxapi.ManagedMCP{
			{Name: "user-srv", Reason: sandboxapi.MCPCodeAssetPolicy}, {Name: "blocked-srv", Reason: sandboxapi.MCPCodeOrganizationBlock}}}, nil
	}
	start := withManagedMCPJudge(context.Background(), d.startMCPJudge("reg-1"))
	kept, skipped, err = daemonMCPInventory{}.SandboxMCPServers(start, "claudecode")
	if err != nil || sent.Registration != "reg-1" || len(sent.MCP) != 3 || !slices.Equal(names(kept), []string{"ok-srv", "codex_apps", "off"}) || len(skipped) != 3 {
		t.Fatalf("start: kept %v skipped %+v sent %+v (%v)", names(kept), skipped, sent, err)
	}
	relay.explain = func(sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
		return sandboxapi.ManagedExplain{}, errors.New("down")
	}
	if kept, _, err := (daemonMCPInventory{}).SandboxMCPServers(start, "claudecode"); err == nil || kept != nil {
		t.Fatalf("a start without the gateway's answer kept %v (%v)", names(kept), err)
	}
	// GAP-0179: once the person withdraws their servers, the next start
	// reads that and brings none along, without a gateway answer to reuse.
	entries = nil
	relay.explain = func(sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
		t.Fatal("a start without claims asked the gateway")
		return sandboxapi.ManagedExplain{}, nil
	}
	if kept, skipped, err := (daemonMCPInventory{}).SandboxMCPServers(start, "claudecode"); err != nil || len(kept) != 0 || len(skipped) != 0 {
		t.Fatalf("a start after the servers were withdrawn kept %v skipped %+v (%v)", names(kept), skipped, err)
	}
}

// The caller's explain judges the MCP servers it claims (the MCP row), and
// refuses a malformed claim.
func TestSandboxExplainJudgesTheCallersMCPServers(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxBob, "dc-sbx-devs")
	var judged []sandboxrelay.MCPServerClaim
	prev := sandboxFilterMCP
	sandboxFilterMCP = func(_ context.Context, _ *APIServer, _ managedHookPeer, connectorName string, claims []sandboxrelay.MCPServerClaim) ([]string, []sandboxrelay.MCPSkip) {
		judged = claims
		return []string{"ok-srv"}, []sandboxrelay.MCPSkip{{Name: "blocked-srv", Reason: sandboxrelay.MCPSkipOrganizationBlock}}
	}
	t.Cleanup(func() { sandboxFilterMCP = prev })

	claims := []sandboxrelay.MCPServerClaim{{Name: "ok-srv", Command: "npx"}, {Name: "blocked-srv", Command: "npx"}}
	rec := f.do(sbxBob, http.MethodPost, sandboxrelay.PathPolicyExplain, sandboxrelay.ExplainRequest{V: 1, Connector: "claudecode", MCP: claims}, nil)
	var me sandboxapi.ManagedExplain
	if err := json.Unmarshal(rec.Body.Bytes(), &me); rec.Code != http.StatusOK || err != nil {
		t.Fatalf("explain: %d %s", rec.Code, rec.Body.String())
	}
	if len(judged) != 2 || !slices.Equal(me.MCPIncluded, []string{"ok-srv"}) ||
		!slices.Equal(me.MCPBlocked, []sandboxapi.ManagedMCP{{Name: "blocked-srv", Reason: sandboxapi.MCPCodeOrganizationBlock}}) {
		t.Fatalf("explain MCP: included %v blocked %v (judged %d)", me.MCPIncluded, me.MCPBlocked, len(judged))
	}
	// A floor that leaves foreign_sandboxes unset stops them, and the
	// explain says so (r103 GAP-0225).
	if me.ForeignSandboxes != config.OpenShellForeignSandboxesStop {
		t.Fatalf("explain foreign_sandboxes = %q, want stop", me.ForeignSandboxes)
	}
	bad := []sandboxrelay.MCPServerClaim{{Name: "bad\x01", Command: "npx"}}
	if rec := f.do(sbxBob, http.MethodPost, sandboxrelay.PathPolicyExplain, sandboxrelay.ExplainRequest{V: 1, Connector: "claudecode", MCP: bad}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed claim: %d %s", rec.Code, rec.Body.String())
	}
}
