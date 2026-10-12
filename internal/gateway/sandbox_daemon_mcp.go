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
	"context"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/manager"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// A managed run brings the user's own MCP servers along as the managed
// gateway judged them (GAP-0475). The daemon reads the user's servers once,
// as the user and from user scope only, claims them in the request
// (policy/resolve for a create, policy/explain for an explain or a start)
// and the run imports exactly the claimed servers the gateway kept, from
// what was read: a server the gateway left out, or did not judge, stays
// behind with the reason, and without the gateway's answer none comes along.

// managedMCPDecision is the managed gateway's answer for the MCP servers
// one run of harness claimed: entries is what the daemon read, kept the
// claimed names the gateway kept and skipped the reason of each it left out.
type managedMCPDecision struct {
	harness string
	entries []config.MCPServerEntry
	kept    map[string]bool
	skipped map[string]string
}

// newManagedMCPDecision is the decision for entries, of which the gateway
// kept the names kept (only claimed names count) and left out skipped.
func newManagedMCPDecision(harness string, entries []config.MCPServerEntry, kept []string, skipped map[string]string) *managedMCPDecision {
	claimed := map[string]bool{}
	for _, c := range managedMCPClaims(entries) {
		claimed[c.Name] = true
	}
	d := &managedMCPDecision{harness: harness, entries: entries, kept: map[string]bool{}, skipped: skipped}
	for _, name := range kept {
		if claimed[name] && skipped[name] == "" {
			d.kept[name] = true
		}
	}
	return d
}

// resolveMCPDecision is the decision a policy/resolve answer carries.
func resolveMCPDecision(harness string, entries []config.MCPServerEntry, resp sandboxrelay.ResolveResponse) *managedMCPDecision {
	skipped := map[string]string{}
	for _, s := range resp.MCPSkipped {
		skipped[s.Name] = s.Reason
	}
	return newManagedMCPDecision(harness, entries, resp.MCPKept, skipped)
}

// explainMCPDecision is the decision a policy/explain answer carries.
func explainMCPDecision(harness string, entries []config.MCPServerEntry, me sandboxapi.ManagedExplain) *managedMCPDecision {
	skipped := map[string]string{}
	for _, s := range me.MCPBlocked {
		skipped[s.Name] = s.Reason
	}
	return newManagedMCPDecision(harness, entries, me.MCPIncluded, skipped)
}

// managedMCPClaims are the claims of the servers in entries the managed
// gateway can judge, each name once (the first, as the manager imports
// them): neither the harness's own servers nor disabled ones, which the
// manager handles itself, and only claims the gateway accepts
// (sandboxrelay.ValidMCPServerClaim), at most sandboxrelay.MaxMCPClaims of
// them and sandboxrelay.MaxMCPClaimBytes in all. A server not claimed is
// not judged, so it stays behind.
func managedMCPClaims(entries []config.MCPServerEntry) []sandboxrelay.MCPServerClaim {
	claims := []sandboxrelay.MCPServerClaim{}
	seen := map[string]bool{}
	size := 0
	for _, e := range entries {
		name := strings.TrimSpace(e.Name)
		if e.Bundled || e.Disabled || seen[name] {
			continue
		}
		seen[name] = true
		c := sandboxrelay.MCPServerClaim{Name: name, Transport: strings.TrimSpace(e.Transport), URL: strings.TrimSpace(e.URL),
			Command: strings.TrimSpace(e.Command), Args: append([]string(nil), e.Args...)}
		if !sandboxrelay.ValidMCPServerClaim(c) || len(claims) == sandboxrelay.MaxMCPClaims || size+c.Size() > sandboxrelay.MaxMCPClaimBytes {
			continue
		}
		size += c.Size()
		claims = append(claims, c)
	}
	return claims
}

// managedMCPJudge answers the managed gateway's decision for a run of
// harness; the daemon puts one in the context of each create, explain and
// start (withManagedMCPJudge).
type managedMCPJudge func(ctx context.Context, harness string) (*managedMCPDecision, error)

type managedMCPJudgeKey struct{}

func withManagedMCPJudge(ctx context.Context, judge managedMCPJudge) context.Context {
	return context.WithValue(ctx, managedMCPJudgeKey{}, judge)
}

// fixedMCPJudge answers dec.
func fixedMCPJudge(dec *managedMCPDecision) managedMCPJudge {
	return func(context.Context, string) (*managedMCPDecision, error) { return dec, nil }
}

// daemonMCPInventory is the daemon manager's MCP import source: of the
// user's servers the daemon read, those the managed gateway kept (the
// judge in the context). Without a judge, or for another harness than the
// one judged, no server comes along.
type daemonMCPInventory struct{}

var _ manager.MCPInventory = daemonMCPInventory{}

// SandboxMCPServers implements manager.MCPInventory.
func (daemonMCPInventory) SandboxMCPServers(ctx context.Context, harness string) ([]config.MCPServerEntry, []manager.MCPSkip, error) {
	judge, _ := ctx.Value(managedMCPJudgeKey{}).(managedMCPJudge)
	if judge == nil {
		return nil, nil, nil
	}
	dec, err := judge(ctx, harness)
	if err != nil || dec == nil || dec.harness != harness {
		return nil, nil, err
	}
	var kept []config.MCPServerEntry
	var skipped []manager.MCPSkip
	seen := map[string]bool{}
	for _, e := range dec.entries {
		name := strings.TrimSpace(e.Name)
		switch {
		case e.Bundled || e.Disabled:
			// The manager leaves these out itself, with the reason.
			kept = append(kept, e)
			continue
		case seen[name]:
			continue
		}
		seen[name] = true
		if dec.kept[name] {
			kept = append(kept, e)
			continue
		}
		code := dec.skipped[name]
		skipped = append(skipped, manager.MCPSkip{Name: name, Reason: managedMCPSkipText(code), Code: code})
	}
	return kept, skipped, nil
}

// managedMCPSkipText is the user's text for a server the managed gateway
// left out for code ("" when it did not judge the server).
func managedMCPSkipText(code string) string {
	switch code {
	case sandboxapi.MCPCodeOrganizationBlock:
		return "blocked by your organization"
	case sandboxapi.MCPCodeAssetPolicy:
		return "blocked by your organization's MCP asset policy"
	case "":
		return "your organization's policy did not check it"
	default:
		return "left out by your organization's policy"
	}
}
