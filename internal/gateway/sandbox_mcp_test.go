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
	"errors"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

func TestSandboxMCPInventoryFiltersDefenseClawBlocks(t *testing.T) {
	store, err := audit.NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	pe := enforce.NewPolicyEngine(store)
	if err := pe.Block("mcp", "globally-blocked", "scan verdict"); err != nil {
		t.Fatal(err)
	}
	if err := pe.BlockForConnector("mcp", "claude-blocked", "claudecode", "manual"); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = config.AssetPolicyModeAction
	cfg.AssetPolicy.MCP.Denied = []config.AssetPolicyRule{{Name: "policy-denied"}}

	var asked []string
	inv := &sandboxMCPInventory{
		config: func() *config.Config { return cfg },
		policy: pe,
		read: func(connector string) ([]config.MCPServerEntry, error) {
			asked = append(asked, connector)
			return []config.MCPServerEntry{
				{Name: "github", Command: "npx"},
				{Name: "globally-blocked", Command: "a"},
				{Name: "claude-blocked", Command: "b"},
				{Name: "policy-denied", URL: "https://x.example/mcp"},
				{Name: "codex_apps", URL: "https://x.example/apps", Bundled: true},
			}, nil
		},
	}
	kept, skipped, err := inv.SandboxMCPServers(context.Background(), "claudecode")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range kept {
		names = append(names, e.Name)
	}
	if !slices.Equal(names, []string{"github", "codex_apps"}) || !slices.Equal(asked, []string{"claudecode"}) {
		t.Fatalf("kept %v (asked %v)", names, asked)
	}
	reasons := map[string]string{}
	for _, s := range skipped {
		reasons[s.Name] = s.Reason
	}
	want := map[string]string{
		"globally-blocked": "blocked by DefenseClaw", "claude-blocked": "blocked by DefenseClaw",
		"policy-denied": "blocked by the MCP asset policy",
	}
	if len(reasons) != len(want) {
		t.Fatalf("skipped = %v", reasons)
	}
	for name, reason := range want {
		if reasons[name] != reason {
			t.Fatalf("%s skipped for %q, want %q", name, reasons[name], reason)
		}
	}

	// A connector-scoped block applies to that harness only.
	kept, _, err = inv.SandboxMCPServers(context.Background(), "codex")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(kept, func(e config.MCPServerEntry) bool { return e.Name == "claude-blocked" }) {
		t.Fatal("a claudecode-scoped block left the server out of a codex sandbox")
	}

	// Observe mode reports but does not block.
	cfg.AssetPolicy.Mode = config.AssetPolicyModeObserve
	kept, _, _ = inv.SandboxMCPServers(context.Background(), "claudecode")
	if !slices.ContainsFunc(kept, func(e config.MCPServerEntry) bool { return e.Name == "policy-denied" }) {
		t.Fatal("an observe-mode asset policy blocked an import")
	}
}

func TestSandboxMCPInventoryErrors(t *testing.T) {
	inv := &sandboxMCPInventory{read: func(string) ([]config.MCPServerEntry, error) { return nil, errors.New("unreadable") }}
	if _, _, err := inv.SandboxMCPServers(context.Background(), "claudecode"); err == nil {
		t.Fatal("a read failure was ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inv = &sandboxMCPInventory{read: func(string) ([]config.MCPServerEntry, error) {
		return []config.MCPServerEntry{{Name: "a", Command: "x"}}, nil
	}}
	if _, _, err := inv.SandboxMCPServers(ctx, "claudecode"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context = %v", err)
	}
	// Without an audit store or a config every server comes along.
	kept, skipped, err := inv.SandboxMCPServers(context.Background(), "codex")
	if err != nil || len(kept) != 1 || len(skipped) != 0 {
		t.Fatalf("kept %v skipped %v err %v", kept, skipped, err)
	}
	if _, err := config.ReadUserMCPServersForConnector("cursor"); err == nil {
		t.Fatal("a harness without a sandbox has a user-scope MCP inventory")
	}
}
