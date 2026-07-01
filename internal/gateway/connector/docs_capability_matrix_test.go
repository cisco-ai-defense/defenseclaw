// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

type documentedCapabilityMatrix struct {
	Connectors []struct {
		ID               string `json:"id"`
		Family           string `json:"family"`
		ToolInspection   string `json:"toolInspection"`
		SubprocessPolicy string `json:"subprocessPolicy"`
		Hooks            struct {
			CanBlock           bool     `json:"canBlock"`
			CanAskNative       bool     `json:"canAskNative"`
			AskEvents          []string `json:"askEvents"`
			BlockEvents        []string `json:"blockEvents"`
			SupportsFailClosed bool     `json:"supportsFailClosed"`
			Scope              string   `json:"scope"`
		} `json:"hooks"`
	} `json:"connectors"`
}

// TestDocsCapabilityMatrixMatchesConnectors makes the JSON shared by the docs
// table and command generator a checked projection of the connector registry.
func TestDocsCapabilityMatrixMatchesConnectors(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", ".."))
	path := filepath.Join(repoRoot, "docs-site", "data", "capability-matrix.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var documented documentedCapabilityMatrix
	if err := json.Unmarshal(raw, &documented); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}

	rows := make(map[string]struct {
		family, toolInspection, subprocessPolicy string
		canBlock, canAskNative, failClosed       bool
		askEvents, blockEvents                   []string
		scope                                    string
	}, len(documented.Connectors))
	for _, row := range documented.Connectors {
		if _, exists := rows[row.ID]; exists {
			t.Fatalf("duplicate connector %q in capability matrix", row.ID)
		}
		rows[row.ID] = struct {
			family, toolInspection, subprocessPolicy string
			canBlock, canAskNative, failClosed       bool
			askEvents, blockEvents                   []string
			scope                                    string
		}{
			row.Family,
			row.ToolInspection,
			row.SubprocessPolicy,
			row.Hooks.CanBlock,
			row.Hooks.CanAskNative,
			row.Hooks.SupportsFailClosed,
			row.Hooks.AskEvents,
			row.Hooks.BlockEvents,
			row.Hooks.Scope,
		}
	}

	opts := SetupOpts{DataDir: t.TempDir(), WorkspaceDir: t.TempDir()}
	for _, conn := range newBuiltinConnectors() {
		row, exists := rows[conn.Name()]
		if !exists {
			t.Errorf("connector %q is missing from docs capability matrix", conn.Name())
			continue
		}
		delete(rows, conn.Name())

		wantFamily := LLMTrafficModeForConnector(conn.Name())
		if wantFamily == LLMTrafficModeHooksOnly {
			wantFamily = "hooks"
		}
		wantToolInspection := string(conn.ToolInspectionMode())
		if conn.ToolInspectionMode() == ToolModeBoth {
			wantToolInspection = "pre-execution + response-scan"
		}

		if row.family != wantFamily {
			t.Errorf("%s family=%q want %q", conn.Name(), row.family, wantFamily)
		}
		if row.toolInspection != wantToolInspection {
			t.Errorf("%s toolInspection=%q want %q", conn.Name(), row.toolInspection, wantToolInspection)
		}
		actualSubprocess := string(conn.SubprocessPolicy())
		// Codex and Claude Code prefer the sandbox policy but resolve to
		// shims when OpenShell is not installed on the test host. The docs
		// describe the configured/preferred policy, not that host fallback.
		subprocessMatches := row.subprocessPolicy == actualSubprocess || (row.subprocessPolicy == "sandbox" && actualSubprocess == "shims")
		if !subprocessMatches {
			t.Errorf("%s subprocessPolicy=%q want %q", conn.Name(), row.subprocessPolicy, conn.SubprocessPolicy())
		}

		provider, ok := conn.(HookCapabilityProvider)
		if !ok {
			// Proxy connectors expose their interception/HITL contract through
			// the plugin/proxy path rather than HookCapabilityProvider. Their
			// family, inspection, and subprocess columns are still checked above;
			// hook-specific columns remain reviewed documentation.
			if wantFamily != LLMTrafficModeProxy {
				t.Errorf("hook connector %q does not expose HookCapabilities", conn.Name())
			}
			continue
		}
		caps := provider.HookCapabilities(opts)
		if row.canBlock != caps.CanBlock || row.canAskNative != caps.CanAskNative || row.failClosed != caps.SupportsFailClosed || row.scope != caps.Scope {
			t.Errorf("%s documented hooks do not match runtime: docs=(block=%v ask=%v failClosed=%v scope=%q) runtime=(block=%v ask=%v failClosed=%v scope=%q)", conn.Name(), row.canBlock, row.canAskNative, row.failClosed, row.scope, caps.CanBlock, caps.CanAskNative, caps.SupportsFailClosed, caps.Scope)
		}
		if !sameDocumentedStrings(row.askEvents, caps.AskEvents) {
			t.Errorf("%s askEvents=%v want %v", conn.Name(), row.askEvents, caps.AskEvents)
		}
		if !sameDocumentedStrings(row.blockEvents, caps.BlockEvents) {
			t.Errorf("%s blockEvents=%v want %v", conn.Name(), row.blockEvents, caps.BlockEvents)
		}
	}
	for id := range rows {
		t.Errorf("docs capability matrix contains unknown connector %q", id)
	}
}

func sameDocumentedStrings(left, right []string) bool {
	left = slices.Clone(left)
	right = slices.Clone(right)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}
