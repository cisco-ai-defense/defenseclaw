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

package inventory

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSignalFromMCPConfigPathCapExceededStampsPartial covers Vineet's
// [P1] inline finding on the MCP-inventory silent truncation. Before
// the fix, the parent "mcp" evidence row consumed one slot of the
// maxEvidencePerSignal (32) cap, so a caller with 32 real MCP servers
// silently dropped the 32nd row and marked the signal complete. The
// new code caps mcp_server rows at maxEvidencePerSignal-1 and — more
// importantly — stamps Partial + CoverageReason=cap_exceeded so
// downstream tells "31 servers exist" apart from "32+ exist but we
// stopped."
func TestSignalFromMCPConfigPathCapExceededStampsPartial(t *testing.T) {
	t.Parallel()

	// Codex-shape .mcp.json — many callers use this file layout.
	// Assemble one more than the cap to make the guard fire.
	root := t.TempDir()
	cfgPath := filepath.Join(root, ".mcp.json")

	extras := 5
	total := (maxEvidencePerSignal - 1) + extras
	servers := map[string]any{}
	for i := 0; i < total; i++ {
		servers[fmt.Sprintf("server-%03d", i)] = map[string]any{
			"command": "/usr/bin/true",
		}
	}
	raw, err := json.Marshal(map[string]any{"mcpServers": servers})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	s := &ContinuousDiscoveryService{}
	sig := AISignature{ID: "codex"}
	signal := s.signalFromMCPConfigPath(sig, cfgPath)

	if !signal.Partial {
		t.Fatalf("expected Partial=true when MCP server count exceeds cap; got %d evidence rows, Partial=false", len(signal.Evidence))
	}
	if signal.CoverageReason != CoverageReasonCapExceeded {
		t.Fatalf("expected CoverageReason=%q, got %q", CoverageReasonCapExceeded, signal.CoverageReason)
	}
	// Evidence rows: 1 parent "mcp" row + up to (cap-1) "mcp_server" rows.
	// The exact count depends on map iteration order (Go maps are
	// intentionally unordered) filtering out sanitize-rejected names —
	// none in this fixture are rejected — so we should hit exactly the cap.
	mcpServers := 0
	for _, ev := range signal.Evidence {
		if ev.Type == "mcp_server" {
			mcpServers++
		}
	}
	if mcpServers != maxEvidencePerSignal-1 {
		t.Fatalf("expected exactly %d mcp_server rows (cap-1, parent reserved), got %d",
			maxEvidencePerSignal-1, mcpServers)
	}
	if len(signal.Evidence) != maxEvidencePerSignal {
		t.Fatalf("expected %d total evidence rows, got %d", maxEvidencePerSignal, len(signal.Evidence))
	}
}

// TestSignalFromMCPConfigPathParseErrorStampsPartial verifies the
// parse-error branch of the coverage annotation. A malformed MCP
// config leaves the operator with the "endpoint has MCP configured"
// signal (parent evidence row) but zero server-name rows — which must
// not read as "no MCP servers." Partial + CoverageReason=parse_error
// makes the gap explicit.
func TestSignalFromMCPConfigPathParseErrorStampsPartial(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	cfgPath := filepath.Join(root, ".mcp.json")
	// JSON with a trailing dangling comma + missing closing brace —
	// the parseMCPConfigForNames dispatcher for this shape returns
	// a real error, exercising the parseErr != nil path.
	if err := os.WriteFile(cfgPath, []byte(`{"mcpServers": { "s1": { "command":`), 0o644); err != nil {
		t.Fatalf("write malformed fixture: %v", err)
	}

	s := &ContinuousDiscoveryService{}
	sig := AISignature{ID: "codex"}
	signal := s.signalFromMCPConfigPath(sig, cfgPath)

	if !signal.Partial {
		t.Fatalf("expected Partial=true on malformed MCP config; got Partial=false with evidence=%v", signal.Evidence)
	}
	if signal.CoverageReason != CoverageReasonParseError {
		t.Fatalf("expected CoverageReason=%q, got %q", CoverageReasonParseError, signal.CoverageReason)
	}
	// Parent evidence row survives — the operator still sees the
	// endpoint has MCP configured. Confirm there are no mcp_server
	// rows though (parse failed before we could enumerate).
	for _, ev := range signal.Evidence {
		if ev.Type == "mcp_server" {
			t.Fatalf("parse failure should emit zero mcp_server rows; got one for %q", ev.Basename)
		}
	}
	// Parent row must exist and identify the file.
	if len(signal.Evidence) == 0 || signal.Evidence[0].Type != "mcp" {
		t.Fatalf("expected parent 'mcp' evidence row for the endpoint; got %v", signal.Evidence)
	}
	if !strings.HasSuffix(cfgPath, signal.Evidence[0].Basename) {
		t.Fatalf("parent evidence basename does not match config file: base=%q cfg=%q",
			signal.Evidence[0].Basename, cfgPath)
	}
}

// TestSignalFromMCPConfigPathHealthyIsComplete is the negative baseline —
// a small, healthy MCP config with 3 servers must leave the signal
// complete (Partial=false, empty CoverageReason) so the JSON stays
// clean via omitempty.
func TestSignalFromMCPConfigPathHealthyIsComplete(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	cfgPath := filepath.Join(root, ".mcp.json")
	raw, err := json.Marshal(map[string]any{
		"mcpServers": map[string]any{
			"webex":     map[string]any{"command": "/usr/bin/true"},
			"atlassian": map[string]any{"command": "/usr/bin/true"},
			"cisco":     map[string]any{"command": "/usr/bin/true"},
		},
	})
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(cfgPath, raw, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	s := &ContinuousDiscoveryService{}
	sig := AISignature{ID: "codex"}
	signal := s.signalFromMCPConfigPath(sig, cfgPath)

	if signal.Partial {
		t.Fatalf("healthy config should NOT be partial; got CoverageReason=%q", signal.CoverageReason)
	}
	if signal.CoverageReason != "" {
		t.Fatalf("healthy config should have empty CoverageReason; got %q", signal.CoverageReason)
	}
}
