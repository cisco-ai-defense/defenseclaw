// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/mcplocal"
)

// The facts keep the first maxArgs arguments, and whether the scanner refuses
// a local server depends on all of them: the hook states the verdict from the
// complete definition (GAP-0925).
func TestEncodeStatesTheScannerVerdictOfTheCompleteLocalDefinition(t *testing.T) {
	filler := func(n int, tail ...string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "--quiet"
		}
		return append(out, tail...)
	}
	for _, tc := range []struct {
		name   string
		server MCPServer
		want   string
	}{
		{"flag past the bound", MCPServer{Name: "s", Command: "npx", Args: filler(maxArgs+2, "-c", "x")}, mcplocal.Arguments},
		{"package past the bound", MCPServer{Name: "s", Command: "npx", Args: filler(maxArgs+2, "pkg")}, mcplocal.None},
		{"package within the bound", MCPServer{Name: "s", Command: "npx", Args: []string{"-y", "pkg"}}, mcplocal.None},
		{"flag within the bound", MCPServer{Name: "s", Command: "uvx", Args: []string{"--eval=1", "pkg"}}, mcplocal.Arguments},
		{"interpreter", MCPServer{Name: "s", Command: "python3", Args: filler(maxArgs + 5)}, mcplocal.Launcher},
		{"url server", MCPServer{Name: "s", URL: "https://mcp.example.com/mcp"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := tc.server
			facts, ok := Decode(Encode(Facts{MCP: &server}))
			if !ok || facts.MCP == nil {
				t.Fatal("the claim was lost")
			}
			if facts.MCP.LocalRefusal != tc.want {
				t.Fatalf("LocalRefusal = %q, want %q", facts.MCP.LocalRefusal, tc.want)
			}
			if len(facts.MCP.Args) > maxArgs {
				t.Fatalf("%d arguments carried, want at most %d", len(facts.MCP.Args), maxArgs)
			}
			if facts.MCP.ArgsMayBeCut() {
				t.Fatal("a claim that states its verdict is reported as possibly cut")
			}
		})
	}
}

// A claim from a hook that stated no verdict and holds as many arguments as
// the bound allows may be the first part of a longer list; a shorter one is
// complete. A verdict that is not one of the classes is dropped.
func TestClaimWithoutVerdictAtTheArgumentBoundMayBeCut(t *testing.T) {
	long := MCPServer{Command: "npx", Args: make([]string, maxArgs)}
	if !long.ArgsMayBeCut() {
		t.Fatal("a claim at the bound without a verdict is judged by its arguments")
	}
	if (MCPServer{Command: "npx", Args: make([]string, maxArgs-1)}).ArgsMayBeCut() {
		t.Fatal("a claim below the bound cannot be cut")
	}
	forged := MCPServer{Name: "s", Command: "npx", Args: []string{"pkg"}, LocalRefusal: "allow"}
	facts := bounded(Facts{MCP: &forged})
	if facts.MCP == nil || facts.MCP.LocalRefusal != "" {
		t.Fatalf("claim %+v, want the unknown verdict dropped", facts.MCP)
	}
}
