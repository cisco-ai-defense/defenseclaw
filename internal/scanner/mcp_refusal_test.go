// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1195 (review loop 2): the watcher keeps an MCP server whose scan did
// not finish under unverified_server warn, so the scanner marks the scans it
// refused for the server's own definition (ErrMCPScanRefused): those still
// block, as mcp set still refuses them. A timeout, an exit and a parse
// failure are not refusals.
func TestMCPScanMarksDefinitionRefusalsOnly(t *testing.T) {
	t.Setenv("DEFENSECLAW_ALLOW_LOCAL_MCP_TARGETS", "")
	ms := NewMCPScannerFromLLM(config.MCPScannerConfig{Binary: "mcp-scanner"}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
	if _, err := ms.Scan(context.Background(), "http://127.0.0.1:28571/mcp"); !errors.Is(err, ErrMCPScanRefused) {
		t.Fatalf("private URL: %v, want a refusal", err)
	}
	if _, err := ms.Scan(context.Background(), "https://user:pw@mcp.example.test/mcp"); !errors.Is(err, ErrMCPScanRefused) {
		t.Fatalf("URL with credentials: %v, want a refusal", err)
	}

	cliRefusal := buildScannerFixture(t, `{"scanner":"mcp-scanner","target":"notes","error":"scan failed: refusing to scan local MCP server 'notes': /usr/bin/node is not npx or uvx","findings":[]}`+"\n", 1)
	cliTimeout := buildScannerFixture(t, `{"scanner":"mcp-scanner","target":"notes","error":"scan failed: timed out waiting for the server","findings":[]}`+"\n", 1)
	silentExit := buildScannerFixture(t, "", 1)
	for _, tc := range []struct {
		name, binary, stderr string
		refused              bool
	}{
		{name: "mcp scan --json refusal", binary: cliRefusal, refused: true},
		{name: "mcp scan --json timeout", binary: cliTimeout},
		{name: "runtime refusal on stderr", binary: silentExit, stderr: "ValueError: refusing to scan MCP URL 'http://10.0.0.5/mcp': private address", refused: true},
		{name: "runtime crash on stderr", binary: silentExit, stderr: "TimeoutError: the server did not answer initialize"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prior := runMCPScannerCommand
			t.Cleanup(func() { runMCPScannerCommand = prior })
			runMCPScannerCommand = func(_ context.Context, cmd *exec.Cmd) error {
				_, _ = io.WriteString(cmd.Stderr, tc.stderr)
				return cmd.Run()
			}
			scan := NewMCPScannerFromLLM(config.MCPScannerConfig{Binary: tc.binary}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
			_, err := scan.Scan(context.Background(), "notes")
			if err == nil || errors.Is(err, ErrMCPScanRefused) != tc.refused || MCPScanRefused(err) != tc.refused {
				t.Fatalf("Scan() error %v, refusal %v; want an error, refusal %v", err, errors.Is(err, ErrMCPScanRefused), tc.refused)
			}
		})
	}

	prior := runMCPScannerCommand
	t.Cleanup(func() { runMCPScannerCommand = prior })
	runMCPScannerCommand = func(context.Context, *exec.Cmd) error { return context.DeadlineExceeded }
	if _, err := ms.Scan(context.Background(), "notes"); err == nil || MCPScanRefused(err) {
		t.Fatalf("timeout: %v, want a failure that is not a refusal", err)
	}

	// Another scanner's error text: the managed as-user launch refusals.
	for _, text := range []string{
		`mcp-scan: MCP server "notes" is not started in server: the folder is not an absolute path`,
		`MCP server "notes" is not started: launcher C:\tools\npx.cmd is not trusted`,
	} {
		if !MCPScanRefused(errors.New(text)) {
			t.Errorf("MCPScanRefused(%q) = false, want a refusal", text)
		}
	}
	if MCPScanRefused(errors.New("mcp-scanner exited 1")) || MCPScanRefused(nil) {
		t.Error("a plain exit or no error read as a refusal")
	}
}
