// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// GAP-0185: a configured mcp-scanner path that does not exist is "not
// installed", as a bare name not on PATH is, so the runtime's config rules
// decide instead of a failed scan refusing every server.
func TestGAP0185MissingMCPScannerPathIsUnavailable(t *testing.T) {
	for _, bin := range []string{"dc-gap0185-no-mcp-scanner", filepath.Join(t.TempDir(), "mcp-scanner")} {
		_, err := (&MCPStaticScanner{Binary: bin}).Scan(context.Background(), filepath.Join(t.TempDir(), "tools.json"))
		if !scanner.Unavailable(err) {
			t.Errorf("%s: %v is not unavailable", bin, err)
		}
	}
}

// GAP-0185: one server's in-repository source decides only that server.
func TestGAP0185ServerSourceBelongsToItsServer(t *testing.T) {
	local := MCPServer{Name: "notes", Transport: "stdio", Command: "python3", Args: []string{"srv.py"}}
	pkg := MCPServer{Name: "fs", Transport: "stdio", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "."}}
	abs := MCPServer{Name: "abs", Transport: "stdio", Command: "/work/repo/bin/srv.js"}
	for _, c := range []struct {
		s    MCPServer
		p    string
		want bool
	}{
		{local, "/work/repo/srv.py", true},
		{local, "/work/repo/other.py", false},
		{pkg, "/work/repo/srv.py", false},
		{abs, "/work/repo/bin/srv.js", true},
		{abs, "/work/repo/srv.js", false},
	} {
		if got := serverStarts(c.s, c.p); got != c.want {
			t.Errorf("%s starts %s = %v, want %v", c.s.Name, c.p, got, c.want)
		}
	}
}
