// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
)

// A mistake in --mcp is a usage error (exit 2) found before the cluster is
// asked anything: run and connect both read the flag the same way.
func TestSubstrateMCPFlagErrors(t *testing.T) {
	self := os.Args[0]
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no equals", []string{"--mcp", "files"}, "mcp_spec_invalid"},
		{"empty name", []string{"--mcp", "=cmd"}, "mcp_spec_invalid"},
		{"bad name", []string{"--mcp", "Files=" + self}, "mcp_spec_invalid"},
		{"empty command", []string{"--mcp", "files="}, "mcp_spec_invalid"},
		{"unclosed double quote", []string{"--mcp", "files=prog \"x"}, "mcp_spec_invalid"},
		{"duplicate", []string{"--mcp", "files=" + self, "--mcp", "files=" + self}, "mcp_name_duplicate"},
		{"command missing", []string{"--mcp", "files=/no/such/dc-mcp-tool"}, "mcp_command_missing"},
	}
	if runtime.GOOS != "windows" {
		// Only POSIX splitting treats a single quote as quoting. On Windows it
		// is an ordinary character (C:\Users\O'Brien\srv.exe must work as
		// typed), so there is no unclosed quote to report; see
		// TestParseMCPSpec in the attach package.
		cases = append(cases, struct {
			name string
			args []string
			want string
		}{"unclosed single quote", []string{"--mcp", "files=prog 'x"}, "mcp_spec_invalid"})
	}
	for _, tc := range cases {
		for _, sub := range []string{"run", "connect"} {
			cmd := newSubstrateRunCmd()
			args := append([]string{"claude"}, tc.args...)
			if sub == "connect" {
				cmd = newSubstrateConnectCmd()
				args = append([]string{"web-3f2a"}, tc.args...)
			}
			_, _, err := runSubstrate(t, cmd, args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) || cliusage.ExitCode(err) != 2 {
				t.Errorf("%s %s: err = %v (exit %d); want %s with exit 2", sub, tc.name, err, cliusage.ExitCode(err), tc.want)
			}
		}
	}
	// A bridge lasts while the launcher is attached.
	for _, extra := range [][]string{{"--task", "x", "--detach"}, {"--batch", "tasks.yaml"}} {
		args := append([]string{"claude", "--mcp", "files=" + self}, extra...)
		_, _, err := runSubstrate(t, newSubstrateRunCmd(), args...)
		if err == nil || cliusage.ExitCode(err) != 2 || !strings.Contains(err.Error(), "--mcp") {
			t.Errorf("--mcp with %v: %v (exit %d)", extra, err, cliusage.ExitCode(err))
		}
	}
}

// --mcp is a per-run action: no config key and no environment variable.
func TestSubstrateMCPIsNotASetting(t *testing.T) {
	t.Setenv("DEFENSECLAW_SUBSTRATE_MCP", "files="+os.Args[0])
	specs, err := substrateMCPSpecs(nil, false, false)
	if err != nil || specs != nil {
		t.Fatalf("no flag gave %v, %v", specs, err)
	}
}

// A --task run in which no requested server could be bridged exits 1; one in
// which some were bridged, or none were asked for, does not.
func TestSubstrateMCPNone(t *testing.T) {
	specs := []attach.MCPSpec{{Name: "a"}, {Name: "b"}}
	if err := substrateMCPNone(nil, nil); err != nil {
		t.Errorf("no --mcp: %v", err)
	}
	none := &substrateMCPRun{asked: 2, bridges: &attach.MCPBridges{Refused: 2}}
	err := substrateMCPNone(none, specs)
	if err == nil || cliusage.ExitCode(err) != 1 || !strings.Contains(err.Error(), "a, b") {
		t.Errorf("all refused: %v (exit %d)", err, cliusage.ExitCode(err))
	}
	some := &substrateMCPRun{asked: 2, bridges: &attach.MCPBridges{Opened: 1, Refused: 1}}
	if err := substrateMCPNone(some, specs); err != nil {
		t.Errorf("one bridged: %v", err)
	}
}

// The flag says Preview and names no tested claim.
func TestSubstrateMCPFlagHelp(t *testing.T) {
	run := newSubstrateRunCmd().Flags().Lookup("mcp")
	conn := newSubstrateConnectCmd().Flags().Lookup("mcp")
	if run == nil || conn == nil || !strings.Contains(run.Usage, "Preview") || run.Usage != conn.Usage {
		t.Fatalf("--mcp flags: %+v %+v", run, conn)
	}
}

// The docs reference rows are written from the one table of codes and lines.
func TestSubstrateMCPDocsRowsMatchTable(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs-site", "content", "docs", "substrate", "reference.mdx"))
	if err != nil {
		t.Skipf("no docs tree here: %v", err)
	}
	doc := string(b)
	for _, m := range attach.MCPMessages {
		if !strings.Contains(doc, "| "+m.Line+" | `"+m.Code+"` |") {
			t.Errorf("reference.mdx has no row for %s: %q", m.Code, m.Line)
		}
	}
}
