// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"errors"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func specCode(err error) string {
	var se *MCPSpecError
	if errors.As(err, &se) {
		return se.Code
	}
	return ""
}

type mcpSpecCase struct {
	in   string
	name string
	argv []string
}

// TestParseMCPSpec: B3.3 --mcp NAME=CMD. On POSIX the command splits on
// quotes and backslashes only; $VAR, globs, ~ and pipes stay as typed, and
// nothing runs through a shell. On Windows ParseMCPSpec uses the Windows
// split by design (no single quote, a backslash is literal except before a
// double quote), so the quoting cases are per GOOS and each table pins what
// that split really does.
func TestParseMCPSpec(t *testing.T) {
	good := []mcpSpecCase{
		{"files=npx -y @modelcontextprotocol/server-filesystem .", "files", []string{"npx", "-y", "@modelcontextprotocol/server-filesystem", "."}},
		{"a=/usr/bin/true", "a", []string{"/usr/bin/true"}},
		{"my_srv-2=prog  two   spaces", "my_srv-2", []string{"prog", "two", "spaces"}},
		{"x=prog $HOME * ~ a|b >out ${X} `id` $(id) ;", "x", []string{"prog", "$HOME", "*", "~", "a|b", ">out", "${X}", "`id`", "$(id)", ";"}},
		{"x=prog --token=a=b", "x", []string{"prog", "--token=a=b"}},
	}
	bad := []string{
		"", "noequals", "=cmd", "Bad=cmd", "-x=cmd", "_x=cmd", strings.Repeat("a", 33) + "=cmd", "a b=cmd", "a/b=cmd", "x=", "x=   ",
		`x=prog "unterminated`, `x=""`,
	}
	if runtime.GOOS == "windows" {
		good = append(good,
			// A single quote is an ordinary character; a backslash is
			// literal unless it sits before a double quote.
			mcpSpecCase{`q=prog "a b" 'c d' e\ f g"h i"j`, "q", []string{"prog", "a b", "'c", "d'", `e\`, "f", "gh ij"}},
			mcpSpecCase{`q=prog "say \"hi\"" 'it\n' "back\\slash" ""`, "q", []string{"prog", `say "hi"`, `'it\n'`, `back\\slash`, ""}},
			mcpSpecCase{`w=C:\tools\srv.exe --root "C:\Program Files\x"`, "w", []string{`C:\tools\srv.exe`, "--root", `C:\Program Files\x`}},
			mcpSpecCase{`x=prog 'unterminated`, "x", []string{"prog", `'unterminated`}},
			mcpSpecCase{`x=prog trailing\`, "x", []string{"prog", `trailing\`}},
		)
		// \" inside quotes is an escaped quote, so this one never closes.
		bad = append(bad, `x=prog "C:\dir\"`)
	} else {
		good = append(good,
			mcpSpecCase{`q=prog "a b" 'c d' e\ f g"h i"j`, "q", []string{"prog", "a b", "c d", "e f", "gh ij"}},
			mcpSpecCase{`q=prog "say \"hi\"" 'it\n' "back\\slash" ""`, "q", []string{"prog", `say "hi"`, `it\n`, `back\slash`, ""}},
		)
		bad = append(bad, `x=prog 'unterminated`, `x=prog trailing\`)
	}
	for _, tc := range good {
		spec, err := ParseMCPSpec(tc.in)
		if err != nil {
			t.Errorf("ParseMCPSpec(%q): %v", tc.in, err)
			continue
		}
		if spec.Name != tc.name || !reflect.DeepEqual(spec.Argv, tc.argv) {
			t.Errorf("ParseMCPSpec(%q) = %q %q; want %q %q", tc.in, spec.Name, spec.Argv, tc.name, tc.argv)
		}
	}
	for _, b := range bad {
		spec, err := ParseMCPSpec(b)
		if err == nil || specCode(err) != "mcp_spec_invalid" {
			t.Errorf("ParseMCPSpec(%q) = %+v, %v; want mcp_spec_invalid", b, spec, err)
		}
	}
	if _, err := ParseMCPSpec(strings.Repeat("a", 32) + "=cmd"); err != nil {
		t.Errorf("a 32-character name: %v", err)
	}
}

// A Windows path keeps its backslashes; only \" is an escape there.
func TestSplitMCPCommandWindows(t *testing.T) {
	got, err := SplitMCPCommand(`C:\tools\srv.exe "C:\Program Files\x" "say \"hi\"" 'lit'`, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{`C:\tools\srv.exe`, `C:\Program Files\x`, `say "hi"`, `'lit'`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q; want %q", got, want)
	}
}

func TestParseMCPSpecsDuplicateAndMissing(t *testing.T) {
	self := os.Args[0]
	if _, err := ParseMCPSpecs([]string{"a=" + self, "b=" + self, "a=" + self}); specCode(err) != "mcp_name_duplicate" {
		t.Fatalf("duplicate name: %v", err)
	}
	// A duplicate is refused before a missing command is looked for.
	if _, err := ParseMCPSpecs([]string{"a=/no/such/dc-mcp-tool", "a=" + self}); specCode(err) != "mcp_name_duplicate" {
		t.Fatalf("duplicate before lookup: %v", err)
	}
	if _, err := ParseMCPSpecs([]string{"a=" + self, "b=/no/such/dc-mcp-tool --x"}); specCode(err) != "mcp_command_missing" || !strings.Contains(err.Error(), "b") {
		t.Fatalf("missing command: %v", err)
	}
	if _, err := ParseMCPSpecs([]string{"a"}); specCode(err) != "mcp_spec_invalid" {
		t.Fatalf("bad spec: %v", err)
	}
	specs, err := ParseMCPSpecs([]string{"a=" + self + " -x", "b=" + self})
	if err != nil || len(specs) != 2 || specs[0].Name != "a" || specs[1].Argv[0] != self {
		t.Fatalf("good specs: %+v, %v", specs, err)
	}
	// An error never prints the command line, which may carry a token.
	_, err = ParseMCPSpecs([]string{"a=/no/such/dc-mcp-tool --token=SECRET123"})
	if err == nil || strings.Contains(err.Error(), "SECRET123") {
		t.Fatalf("error shows the command line: %v", err)
	}
}

// Every code of the table has a line, and the three CLI codes are the
// contract's.
func TestMCPMessagesTable(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range MCPMessages {
		if m.Code == "" || m.Line == "" || seen[m.Code] {
			t.Errorf("bad or repeated row %+v", m)
		}
		seen[m.Code] = true
		switch m.Where {
		case "cli", "gateway", "stream":
		default:
			t.Errorf("row %s: Where %q", m.Code, m.Where)
		}
	}
	for _, c := range []string{"mcp_spec_invalid", "mcp_name_duplicate", "mcp_command_missing", "mcp_bridge_off", "not_your_agent", "relay_too_old",
		"websocket_required", "too_many_streams", "not_found", "relay_unreachable", "relay_tls_required"} {
		if !seen[c] {
			t.Errorf("no row for %s", c)
		}
	}
	if got := MCPLine("not_found", "web"); !strings.HasPrefix(got, "web is not a valid MCP server name") {
		t.Errorf("not_found line: %q", got)
	}
}
