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

package attach

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// MCP bridge (B3.3): `defenseclaw substrate run|connect --mcp NAME=CMD`.
// The launcher starts CMD on this computer, only while the agent's shim is
// connected, and carries its JSON-RPC lines over one relay stream. The
// gateway judges every tools/call; the launcher never reads a message.

// MCPMessage is one line the launcher can print about a bridged server: a
// refusal the gateway gave on the stream open, a mistake in the flag, or a
// code the agent's relay sent on the stream. NAME in Line is the server's
// name. The docs reference rows are written from this table.
type MCPMessage struct {
	Code string
	// Where is "cli" (before anything is dialed, exit 2), "gateway" (the
	// refusal of the stream open) or "stream" (a control message).
	Where string
	Line  string
}

// MCPMessages is the one table of codes and lines.
var MCPMessages = []MCPMessage{
	{"mcp_bridge_off", "gateway", "Laptop MCP servers are turned off on this cluster."},
	{"not_your_agent", "gateway", "Only the person who started this agent can bridge MCP servers to it."},
	{"relay_too_old", "gateway", "This agent's image is older than this DefenseClaw. Rebuild its template (`template build`) to use MCP bridges."},
	{"websocket_required", "gateway", "MCP bridges need WebSocket. Your network allows only the long-poll fallback."},
	{"too_many_streams", "gateway", "This agent already has the most bridged MCP servers allowed (mcp_bridge.max_servers)."},
	{"not_found", "gateway", "NAME is not a valid MCP server name (a-z, 0-9, _ and -, up to 32)."},
	{"mcp_server_blocked", "gateway", "NAME is on this cluster's MCP block list, so it cannot be bridged. Ask your administrator."},
	{"relay_unreachable", "gateway", "The cluster could not reach the agent; it may still be starting. Try again in a moment, or check it with: defenseclaw substrate status"},
	{"relay_tls_required", "gateway", "This agent's relay accepts TLS only and its image predates that. Rebuild its template (`template build`) and start a new agent."},
	{"mcp_busy", "stream", "Another launcher already bridges NAME to this agent."},
	{"mcp_spec_invalid", "cli", `--mcp needs NAME=COMMAND, for example --mcp files="npx -y @modelcontextprotocol/server-filesystem ." (NAME: a-z, 0-9, _ and -, up to 32; COMMAND: a command line, no shell).`},
	{"mcp_name_duplicate", "cli", "--mcp NAME is given twice. Give each MCP server its own name."},
	{"mcp_command_missing", "cli", "The command for --mcp NAME was not found on this computer."},
}

// MCPLine returns the line of code with NAME filled in, or "" when the
// table has none.
func MCPLine(code, name string) string {
	for _, m := range MCPMessages {
		if m.Code == code {
			return strings.ReplaceAll(m.Line, "NAME", name)
		}
	}
	return ""
}

// MCPSpecError is a mistake in an --mcp value, found before any stream is
// opened. Code is mcp_spec_invalid, mcp_name_duplicate or
// mcp_command_missing.
type MCPSpecError struct {
	Code string
	Name string
	// Detail says what is wrong in the value (never the command line: it may
	// carry a token).
	Detail string
}

func (e *MCPSpecError) Error() string {
	s := MCPLine(e.Code, e.Name)
	if e.Detail != "" {
		s += " " + e.Detail
	}
	return s + " (" + e.Code + ")"
}

// MCPSpec is one --mcp NAME=CMD.
type MCPSpec struct {
	Name string
	// Argv is CMD split like a shell without a shell: it runs as
	// exec.Command(Argv[0], Argv[1:]...).
	Argv []string
}

// ParseMCPSpec reads one NAME=CMD. It starts nothing and looks nothing up.
func ParseMCPSpec(v string) (MCPSpec, error) {
	name, cmd, ok := strings.Cut(v, "=")
	if !ok {
		return MCPSpec{}, &MCPSpecError{Code: "mcp_spec_invalid", Name: "NAME", Detail: "There is no = in the value."}
	}
	if !relay.MCPNameRE.MatchString(name) {
		return MCPSpec{}, &MCPSpecError{Code: "mcp_spec_invalid", Name: "NAME", Detail: "The name is empty or not a-z, 0-9, _ and -."}
	}
	if strings.TrimSpace(cmd) == "" {
		return MCPSpec{}, &MCPSpecError{Code: "mcp_spec_invalid", Name: name, Detail: "The command is empty."}
	}
	argv, err := SplitMCPCommand(cmd, runtime.GOOS == "windows")
	if err != nil {
		return MCPSpec{}, &MCPSpecError{Code: "mcp_spec_invalid", Name: name, Detail: "The command " + err.Error() + "."}
	}
	return MCPSpec{Name: name, Argv: argv}, nil
}

// ParseMCPSpecs reads every --mcp value: each must parse, no name may
// repeat, and every command must be found. Nothing is started.
func ParseMCPSpecs(values []string) ([]MCPSpec, error) {
	specs := make([]MCPSpec, 0, len(values))
	seen := map[string]bool{}
	for _, v := range values {
		spec, err := ParseMCPSpec(v)
		if err != nil {
			return nil, err
		}
		if seen[spec.Name] {
			return nil, &MCPSpecError{Code: "mcp_name_duplicate", Name: spec.Name}
		}
		seen[spec.Name] = true
		specs = append(specs, spec)
	}
	for _, spec := range specs {
		if err := checkMCPCommand(spec); err != nil {
			return nil, err
		}
	}
	return specs, nil
}

// checkMCPCommand says whether argv[0] is on PATH or an existing file.
func checkMCPCommand(spec MCPSpec) error {
	if _, err := exec.LookPath(spec.Argv[0]); err == nil {
		return nil
	}
	if st, err := os.Stat(spec.Argv[0]); err == nil && !st.IsDir() {
		return nil
	}
	return &MCPSpecError{Code: "mcp_command_missing", Name: spec.Name}
}

// SplitMCPCommand splits s into arguments the way a shell does for quotes
// and backslashes, and for nothing else: no $VAR, no globs, no ~, no pipes
// or redirects (they stay in the argument as typed). Single quotes keep
// everything. Double quotes keep everything except \" and \\. Outside
// quotes a backslash escapes the next character. On a Windows computer
// (windows true) a backslash is only an escape before a double quote, so
// C:\tools\server.exe works as typed.
func SplitMCPCommand(s string, windows bool) ([]string, error) {
	var (
		out   []string
		cur   strings.Builder
		inTok bool
	)
	rs := []rune(s)
	flush := func() {
		if inTok {
			out = append(out, cur.String())
			cur.Reset()
			inTok = false
		}
	}
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		case c == '\'' && !windows:
			inTok = true
			j := i + 1
			for ; j < len(rs) && rs[j] != '\''; j++ {
				cur.WriteRune(rs[j])
			}
			if j >= len(rs) {
				return nil, errors.New("has a single quote that is never closed")
			}
			i = j
		case c == '"':
			inTok = true
			j := i + 1
			closed := false
			for ; j < len(rs); j++ {
				if rs[j] == '"' {
					closed = true
					break
				}
				if rs[j] == '\\' && j+1 < len(rs) && (rs[j+1] == '"' || rs[j+1] == '\\' && !windows) {
					j++
				}
				cur.WriteRune(rs[j])
			}
			if !closed {
				return nil, errors.New("has a double quote that is never closed")
			}
			i = j
		case c == '\\':
			inTok = true
			switch {
			case windows && (i+1 >= len(rs) || rs[i+1] != '"'):
				cur.WriteRune(c)
			case i+1 >= len(rs):
				return nil, errors.New("ends in a backslash")
			default:
				i++
				cur.WriteRune(rs[i])
			}
		default:
			inTok = true
			cur.WriteRune(c)
		}
	}
	flush()
	if len(out) == 0 {
		return nil, errors.New("is empty")
	}
	if out[0] == "" {
		return nil, errors.New("starts with an empty word")
	}
	return out, nil
}
