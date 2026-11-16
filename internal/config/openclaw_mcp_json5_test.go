// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/jsonc"
)

// OpenClaw runs on openclaw.json as JSON5, so the MCP servers it lists are
// read from every spelling it accepts (GAP-0907).
var openClawMCPSpellings = map[string]string{
	"plain json":      `{"gateway":{"port":18789},"mcp":{"servers":{"demo":{"command":"echo"}}}}`,
	"line comments":   "// mine\n{\"gateway\":{\"port\":18789}, // port\n\"mcp\":{\"servers\":{\"demo\":{\"command\":\"echo\"}}}}",
	"block comments":  `{"gateway":{"port":18789},/* a */"mcp":{"servers":{"demo":{"command":"echo"}}}}`,
	"trailing commas": `{"gateway":{"port":18789,},"mcp":{"servers":{"demo":{"command":"echo",},},},}`,
	"hex port":        `{"gateway":{"port":0x4965},"mcp":{"servers":{"demo":{"command":"echo"}}}}`,
	"unquoted keys":   `{gateway:{port:18789},mcp:{servers:{demo:{command:"echo"}}}}`,
	"single quotes":   `{'gateway':{'port':18789},'mcp':{'servers':{'demo':{'command':'echo'}}}}`,
	"all of json5":    "\xef\xbb\xbf// c\n{gateway:{port:0x4965,},mcp:{servers:{demo:{command:'echo',},},},}",
}

func TestOpenClawMCPServersAreReadFromEveryJSON5Spelling(t *testing.T) {
	for name, in := range openClawMCPSpellings {
		t.Run(name, func(t *testing.T) {
			got, err := ParseMCPFromOpenClawConfig([]byte(in))
			if err != nil {
				t.Fatalf("ParseMCPFromOpenClawConfig: %v", err)
			}
			if len(got) != 1 || got[0].Name != "demo" || got[0].Command != "echo" {
				t.Fatalf("servers = %+v, want the one server demo running echo", got)
			}
		})
	}
}

func TestOpenClawMCPConfigWithoutServersListsNone(t *testing.T) {
	got, err := ParseMCPFromOpenClawConfig([]byte(`{gateway:{port:0x4965}}`))
	if err != nil || len(got) != 0 {
		t.Fatalf("servers, err = %+v, %v, want none", got, err)
	}
}

func TestOpenClawMCPConfigThatIsNotJSON5NamesTheLine(t *testing.T) {
	_, err := ParseMCPFromOpenClawConfig([]byte("{\n  mcp: {servers: !},\n}"))
	var syntax *jsonc.SyntaxError
	if !errors.As(err, &syntax) || syntax.Line != 2 {
		t.Fatalf("err = %v, want a syntax error on line 2", err)
	}
}
