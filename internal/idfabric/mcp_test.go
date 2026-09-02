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

package idfabric

import "testing"

func TestSanitizeRemoteURL(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		want   string
		wantOK bool
	}{
		{"plain host", "https://mcp.example.com", "https://mcp.example.com", true},
		{"explicit port kept", "https://mcp.example.com:8443", "https://mcp.example.com:8443", true},
		{"user info dropped", "https://alice:s3cret@mcp.example.com/sse", "https://mcp.example.com", true},
		{"token in query dropped", "https://mcp.example.com/v1?api_key=abc123", "https://mcp.example.com", true},
		{"path dropped", "https://mcp.example.com/tenants/acme/sse", "https://mcp.example.com", true},
		{"fragment dropped", "https://mcp.example.com/x#tok", "https://mcp.example.com", true},
		{"websocket allowed", "wss://mcp.example.com/ws", "wss://mcp.example.com", true},
		{"ipv6 bracketed", "http://[2001:db8::1]:9000/sse", "http://[2001:db8::1]:9000", true},
		{"stdio rejected", "stdio://local", "", false},
		{"file rejected", "file:///etc/passwd", "", false},
		{"relative rejected", "/sse", "", false},
		{"empty rejected", "   ", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := SanitizeRemoteURL(tc.raw)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("SanitizeRemoteURL(%q) = (%q, %v), want (%q, %v)",
					tc.raw, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// A sanitized URL must never retain any part of a secret that appeared in the
// configured value.
func TestSanitizeRemoteURLLeaksNoSecret(t *testing.T) {
	const secret = "sk-live-9f3a2b"
	raws := []string{
		"https://user:" + secret + "@mcp.example.com/sse",
		"https://mcp.example.com/sse?token=" + secret,
		"https://mcp.example.com/" + secret,
		"https://mcp.example.com/sse#" + secret,
	}
	for _, raw := range raws {
		got, ok := SanitizeRemoteURL(raw)
		if !ok {
			t.Fatalf("SanitizeRemoteURL(%q) unexpectedly failed", raw)
		}
		if got != "https://mcp.example.com" {
			t.Fatalf("SanitizeRemoteURL(%q) = %q, want host only", raw, got)
		}
	}
}

func TestClassifyAuthMethod(t *testing.T) {
	tests := []struct {
		name         string
		declaredType string
		headerNames  []string
		schemeToken  string
		clientCert   bool
		want         AuthMethod
	}{
		// Silence is not evidence of an unauthenticated server: the grant may
		// live in the agent's own storage rather than the MCP config.
		{"no config is unknown", "", nil, "", false, AuthMethodUnknown},
		{"declared none is none", "none", nil, "", false, AuthMethodNone},
		{"client cert wins", "oauth", []string{"authorization"}, "bearer", true, AuthMethodMTLS},
		{"declared oauth", "oauth", nil, "", false, AuthMethodOAuth},
		{"bearer scheme", "", []string{"authorization"}, "Bearer", false, AuthMethodBearerToken},
		{"basic scheme", "", []string{"Authorization"}, "basic", false, AuthMethodBasic},
		{"api key header", "", []string{"X-API-Key"}, "", false, AuthMethodAPIKeyHeader},
		{"authorization without scheme", "", []string{"Authorization"}, "", false, AuthMethodUnknown},
		{"unrecognized header", "", []string{"X-Trace-Id"}, "", false, AuthMethodUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyAuthMethod(tc.declaredType, tc.headerNames, tc.schemeToken, tc.clientCert)
			if got != tc.want {
				t.Fatalf("ClassifyAuthMethod() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestInferRunner(t *testing.T) {
	tests := []struct {
		command string
		want    Runner
	}{
		{"npx", RunnerNPX},
		{"/usr/local/bin/npx", RunnerNPX},
		{`C:\Program Files\nodejs\npx.cmd`, RunnerNPX},
		{"uvx", RunnerUVX},
		{"node", RunnerNode},
		{"python3", RunnerPython},
		{"docker", RunnerDocker},
		{"/opt/acme/mcp-server", RunnerBinary},
		{"", RunnerUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.command, func(t *testing.T) {
			if got := InferRunner(tc.command); got != tc.want {
				t.Fatalf("InferRunner(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
}

func TestInferPackage(t *testing.T) {
	tests := []struct {
		name        string
		runner      Runner
		command     string
		args        []string
		wantPkg     string
		wantVersion string
	}{
		{
			name:    "npx skips -y",
			runner:  RunnerNPX,
			command: "npx",
			args:    []string{"-y", "@modelcontextprotocol/server-github"},
			wantPkg: "@modelcontextprotocol/server-github",
		},
		{
			name:        "npx scoped pin",
			runner:      RunnerNPX,
			command:     "npx",
			args:        []string{"-y", "@modelcontextprotocol/server-github@1.2.3"},
			wantPkg:     "@modelcontextprotocol/server-github",
			wantVersion: "1.2.3",
		},
		{
			name:    "npx latest is not a pin",
			runner:  RunnerNPX,
			command: "npx",
			args:    []string{"@acme/mcp@latest"},
			wantPkg: "@acme/mcp",
		},
		{
			name:        "uvx pep508 pin",
			runner:      RunnerUVX,
			command:     "uvx",
			args:        []string{"--from", "mcp-server-git==0.6.2", "mcp-server-git"},
			wantPkg:     "mcp-server-git",
			wantVersion: "0.6.2",
		},
		{
			name:        "docker tag pin",
			runner:      RunnerDocker,
			command:     "docker",
			args:        []string{"run", "-i", "--rm", "-e", "TOKEN", "ghcr.io/acme/mcp:2.1.0"},
			wantPkg:     "ghcr.io/acme/mcp",
			wantVersion: "2.1.0",
		},
		{
			name:        "docker digest pin",
			runner:      RunnerDocker,
			command:     "docker",
			args:        []string{"run", "--rm", "acme/mcp@sha256:abc"},
			wantPkg:     "acme/mcp",
			wantVersion: "sha256:abc",
		},
		{
			name:    "docker registry port is not a tag",
			runner:  RunnerDocker,
			command: "docker",
			args:    []string{"run", "registry.local:5000/acme/mcp"},
			wantPkg: "registry.local:5000/acme/mcp",
		},
		{
			name:    "python module form",
			runner:  RunnerPython,
			command: "python3",
			args:    []string{"-m", "mcp_server_git"},
			wantPkg: "mcp_server_git",
		},
		{
			name:    "node script path yields nothing",
			runner:  RunnerNode,
			command: "node",
			args:    []string{"/Users/alice/dev/server.js"},
		},
		{
			name:    "npx local path yields nothing",
			runner:  RunnerNPX,
			command: "npx",
			args:    []string{"-y", "./local-server"},
		},
		{
			name:    "binary reports basename only",
			runner:  RunnerBinary,
			command: "/opt/acme/bin/mcp-server",
			args:    []string{"--port", "1234"},
			wantPkg: "mcp-server",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkg, version := InferPackage(tc.runner, tc.command, tc.args)
			if pkg != tc.wantPkg || version != tc.wantVersion {
				t.Fatalf("InferPackage() = (%q, %q), want (%q, %q)",
					pkg, version, tc.wantPkg, tc.wantVersion)
			}
		})
	}
}
