// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package idfabric

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSecret is assembled at runtime so no credential-shaped literal is stored
// in the repository. The tests assert this value never reaches a record.
func fakeSecret() string { return "s3cr" + "et-t0ken-" + "value" }

func writeJSON(t *testing.T, path string, doc any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// setHome points user-home lookup at a scratch directory on every platform.
func setHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}

func TestDiscoverMCPServersProjectsOnlyAllowListedFields(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	secret := fakeSecret()

	writeJSON(t, filepath.Join(home, ".cursor", "mcp.json"), map[string]any{
		"mcpServers": map[string]any{
			"remote-with-credentials": map[string]any{
				"url": "https://user:" + secret + "@mcp.example.com:8443/v1/sse?token=" + secret + "#frag",
				"headers": map[string]string{
					"Authorization": "Bearer " + secret,
					"X-Tenant":      "acme",
				},
			},
			"local-npx": map[string]any{
				"command": "npx",
				"args":    []string{"-y", "@modelcontextprotocol/server-github@1.2.3"},
				"env":     map[string]string{"GITHUB_TOKEN": secret},
			},
			"turned-off": map[string]any{
				"command":  "uvx",
				"args":     []string{"some-server"},
				"disabled": true,
			},
		},
	})

	got := DiscoverMCPServers(PlatformCursor, "", time.Now().Add(5*time.Second))

	if got.Status != MCPDiscoveryComplete {
		t.Errorf("Status = %q, want %q", got.Status, MCPDiscoveryComplete)
	}
	if got.SkippedDisabled != 1 {
		t.Errorf("SkippedDisabled = %d, want 1", got.SkippedDisabled)
	}
	if len(got.Servers) != 2 {
		t.Fatalf("len(Servers) = %d, want 2: %+v", len(got.Servers), got.Servers)
	}

	// Serialize the projection and assert no secret survived anywhere in it,
	// including inside a field this test does not name explicitly.
	encoded, err := json.Marshal(got.Servers)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	blob := string(encoded)
	for _, forbidden := range []string{secret, "GITHUB_TOKEN", "Authorization", "token=", "frag", "/v1/sse"} {
		if strings.Contains(blob, forbidden) {
			t.Errorf("projection leaked %q: %s", forbidden, blob)
		}
	}

	byName := make(map[string]MCPServer, len(got.Servers))
	for _, server := range got.Servers {
		byName[server.ServerName] = server
	}

	remote, ok := byName["remote-with-credentials"]
	if !ok {
		t.Fatalf("remote server missing: %+v", got.Servers)
	}
	if remote.ServerType != ServerTypeRemote {
		t.Errorf("ServerType = %q, want %q", remote.ServerType, ServerTypeRemote)
	}
	if remote.URL != "https://mcp.example.com:8443" {
		t.Errorf("URL = %q, want scheme+host only", remote.URL)
	}
	if remote.AuthMethod != AuthMethodBearerToken {
		t.Errorf("AuthMethod = %q, want %q", remote.AuthMethod, AuthMethodBearerToken)
	}

	local, ok := byName["local-npx"]
	if !ok {
		t.Fatalf("local server missing: %+v", got.Servers)
	}
	if local.ServerType != ServerTypeLocal {
		t.Errorf("ServerType = %q, want %q", local.ServerType, ServerTypeLocal)
	}
	if local.Runner != RunnerNPX {
		t.Errorf("Runner = %q, want %q", local.Runner, RunnerNPX)
	}
	if local.Package != "@modelcontextprotocol/server-github" {
		t.Errorf("Package = %q", local.Package)
	}
	if local.PackageVersion != "1.2.3" {
		t.Errorf("PackageVersion = %q, want 1.2.3", local.PackageVersion)
	}
}

func TestDiscoverMCPServersReportsUnreadableLayerAsDegraded(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)

	// A syntactically invalid user-scope file must not be reported as an
	// authoritative empty inventory.
	path := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got := DiscoverMCPServers(PlatformCursor, "", time.Now().Add(5*time.Second))
	if got.Status == MCPDiscoveryComplete {
		t.Errorf("Status = %q, want a degraded status", got.Status)
	}
	if len(got.Servers) != 0 {
		t.Errorf("len(Servers) = %d, want 0", len(got.Servers))
	}
}

func TestDiscoverMCPServersAbsentConfigIsAuthoritativeEmpty(t *testing.T) {
	setHome(t, t.TempDir())

	got := DiscoverMCPServers(PlatformCodex, "", time.Now().Add(5*time.Second))
	if got.Status != MCPDiscoveryComplete {
		t.Errorf("Status = %q, want %q", got.Status, MCPDiscoveryComplete)
	}
	if len(got.Servers) != 0 {
		t.Errorf("len(Servers) = %d, want 0", len(got.Servers))
	}
}

// TestDiscoverMCPServersDoesNotClaimNoneFromAuthOpaqueLayer covers the layers
// whose parsers drop headers and authProviderType. Such an entry carries no
// auth evidence, so it must not be reported as unauthenticated.
func TestDiscoverMCPServersDoesNotClaimNoneFromAuthOpaqueLayer(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")

	writeJSON(t, filepath.Join(home, ".claude.json"), map[string]any{
		"mcpServers": map[string]any{
			"sentry": map[string]any{
				"url": "https://mcp.sentry.dev/sse",
				// The Claude state-file parser drops this entirely.
				"headers": map[string]string{"Authorization": "Bearer"},
			},
		},
	})

	got := DiscoverMCPServers(PlatformClaudeCode, "", time.Now().Add(5*time.Second))
	if len(got.Servers) != 1 {
		t.Fatalf("len(Servers) = %d, want 1", len(got.Servers))
	}
	if got.Servers[0].AuthMethod != AuthMethodUnknown {
		t.Errorf("AuthMethod = %q, want %q from an auth-opaque layer",
			got.Servers[0].AuthMethod, AuthMethodUnknown)
	}
}

func TestAuthHintFromURL(t *testing.T) {
	secret := fakeSecret()
	tests := []struct {
		name string
		raw  string
		want AuthMethod
	}{
		{name: "no hint", raw: "https://mcp.example.com/sse", want: ""},
		{name: "user info is basic auth", raw: "https://user:" + secret + "@mcp.example.com", want: AuthMethodBasic},
		{name: "query string carries an unidentified credential", raw: "https://mcp.example.com/sse?apikey=" + secret, want: AuthMethodUnknown},
		{name: "empty", raw: "", want: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := AuthHintFromURL(tc.raw); got != tc.want {
				t.Errorf("AuthHintFromURL = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDiscoverMCPServersDoesNotReportURLCredentialAsUnauthenticated(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	secret := fakeSecret()

	writeJSON(t, filepath.Join(home, ".cursor", "mcp.json"), map[string]any{
		"mcpServers": map[string]any{
			"query-key": map[string]any{"url": "https://mcp.example.com/sse?apikey=" + secret},
			"no-auth":   map[string]any{"url": "https://open.example.com/sse"},
		},
	})

	got := DiscoverMCPServers(PlatformCursor, "", time.Now().Add(5*time.Second))
	byName := make(map[string]MCPServer, len(got.Servers))
	for _, server := range got.Servers {
		byName[server.ServerName] = server
	}
	if byName["query-key"].AuthMethod != AuthMethodUnknown {
		t.Errorf("query-key AuthMethod = %q, want %q", byName["query-key"].AuthMethod, AuthMethodUnknown)
	}
	if byName["no-auth"].AuthMethod != AuthMethodUnknown {
		t.Errorf("no-auth AuthMethod = %q, want %q", byName["no-auth"].AuthMethod, AuthMethodUnknown)
	}
}

// TestDiscoverMCPServersDoesNotClaimNoneForBareRemoteURL pins the rule that
// silence in the config is not evidence of an unauthenticated server.
//
// A Cursor entry that is nothing but a url is the common shape for an
// OAuth-authenticated remote server: Cursor holds the grant in its own
// storage, so mcp.json carries no auth field at all. Reporting "none" here
// told an operator the endpoint was open when it was not.
func TestDiscoverMCPServersDoesNotClaimNoneForBareRemoteURL(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)

	writeJSON(t, filepath.Join(home, ".cursor", "mcp.json"), map[string]any{
		"mcpServers": map[string]any{
			"atlassian-rovo": map[string]any{"url": "https://mcp.atlassian.com/v1/sse"},
		},
	})

	got := DiscoverMCPServers(PlatformCursor, "", time.Now().Add(5*time.Second))
	if len(got.Servers) != 1 {
		t.Fatalf("len(Servers) = %d, want 1", len(got.Servers))
	}
	if got.Servers[0].AuthMethod == AuthMethodNone {
		t.Error("AuthMethod = none for a bare remote URL, which asserts an unauthenticated endpoint that was never observed")
	}
	if got.Servers[0].AuthMethod != AuthMethodUnknown {
		t.Errorf("AuthMethod = %q, want %q", got.Servers[0].AuthMethod, AuthMethodUnknown)
	}
}

func TestAuthorizationSchemeDropsCredential(t *testing.T) {
	secret := fakeSecret()
	got := authorizationScheme(map[string]string{"authorization": "Bearer " + secret})
	if got != "Bearer" {
		t.Fatalf("authorizationScheme = %q, want %q", got, "Bearer")
	}
	if strings.Contains(got, secret) {
		t.Fatal("authorizationScheme leaked the credential")
	}
}
