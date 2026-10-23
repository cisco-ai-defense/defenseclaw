// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Review fix (G-deadcode loop round 3): an upgraded host keeps the OpenHands
// hook token (removed.go keepHookToken). Once 1.0.4 no longer shipped the
// connector, a plugin named openhands registered, the gateway loaded the
// kept token for it and accepted it on loopback /api/v1/inspect/* calls
// scoped to openhands. The names of the removed connectors stay reserved
// (under every spelling the teardown accepts), and their tokens authenticate
// nothing: not on the inspect routes, not on the foreign-hook-session route,
// not from the snapshot the gateway loads at start, even when a registry
// holds the name some other way. Delete with connector/removed.go in 1.1.
func TestRemovedConnectorTokensAuthenticateNothing(t *testing.T) {
	home := testenv.PrivateTempDir(t)
	restore, err := connector.BindUserHomeDir(home)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restore)
	dataDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	tokens := map[string]string{}
	for _, name := range []string{"openhands", "omnigent", "codex"} {
		token, err := connector.EnsureHookAPIToken(dataDir, name)
		if err != nil || token == "" {
			t.Fatalf("mint the %s hook token: %q, %v", name, token, err)
		}
		tokens[name] = token
	}

	// No plugin can take a removed connector's name.
	registry := connector.NewDefaultRegistry()
	for _, name := range []string{"openhands", "OpenHands", "open-hands", "open_hands", " openhands ", "omnigent", "OmniGent"} {
		err := registry.RegisterPlugin(&stubConnector{name: name})
		if err == nil || !strings.Contains(err.Error(), "removed") {
			t.Fatalf("RegisterPlugin(%q) = %v, want a refusal that names the removed connector", name, err)
		}
		if _, ok := registry.Get(name); ok {
			t.Fatalf("the refused plugin %q is in the registry", name)
		}
	}

	// A registry that holds the names anyway: the tokens still
	// authenticate nothing.
	held := connector.NewDefaultRegistry()
	held.RegisterBuiltin(&stubConnector{name: "openhands"})
	held.RegisterBuiltin(&stubConnector{name: "omnigent"})
	loaded, err := connector.LoadHookAPITokens(dataDir, append(held.Names(), "OpenHands", "open-hands"))
	if err != nil {
		t.Fatal(err)
	}
	for scope := range loaded {
		if connector.IsRemovedConnector(scope) {
			t.Fatalf("the gateway loaded the %s hook token as an authentication scope: %v", scope, keysOf(loaded))
		}
	}
	if loaded["codex"] != tokens["codex"] {
		t.Fatalf("the codex hook token was not loaded: %v", keysOf(loaded))
	}

	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
	api.scannerCfg = &config.Config{}
	api.scannerCfg.Gateway.Token = "master-token"
	api.scannerCfg.DataDir = dataDir
	api.connectorRegistry = held
	// The snapshot of an older start that held them.
	api.SetHookAPITokens(map[string]string{"openhands": tokens["openhands"], "omnigent": tokens["omnigent"], "codex": tokens["codex"]})
	call := func(path, scope, token string) int {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		request.RemoteAddr = "127.0.0.1:40000"
		request.Header.Set("Authorization", "Bearer "+token)
		if scope != "" {
			request.Header.Set("X-DefenseClaw-Connector", scope)
		}
		response := httptest.NewRecorder()
		api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })).ServeHTTP(response, request)
		return response.Code
	}
	for _, name := range []string{"openhands", "omnigent"} {
		for _, scope := range []string{name, strings.ToUpper(name), " " + name + " "} {
			if code := call("/api/v1/inspect/tool", scope, tokens[name]); code != http.StatusUnauthorized {
				t.Fatalf("/api/v1/inspect/tool scoped %q with the kept %s token: status %d, want 401", scope, name, code)
			}
		}
		if code := call(enterprisepolicy.ForeignHookSessionPathPrefix+name, "", tokens[name]); code != http.StatusUnauthorized {
			t.Fatalf("the foreign-hook-session route of %s with its kept token: status %d, want 401", name, code)
		}
		if api.hookAPITokenMatches(name, tokens[name]) {
			t.Fatalf("hookAPITokenMatches(%q) accepted its kept token", name)
		}
	}
	// A shipped connector's token still works where it did.
	if code := call("/api/v1/inspect/tool", "codex", tokens["codex"]); code != http.StatusTeapot {
		t.Fatalf("/api/v1/inspect/tool scoped codex with its token: status %d, want it served", code)
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	return out
}
