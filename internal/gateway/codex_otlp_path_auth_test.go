// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Host installs no longer export native Codex OTLP: Codex cannot prove who
// owns a replaced loopback listener before it sends the scoped bearer. A
// credential an earlier release minted must stop authorizing once host Setup
// runs, Teardown must remove every token artifact, and a later credential must
// never revive the revoked one.
func TestCodexHostSetupAndTeardownRevokeCachedOTLPToken(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed Windows Codex hooks are machine policy that the administrator-owned requirements installer writes; host Setup refuses them")
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write Codex config: %v", err)
	}
	connector.CodexConfigPathOverride = configPath
	defer func() { connector.CodexConfigPathOverride = "" }()

	// The credential an earlier (0.8.10 to 1.0.3) host install left behind.
	first, err := connector.EnsureOTLPPathToken(dir, connector.OTLPScopeCodex)
	if err != nil || first == "" {
		t.Fatalf("seed earlier scoped token: present=%v err=%v", first != "", err)
	}

	api, called := tokenAuthTestServer(t, "gateway-master")
	api.scannerCfg.DataDir = dir
	tokens, err := connector.LoadAllOTLPPathTokens(dir)
	if err != nil {
		t.Fatalf("load gateway path tokens: %v", err)
	}
	api.SetOTLPPathTokens(tokens)
	handler := api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	}))
	request := func(token string) int {
		*called = false
		req := httptest.NewRequest(http.MethodPost, "/otlp/codex/"+token+"/v1/logs", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response.Code
	}
	expireStatThrottle := func() {
		// Expire the bounded stat throttle so the running gateway observes
		// the on-disk change and drops its cached credential.
		api.otlpPathTokenMu.Lock()
		api.otlpPathTokenLastStatAt[connector.OTLPScopeCodex] = time.Now().Add(-2 * otlpPathTokenStatMinInterval)
		api.otlpPathTokenMu.Unlock()
	}
	if got := request(first); got != http.StatusOK || !*called {
		t.Fatal("earlier scoped Codex token was not accepted before the upgrade")
	}

	conn := connector.NewCodexConnector()
	opts := connector.SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", APIToken: "hook-token", ManagedEnterprise: true}
	prepareCodexSetupPolicyFixture(t, dir, &opts)
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("host Setup: %v", err)
	}
	if token, err := connector.LoadOTLPPathToken(dir, connector.OTLPScopeCodex); err != nil || token != "" {
		t.Fatalf("host Setup kept a native Codex OTLP credential: present=%v err=%v", token != "", err)
	}
	expireStatThrottle()
	if got := request(first); got != http.StatusUnauthorized || *called {
		t.Fatal("obsolete Codex OTLP token remained authorized after host Setup")
	}

	// Teardown removes any token artifact, including a legacy staged file.
	second, err := connector.EnsureOTLPPathToken(dir, connector.OTLPScopeCodex)
	if err != nil || second == "" || second == first {
		t.Fatalf("a new credential reused the revoked one: rotated=%v err=%v", second != "" && second != first, err)
	}
	tokenPath, err := connector.OTLPPathTokenFilePath(dir, connector.OTLPScopeCodex)
	if err != nil {
		t.Fatalf("resolve scoped Codex token path: %v", err)
	}
	legacyTempPath := tokenPath + ".tmp"
	if err := os.WriteFile(legacyTempPath, []byte("legacy-staged-token\n"), 0o600); err != nil {
		t.Fatalf("seed legacy scoped-token temp file: %v", err)
	}
	expireStatThrottle()
	if got := request(first); got != http.StatusUnauthorized || *called {
		t.Fatal("revoked Codex token became valid again after a new credential")
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	for _, path := range []string{tokenPath, legacyTempPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("Teardown did not remove scoped Codex token artifact %s: %v", filepath.Base(path), err)
		}
	}
	expireStatThrottle()
	if got := request(second); got != http.StatusUnauthorized || *called {
		t.Fatal("Codex OTLP token remained authorized after teardown")
	}
}

func TestTokenAuth_CodexScopedOTLPPathCoversEverySignal(t *testing.T) {
	t.Parallel()
	const gatewayToken = "gateway-master-must-not-authorize-codex-scoped-otlp"
	pathToken := strings.Repeat("c", 64)

	for _, signal := range []string{"logs", "metrics", "traces"} {
		signal := signal
		t.Run(signal, func(t *testing.T) {
			t.Parallel()
			api, called := tokenAuthTestServer(t, gatewayToken)
			api.SetOTLPPathTokens(map[connector.OTLPPathTokenScope]string{
				connector.OTLPScopeCodex: pathToken,
			})
			handler := api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				*called = true
				w.WriteHeader(http.StatusOK)
			}))

			request := httptest.NewRequest(
				http.MethodPost,
				"/otlp/codex/"+pathToken+"/v1/"+signal,
				nil,
			)
			request.RemoteAddr = "127.0.0.1:54321"
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK || !*called {
				t.Fatalf("Codex scoped OTLP %s request was not authenticated", signal)
			}
		})
	}
}

func TestSanitizeRouteForTelemetry_RedactsCodexOTLPPathToken(t *testing.T) {
	t.Parallel()
	token := strings.Repeat("c", 64)
	got := sanitizeRouteForTelemetry("/otlp/codex/" + token + "/v1/traces")
	if strings.Contains(got, token) || got != "/otlp/codex/_token_/v1/traces" {
		t.Fatal("Codex OTLP route telemetry retained the scoped credential")
	}
}

func TestTokenAuth_CodexOTLPTokenHasNoCrossRouteAuthority(t *testing.T) {
	t.Parallel()
	const gatewayToken = "gateway-master"
	codexToken := strings.Repeat("c", 64)
	claudeToken := strings.Repeat("d", 64)

	tests := []struct {
		name   string
		path   string
		header string
		wantOK bool
	}{
		{name: "codex scope", path: "/otlp/codex/" + codexToken + "/v1/logs", wantOK: true},
		{name: "cross connector", path: "/otlp/claudecode/" + codexToken + "/v1/logs"},
		{name: "shared receiver", path: "/v1/logs", header: codexToken},
		{name: "header rejected on scoped path", path: "/otlp/codex/" + codexToken + "/v1/logs", header: gatewayToken},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			api, called := tokenAuthTestServer(t, gatewayToken)
			api.SetOTLPPathTokens(map[connector.OTLPPathTokenScope]string{
				connector.OTLPScopeCodex:  codexToken,
				connector.OTLPScopeClaude: claudeToken,
			})
			handler := api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				*called = true
				w.WriteHeader(http.StatusOK)
			}))
			request := httptest.NewRequest(http.MethodPost, test.path, nil)
			request.RemoteAddr = "127.0.0.1:54321"
			if test.header != "" {
				request.Header.Set("X-DefenseClaw-Token", test.header)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if test.wantOK {
				if response.Code != http.StatusOK || !*called {
					t.Fatal("valid scoped Codex OTLP route was rejected")
				}
				return
			}
			if response.Code != http.StatusUnauthorized || *called {
				t.Fatal("Codex OTLP credential escaped its connector-scoped route")
			}
		})
	}
}
