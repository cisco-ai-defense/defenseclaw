// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-0858: a removed connector whose teardown removed its hook registration
// but could not delete its scoped hook credential was accepted by
// VerifyClean, its lock cleared and the connector marked removed, while the
// token file still authenticated to its hook route. A teardown that failed
// is now finished only once the credential is gone: until then the removal
// stays pending (failed, lock kept) for the next start to retry. A teardown
// that failed for another reason after revoking the credential, one that
// succeeded and a managed deployment are unchanged.
func TestRemovedConnectorWithAFailedCredentialRevocationStaysPending(t *testing.T) {
	revokeFailed := errors.New("codex teardown: codex revoke removed hook credential: remove hook API token: Access is denied")
	for _, tc := range []struct {
		name        string
		teardownErr error
		keepToken   bool
		managed     bool
		wantPending bool
	}{
		{name: "the credential could not be deleted", teardownErr: revokeFailed, keepToken: true, wantPending: true},
		{name: "another teardown error after the credential went", teardownErr: errors.New("revoke scoped OTLP token: busy")},
		{name: "a teardown that succeeded", keepToken: true},
		{name: "a managed deployment", teardownErr: revokeFailed, keepToken: true, managed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			if tc.keepToken {
				if _, err := connector.EnsureHookAPIToken(dataDir, "codex"); err != nil {
					t.Fatal(err)
				}
			}
			opts := connector.SetupOpts{DataDir: dataDir, ManagedEnterprise: tc.managed}
			for _, path := range []string{"multi-connector removal", "connector switch"} {
				conn := &recordingConnector{stubConnector: stubConnector{name: "codex"}, teardownErr: tc.teardownErr}
				other := &recordingConnector{stubConnector: stubConnector{name: "cursor"}}
				reg := newRecordingRegistry(conn, other)
				var pending bool
				var detail string
				if path == "multi-connector removal" {
					failed, _ := teardownRemovedConnectorsReport(reg, []string{"codex", "cursor"}, []string{"cursor"}, opts, "", context.Background())
					pending = len(failed) == 1 && failed[0] == "codex"
					detail = strings.Join(failed, ",")
				} else {
					if err := connector.SaveActiveConnector(dataDir, "codex"); err != nil {
						t.Fatal(err)
					}
					err := teardownPreviousConnector(reg, "cursor", opts, context.Background())
					pending = err != nil
					if err != nil {
						detail = err.Error()
					}
				}
				if pending != tc.wantPending {
					t.Fatalf("%s: removal pending = %t (%s), want %t", path, pending, detail, tc.wantPending)
				}
				if tc.wantPending && path == "connector switch" && !strings.Contains(detail, "hook credential") {
					t.Fatalf("%s: the error does not name the credential: %s", path, detail)
				}
			}
		})
	}
}

// GAP-0858 clause 2: while that removal is pending, the gateway refused the
// connector's hook calls only after the token file was gone; until then
// tokenAuth loaded the kept file and served the removed connector's hook
// route with it. The kept credential is now refused at authentication from
// the failed teardown on, other connectors keep theirs, and a setup that
// issues the credential again (re-adding the connector) is served again.
// Managed deployments, whose credentials the machine lifecycle revokes,
// keep the token they have.
func TestRemovedConnectorCredentialIsRefusedWhileItsRevocationIsPending(t *testing.T) {
	revokeFailed := errors.New("codex teardown: codex revoke removed hook credential: remove hook API token: Access is denied")
	for _, tc := range []struct {
		name        string
		managed     bool
		wantRefused bool
	}{
		{name: "per-user", wantRefused: true},
		{name: "managed", managed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := testenv.PrivateTempDir(t)
			dataDir := filepath.Join(home, ".defenseclaw")
			if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
				t.Fatal(err)
			}
			codexToken, err := connector.EnsureHookAPIToken(dataDir, "codex")
			if err != nil {
				t.Fatal(err)
			}
			claudeToken, err := connector.EnsureHookAPIToken(dataDir, "claudecode")
			if err != nil {
				t.Fatal(err)
			}
			api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, nil, nil)
			api.scannerCfg = &config.Config{}
			api.scannerCfg.Gateway.Token = "master-token"
			api.scannerCfg.DataDir = dataDir
			call := func(path, token string) int {
				t.Helper()
				request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
				request.RemoteAddr = "127.0.0.1:40000"
				request.Header.Set("Authorization", "Bearer "+token)
				response := httptest.NewRecorder()
				api.tokenAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })).ServeHTTP(response, request)
				return response.Code
			}
			codexPath, claudePath := hookPathFor(t, "codex"), hookPathFor(t, "claudecode")
			if code := call(codexPath, codexToken); code != http.StatusTeapot {
				t.Fatalf("codex hook with its token before the removal: status %d, want it served", code)
			}

			opts := connector.SetupOpts{DataDir: dataDir, ManagedEnterprise: tc.managed}
			conn := &recordingConnector{stubConnector: stubConnector{name: "codex"}, teardownErr: revokeFailed}
			other := &recordingConnector{stubConnector: stubConnector{name: "claudecode"}}
			failed, _ := teardownRemovedConnectorsReport(newRecordingRegistry(conn, other), []string{"codex", "claudecode"}, []string{"claudecode"}, opts, "", context.Background())
			if pending := len(failed) == 1 && failed[0] == "codex"; pending != !tc.managed {
				t.Fatalf("removal pending = %t (%v), want %t", pending, failed, !tc.managed)
			}
			if _, err := os.Lstat(filepath.Join(dataDir, "hooks", ".hook-codex.token")); err != nil {
				t.Fatalf("the fixture lost the kept codex token: %v", err)
			}

			want := http.StatusTeapot
			if tc.wantRefused {
				want = http.StatusUnauthorized
			}
			if code := call(codexPath, codexToken); code != want {
				t.Fatalf("codex hook with the kept token while the removal is pending: status %d, want %d", code, want)
			}
			if code := call(claudePath, claudeToken); code != http.StatusTeapot {
				t.Fatalf("claudecode hook with its token: status %d, want it served", code)
			}
			if code := call(codexPath, "master-token"); code != http.StatusTeapot {
				t.Fatalf("codex hook with the master token: status %d, want it served as before", code)
			}

			// Setting the connector up again issues the same credential.
			if again, err := connector.EnsureHookAPIToken(dataDir, "codex"); err != nil || again != codexToken {
				t.Fatalf("re-issue the codex token: %v (same token %t)", err, again == codexToken)
			}
			if code := call(codexPath, codexToken); code != http.StatusTeapot {
				t.Fatalf("codex hook after the connector was set up again: status %d, want it served", code)
			}
		})
	}
}

func hookPathFor(t *testing.T, name string) string {
	t.Helper()
	conn, ok := sharedDefaultRegistry().Get(name)
	if !ok {
		t.Fatalf("no built-in %s connector", name)
	}
	endpoint, ok := conn.(connector.HookEndpoint)
	if !ok {
		t.Fatalf("%s has no hook endpoint", name)
	}
	return endpoint.HookAPIPath()
}
