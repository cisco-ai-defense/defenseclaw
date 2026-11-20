// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/auth"
)

// GAP-0406: `logs NAME` of a finished headless task printed nothing and
// exited 0 when the agent took longer than 3 s to answer (a woken or busy
// actor, a loaded cluster): the snapshot window counted the wait for the
// attach route, so the read was cancelled before the log arrived.
func TestGAP0406LogsOfAFinishedTaskWaitsForASlowAgent(t *testing.T) {
	const prefix = "/api/v1/substrate/actors/eng-web/fix-tests-1/attach/"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			http.Error(w, `{"error":"Unauthorized","reason":"missing"}`, http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/substrate/actors":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(sampleActors())
		case r.URL.Path == prefix+"status":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": map[string]any{
				"t-1": map[string]any{"started": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), "exit_code": 0}}})
		case r.URL.Path == prefix+"task/t-1":
			// The agent answers late: the actor was woken for the read.
			time.Sleep(4500 * time.Millisecond)
			w.Header().Set("Content-Type", "application/x-ndjson")
			for _, line := range []string{`{"type":"start","id":"t-1"}`, `{"type":"stdout","data":"ok"}`, `{"type":"exit","code":0}`} {
				fmt.Fprintln(w, line)
			}
		default:
			http.Error(w, `{"error":"Not Found","reason":"not_found"}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "admin-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	claims, _ := json.Marshal(map[string]any{"sub": "user-1", "email": "dev@example.test", "exp": time.Now().Add(time.Hour).Unix(), "iss": "https://sso.example.test", "aud": []string{"defenseclaw"}})
	tokFile := filepath.Join(t.TempDir(), "workload-token")
	if err := os.WriteFile(tokFile, []byte("e30."+base64.RawURLEncoding.EncodeToString(claims)+".c2ln"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := substrateOpen
	substrateOpen = func(*cobra.Command, *substrateCommon) (*substrateSession, error) {
		c := auth.Context{AdminURL: srv.URL, AdminCAFile: caFile, Profile: "eng"}
		src := auth.NewSource("test", c, nil, auth.SourceOptions{Workload: &auth.WorkloadOptions{TokenFile: tokFile}})
		cl, err := api.New(api.Options{Base: srv.URL, Token: src.Token, HTTP: srv.Client()})
		if err != nil {
			return nil, err
		}
		return &substrateSession{Name: "test", Ctx: c, Source: src, Bearer: src.Token, Client: cl}, nil
	}
	t.Cleanup(func() { substrateOpen = old })
	out, errOut, err := runSubstrate(t, newSubstrateLogsCmd(), "fix-tests-1")
	if err != nil {
		t.Fatalf("logs: %v (stderr %q)", err, errOut)
	}
	if !strings.Contains(out, "ok") {
		t.Fatalf("logs of a finished task printed %q (stderr %q): the output is lost", out, errOut)
	}
}
