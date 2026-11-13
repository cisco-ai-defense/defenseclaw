// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// These tests render the sandbox artifacts of an image, which OpenShell does not do on Windows hosts.
//go:build !windows

package templatecli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// GAP-0052 through the shipped command: template build --from BASE --to
// TARGET with one registry login must not send that login to the base
// image's registry (a template author picks the base reference).
func TestBuildSendsTheLoginOnlyToTheTargetRegistry(t *testing.T) {
	const pw = "MARKER-PASSWORD-f6-cli"
	type seen struct {
		mu    sync.Mutex
		auths []string
	}
	serve := func(s *seen) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.mu.Lock()
			s.auths = append(s.auths, r.Header.Get("Authorization"))
			s.mu.Unlock()
			w.Header().Set("Www-Authenticate", `Basic realm="r"`)
			w.WriteHeader(http.StatusUnauthorized)
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	var base, target seen
	baseSrv, targetSrv := serve(&base), serve(&target)
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	bin := filepath.Join(dir, "bin")
	for _, f := range []string{pwFile, bin} {
		if err := os.WriteFile(f, []byte(pw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	host := func(s *httptest.Server) string { return strings.TrimPrefix(s.URL, "http://") }
	var out, errOut bytes.Buffer
	code := Run(context.Background(), []string{"build", "--connector", "codex",
		"--from", host(baseSrv) + "/harness/codex:v1", "--to", host(targetSrv) + "/tmpl/codex:v1",
		"--hook-binary", bin, "--relay-binary", bin, "--dry-run", "--keep-entrypoint",
		"--registry-user", "svc", "--registry-password-file", pwFile}, &out, &errOut)
	if code == ExitOK {
		t.Fatalf("a base registry that refuses anonymous pulls cannot build: %s", out.String())
	}
	base.mu.Lock()
	defer base.mu.Unlock()
	if len(base.auths) == 0 {
		t.Fatalf("the build never reached the base registry (test is not testing anything): %s", errOut.String())
	}
	for _, a := range base.auths {
		if a != "" {
			t.Fatalf("the --from registry got the login: %q", base.auths)
		}
	}
	if strings.Contains(errOut.String()+out.String(), pw) {
		t.Fatal("the password was printed")
	}
}
