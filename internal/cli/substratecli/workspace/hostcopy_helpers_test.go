// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The host copy runs on Linux and macOS (OpenShell sandboxes are not supported on Windows hosts); its tests use POSIX paths.
//go:build unix

package workspace

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// Helpers for the host-copy and clone tests. They run on every OS, Windows
// included (the unix helpers in helpers_test.go do not).

const hcToken = "hc-session-token"

type hcBearer string

func (b hcBearer) Verify(_ context.Context, r *http.Request) (relay.Session, error) {
	if relay.TokenFrom(r) != string(b) {
		return relay.Session{}, relay.ErrNoToken
	}
	return relay.Session{Person: "alice@example.test", Actor: "t-ns/actor-1"}, nil
}

type hcEnv struct {
	t                   *testing.T
	home, data, project string
}

func newHCEnv(t *testing.T) *hcEnv {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	e := &hcEnv{t: t, home: filepath.Join(root, "home"), data: filepath.Join(root, "data"), project: filepath.Join(root, "myapp")}
	for _, d := range []string{e.home, e.data, e.project} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The relay keeps copy state under its home: a test home.
	t.Setenv("HOME", filepath.Join(root, "relay-home"))
	t.Setenv("USERPROFILE", filepath.Join(root, "relay-home"))
	return e
}

func (e *hcEnv) git(dir string, args ...string) string {
	e.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com", "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		e.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func hcWrite(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// hcActor is a real relay handler whose working directory is a temporary
// directory, and a client of it.
func hcActor(t *testing.T) (string, *Client) {
	t.Helper()
	cfg := kit.DefaultConfig()
	wd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Relay.Workdir = filepath.ToSlash(wd)
	s := relay.NewServer(relay.Options{
		Config: cfg, Verifier: hcBearer(hcToken),
		Log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warm: func(context.Context, string) error { return nil },
	})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return wd, NewClient(srv.Client(), relay.RouteBase(srv.URL), func(context.Context) (string, error) { return hcToken, nil })
}
