//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// gatewaySessions lets a real relay accept the session tokens the gateway
// mints for an attach, as the relay in an actor does.
type gatewaySessions struct{ f *substrateFixture }

func (g gatewaySessions) Verify(_ context.Context, r *http.Request) (relay.Session, error) {
	s, err := g.f.sessions.Verify(relay.TokenFrom(r))
	if err != nil {
		return relay.Session{}, relay.ErrNoToken
	}
	return relay.Session{Person: s.Person, Actor: s.ActorRef, ActorUID: s.ActorUID, Expires: s.Expires}, nil
}

// GAP-0158: the launcher's own clients (workspace.Client for status, exec
// and files; attach.RunTask and attach.Status) go through the REAL admin
// handler to a REAL relay server. The route table is relay.AttachRoutes on
// every side; nothing here builds a URL by hand.
func TestLauncherClientsReachARealRelayThroughTheGateway(t *testing.T) {
	f := newSubstrateFixture(t)
	cfg := kit.DefaultConfig()
	wd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg.Relay.Workdir = wd
	real := relay.NewServer(relay.Options{
		Config: cfg, Verifier: gatewaySessions{f},
		Log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warm: func(context.Context, string) error { return nil },
	}).Handler()
	var tasks int
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A real task needs an agent binary; the task route is answered
		// here, behind the same token check, and the rest is the relay.
		if r.URL.Path == relay.Path(relay.RouteTask) {
			if _, err := (gatewaySessions{f}).Verify(r.Context(), r); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			tasks++
			code := 0
			w.Header().Set("Content-Type", "application/x-ndjson")
			enc := json.NewEncoder(w)
			_ = enc.Encode(relay.TaskEvent{Type: "start", ID: "t1"})
			_ = enc.Encode(relay.TaskEvent{Type: "stdout", Data: "task ran"})
			_ = enc.Encode(relay.TaskEvent{Type: "exit", Code: &code})
			return
		}
		real.ServeHTTP(w, r)
	}))
	defer peer.Close()
	f.api.substrateState().cfg.Relays = &dialRelay{addr: strings.TrimPrefix(peer.URL, "http://")}

	srv := httptest.NewTLSServer(f.admin)
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	gw := attach.Gateway{BaseURL: srv.URL, CAFile: ca}
	target := attach.Target{Atespace: "eng-web", Name: "alice-1"}
	bearer := func(context.Context) (string, error) { return "p-alice", nil }
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	tun, err := attach.NewTunnel(ctx, gw, bearer, target)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	// The same construction substrate run uses (substrate_workspace.go).
	wc := workspace.NewClient(tun.HTTPClient(), tun.BaseURL(), tun.Bearer)
	root, err := wc.DetectRoot(ctx)
	if err != nil || root != wd {
		t.Fatalf("DetectRoot = %q, %v; want %q", root, err, wd)
	}
	proj := t.TempDir()
	if err := os.WriteFile(filepath.Join(proj, "hello.txt"), []byte("from the laptop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := wc.Upload(ctx, "", proj, filepath.Join(wd, "proj")); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	res, err := wc.Exec(ctx, "", osw.ExecRequest{Argv: []string{"sh", "-c", "find . -name hello.txt -exec cat {} +"}, Workdir: wd})
	if err != nil || res.ExitCode != 0 || !strings.Contains(string(res.Stdout), "from the laptop") {
		t.Fatalf("Exec = %+v, %v", res, err)
	}
	back := t.TempDir()
	if err := wc.Download(ctx, "", filepath.Join(wd, "proj"), back); err != nil {
		t.Fatalf("Download: %v", err)
	}
	found := false
	_ = filepath.Walk(back, func(p string, _ os.FileInfo, _ error) error {
		if filepath.Base(p) == "hello.txt" {
			found = true
		}
		return nil
	})
	if !found {
		t.Error("Download brought nothing back")
	}

	st, err := attach.Status(ctx, attach.Options{Target: target, Gateway: gw, Bearer: bearer, NoBanner: true, NoAsks: true})
	if err != nil || st["version"] != relay.Version {
		t.Fatalf("Status = %v, %v", st, err)
	}
	var out []string
	code, err := attach.RunTask(ctx, attach.TaskOptions{
		Options: attach.Options{Target: target, Gateway: gw, Bearer: bearer, NoBanner: true, NoAsks: true},
		Prompt:  "fix the tests", Emit: func(e relay.TaskEvent) { out = append(out, e.Type+":"+e.Data) },
	})
	if err != nil || code != 0 || tasks != 1 || !strings.Contains(strings.Join(out, " "), "stdout:task ran") {
		t.Fatalf("RunTask = %d, %v, tasks %d, events %v", code, err, tasks, out)
	}
	// The old shape (<attach>/dcrelay/1/<route>) is not part of the contract.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, tun.BaseURL()+relay.Path(relay.RouteStatus), nil)
	resp, err := tun.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("<attach>%s answered %d, want 404", relay.Path(relay.RouteStatus), resp.StatusCode)
	}
}
