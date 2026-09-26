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

//go:build openshell_integration

// Live smoke test against the local OpenShell gateway:
//
//	go test -tags openshell_integration -run Live -v ./internal/openshell/
//
// It creates one short-lived sandbox named d-smoke-<random> (override the
// prefix with DC_OPENSHELL_SMOKE_PREFIX, pin the gateway with
// DC_OPENSHELL_GATEWAY) and deletes it again. Nothing else is touched.

package openshell_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

func TestLiveGateway(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	reg, err := openshell.Discover(openshell.DiscoverOptions{Gateway: os.Getenv("DC_OPENSHELL_GATEWAY")})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	for _, w := range reg.Warnings {
		t.Logf("registration warning: %s", w)
	}
	client, err := openshell.Dial(reg, openshell.ClientOptions{})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	// Registered first so it runs after the sandbox cleanup below.
	t.Cleanup(func() { _ = client.Close() })

	h, err := client.Health(ctx)
	if err != nil || !h.Healthy {
		t.Fatalf("Health = %+v, %v", h, err)
	}
	if err := h.CheckVersion(); err != nil {
		t.Fatalf("gateway version: %v", err)
	}
	info, err := client.GatewayInfo(ctx)
	if err != nil {
		t.Fatalf("GatewayInfo: %v", err)
	}
	t.Logf("gateway %s at %s: %s, drivers %+v", reg.Name, reg.Endpoint, h.RawVersion, info.ComputeDrivers)
	all, err := client.ListSandboxes(ctx, nil)
	if err != nil {
		t.Fatalf("ListSandboxes: %v", err)
	}
	t.Logf("%d existing sandboxes", len(all))

	prefix := os.Getenv("DC_OPENSHELL_SMOKE_PREFIX")
	if prefix == "" {
		prefix = "d-smoke"
	}
	suffix := make([]byte, 3)
	_, _ = rand.Read(suffix)
	name := prefix + "-" + hex.EncodeToString(suffix)
	labels := map[string]string{"io.defenseclaw/smoke": name}

	if _, err := client.CreateSandbox(ctx, name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{Labels: labels}); err != nil {
		t.Fatalf("CreateSandbox: %v", err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer ccancel()
		if _, err := client.DeleteSandbox(cctx, name); err != nil {
			t.Errorf("DeleteSandbox: %v", err)
			return
		}
		if err := client.WaitDeleted(cctx, name); err != nil {
			t.Errorf("WaitDeleted: %v", err)
		}
	})

	conn, err := reg.DialGRPC()
	if err != nil {
		t.Fatalf("DialGRPC: %v", err)
	}
	defer conn.Close()
	var (
		mu      sync.Mutex
		events  []stream.Event
		saved   string
		watchWG sync.WaitGroup
	)
	w, err := stream.New(stream.Config{Conn: conn, Sandbox: name, SaveCursor: func(c string) error {
		mu.Lock()
		defer mu.Unlock()
		saved = c
		return nil
	}})
	if err != nil {
		t.Fatalf("stream.New: %v", err)
	}
	wctx, wcancel := context.WithCancel(ctx)
	defer wcancel()
	watchWG.Add(1)
	go func() {
		defer watchWG.Done()
		if err := w.Run(wctx, func(ev stream.Event) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		}); err != nil && wctx.Err() == nil {
			t.Errorf("watch ended: %v", err)
		}
	}()

	sb, err := client.WaitReady(ctx, name)
	if err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	t.Logf("sandbox %s ready (id %s, policy v%d)", name, sb.ID, sb.Status.CurrentPolicyVersion)

	mine, err := client.ListSandboxes(ctx, labels)
	if err != nil || len(mine) != 1 || mine[0].Name != name {
		t.Fatalf("ListSandboxes(%v) = %d sandboxes, %v", labels, len(mine), err)
	}

	res, err := client.Exec(ctx, name, []string{"sh", "-c", "echo sdk-ok; id -u"}, openshell.ExecOptions{Timeout: 30 * time.Second})
	if err != nil || res.ExitCode != 0 || !strings.HasPrefix(string(res.Stdout), "sdk-ok\n") {
		t.Fatalf("Exec = %+v, %v", res, err)
	}
	t.Logf("SDK exec: attempts %d, uid %s", res.Attempts, strings.TrimSpace(strings.TrimPrefix(string(res.Stdout), "sdk-ok\n")))

	// A quiet command that outlives its timeout is stopped in the sandbox
	// and not retried, so nothing finishes it later.
	started := time.Now()
	_, err = client.Exec(ctx, name, []string{"sh", "-c", "sleep 3; echo run >> /tmp/d-smoke-count"}, openshell.ExecOptions{Timeout: time.Second, Attempts: 3})
	if !errors.Is(err, openshell.ErrExecTimeout) {
		t.Fatalf("quiet exec past its timeout = %v", err)
	}
	t.Logf("timed-out exec returned after %s: %v", time.Since(started).Round(time.Millisecond), err)
	time.Sleep(4 * time.Second)
	count, err := client.Exec(ctx, name, []string{"sh", "-c", "cat /tmp/d-smoke-count 2>/dev/null | wc -l"}, openshell.ExecOptions{Timeout: 30 * time.Second})
	if err != nil || strings.TrimSpace(string(count.Stdout)) != "0" {
		t.Fatalf("the timed-out command still ran: %+v, %v", count, err)
	}

	cli := openshell.CLI{Gateway: reg.Name}
	inv, err := cli.Exec(name, []string{"sh", "-c", "echo cli-ok"}, openshell.CLIExecOptions{Timeout: 30 * time.Second, WorkDir: "/tmp"})
	if err != nil {
		t.Fatal(err)
	}
	if out := runInvocation(t, ctx, inv); !strings.Contains(out, "cli-ok") {
		t.Fatalf("CLI exec output %q", out)
	}

	// A background forward returns at once although its forwarder keeps
	// the inherited stderr, and the port accepts connections.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	fwd, err := cli.ForwardStart(name, port, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if stop, err := cli.ForwardStop(name, port); err == nil {
			_, _ = stop.Output(context.Background())
		}
	})
	fwdStart := time.Now()
	t.Logf("forward start: %s (%s)", strings.TrimSpace(runInvocation(t, ctx, fwd)), time.Since(fwdStart).Round(time.Millisecond))
	if time.Since(fwdStart) > 5*time.Second {
		t.Fatalf("forward start took %s", time.Since(fwdStart))
	}
	fconn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 5*time.Second)
	if err != nil {
		t.Fatalf("forwarded port: %v", err)
	}
	_ = fconn.Close()
	stop, err := cli.ForwardStop(name, port)
	if err != nil {
		t.Fatal(err)
	}
	runInvocation(t, ctx, stop)

	local := t.TempDir()
	payload := filepath.Join(local, "payload")
	if err := os.MkdirAll(payload, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payload, "hello.txt"), []byte("round trip\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	up, err := cli.Upload(name, payload, "/sandbox/d-smoke-up", false)
	if err != nil {
		t.Fatal(err)
	}
	runInvocation(t, ctx, up)
	found, err := client.Exec(ctx, name, []string{"sh", "-c", "find /sandbox/d-smoke-up -name hello.txt -exec cat {} +"}, openshell.ExecOptions{Timeout: 30 * time.Second})
	if err != nil || string(found.Stdout) != "round trip\n" {
		t.Fatalf("uploaded file: %+v, %v", found, err)
	}
	back := filepath.Join(local, "back")
	if err := os.MkdirAll(back, 0o700); err != nil {
		t.Fatal(err)
	}
	down, err := cli.Download(name, "/sandbox/d-smoke-up", back)
	if err != nil {
		t.Fatal(err)
	}
	runInvocation(t, ctx, down)
	var roundTrip []byte
	_ = filepath.WalkDir(back, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == "hello.txt" {
			roundTrip, _ = os.ReadFile(p)
		}
		return nil
	})
	if string(roundTrip) != "round trip\n" {
		t.Fatalf("downloaded hello.txt = %q", roundTrip)
	}

	deadline := time.Now().Add(90 * time.Second)
	for {
		mu.Lock()
		ready, ocsfLines := false, 0
		for _, ev := range events {
			if ev.Kind == stream.KindStatus && ev.Status.Phase == openshell.PhaseReady {
				ready = true
			}
			if ev.Kind == stream.KindLog && ev.Log.OCSF != nil {
				ocsfLines++
			}
		}
		n := len(events)
		mu.Unlock()
		if ready && ocsfLines > 0 {
			t.Logf("watch: %d events, %d parsed OCSF lines", n, ocsfLines)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("watch saw %d events (ready=%v, ocsf=%d)", n, ready, ocsfLines)
		}
		time.Sleep(time.Second)
	}
	wcancel()
	watchWG.Wait()
	mu.Lock()
	defer mu.Unlock()
	if !strings.HasPrefix(w.Cursor(), "v1:") || saved != w.Cursor() {
		t.Fatalf("cursor = %q, saved %q", w.Cursor(), saved)
	}
	for _, ev := range events {
		if ev.Kind == stream.KindLog && ev.Log.OCSF != nil {
			t.Logf("ocsf: %s/%s %s", ev.Log.OCSF.Class, ev.Log.OCSF.Activity, ev.Log.Message)
		}
	}
}

func runInvocation(t *testing.T, ctx context.Context, inv openshell.Invocation) string {
	t.Helper()
	out, err := inv.Output(ctx)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return string(out)
}

func TestLiveDoctor(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	free := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	d := &openshell.Doctor{Ports: []openshell.PortRequirement{{Name: "probe", Port: free}}}
	r := d.Run(context.Background())
	t.Logf("\n%s", r)
	for _, id := range []string{openshell.CheckIDPlatform, openshell.CheckIDUser, openshell.CheckIDLandlock, openshell.CheckIDDocker,
		openshell.CheckIDDockerHostNetwork, openshell.CheckIDGatewayService, openshell.CheckIDCLI, openshell.CheckIDRegistration,
		openshell.CheckIDGatewayVersion, openshell.CheckIDGatewayDriver, openshell.CheckIDBindMounts, "port-probe"} {
		if c := r.Get(id); c == nil || c.Status != openshell.StatusPass {
			t.Errorf("%s: %+v", id, c)
		}
	}
	st, err := (&openshell.GatewayConfigurator{}).ServiceState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("service: %+v", st)
}

// TestLiveInstallerDigest downloads the real pinned installer and checks
// its digest, then declines consent: nothing is run.
func TestLiveInstallerDigest(t *testing.T) {
	var out bytes.Buffer
	inst := &openshell.Installer{
		LookPath:   func(string) (string, error) { return "", os.ErrNotExist },
		Candidates: []string{},
		Out:        &out,
		Consent:    func(*openshell.InstallPlan) (bool, error) { return false, nil },
	}
	if _, err := inst.Install(context.Background()); !errors.Is(err, openshell.ErrInstallDeclined) {
		t.Fatalf("Install = %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), openshell.InstallerSHA256) {
		t.Fatalf("plan:\n%s", out.String())
	}
	t.Logf("\n%s", out.String())
}

// noRestart runs real commands but never restarts the shared gateway.
type noRestart struct{ openshell.ExecRunner }

func (r noRestart) Output(ctx context.Context, c openshell.Command) ([]byte, error) {
	if c.Name == "systemctl" && len(c.Args) > 1 && c.Args[1] == "restart" {
		return nil, nil
	}
	return r.ExecRunner.Output(ctx, c)
}

// TestLivePreflight runs the real `openshell-gateway config preflight` on
// DefenseClaw's edit of a scratch gateway.toml.
func TestLivePreflight(t *testing.T) {
	dir := t.TempDir()
	orig := "# scratch\n[openshell]\nversion = 2 # schema\n\n# docker driver\n[openshell.drivers.docker]\nenable_bind_mounts = false # off\n"
	if err := os.WriteFile(filepath.Join(dir, "gateway.toml"), []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	// Bind mounts need the real (mTLS) registration; the edited files are
	// scratch copies.
	real, err := openshell.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	g := &openshell.GatewayConfigurator{Dir: dir, Runner: noRestart{}, VerifyGateway: func(context.Context) error { return nil },
		Discover: openshell.DiscoverOptions{ConfigDir: real, Gateway: os.Getenv("DC_OPENSHELL_GATEWAY")}}
	plan, err := g.Plan(openshell.GatewayChanges{EnableBindMounts: true, Env: map[string]string{openshell.EnvTelemetryEnabled: "false"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%s", plan)
	if _, err := g.Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	st, err := g.Read()
	if err != nil || !st.BindMounts.Enabled() || st.TelemetryEnabled() {
		t.Fatalf("state = %+v, %v", st, err)
	}

	if err := os.WriteFile(filepath.Join(dir, "gateway.toml"), []byte("[openshell.drivers.docker]\nallow_driver_config = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err = g.Plan(openshell.GatewayChanges{EnableBindMounts: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Apply(context.Background(), plan); !errors.Is(err, openshell.ErrPreflight) || !strings.Contains(err.Error(), "already fails preflight") {
		t.Fatalf("unversioned file: %v", err)
	}
}
