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

//go:build linux || darwin

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// The account's gateway is stopped once no sandbox of the account runs and
// the linger after its last ready passed, so the next account gets the one
// gateway port at once, not when the daemon idles out (GAP-0465). A running
// sandbox keeps it, and another account's gateway is not this daemon's.
func TestSandboxDaemonStopsGatewayWhenNoSandboxRuns(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.run(t)
	ctx := context.Background()
	f.os.holder.Store(int64(os.Getuid()))
	f.d.openShellUsed.Store(time.Now().Add(-2 * openShellGatewayLinger).UnixNano())
	f.running.Store(1)
	if f.d.check(ctx); f.os.stopped.Load() != 0 {
		t.Fatal("stopped the gateway under a running sandbox")
	}
	f.running.Store(0)
	f.d.openShellUsed.Store(time.Now().UnixNano())
	if f.d.check(ctx); f.os.stopped.Load() != 0 {
		t.Fatal("stopped the gateway between a run's ready and its create")
	}
	f.d.openShellUsed.Store(time.Now().Add(-2 * openShellGatewayLinger).UnixNano())
	if f.d.check(ctx); f.os.stopped.Load() != 1 {
		t.Fatalf("idle gateway: stopped %d", f.os.stopped.Load())
	}
	f.os.holder.Store(4242)
	if f.d.check(ctx); f.os.stopped.Load() != 1 {
		t.Fatal("stopped another account's gateway")
	}
}

// A stop or delete of a kept sandbox starts the account's gateway the daemon
// stopped; one that listens is used as it is; another account's is refused
// with the one-account-at-a-time text (GAP-0492). Status says that text too,
// not certificates and CAs, and shows no sandbox port the daemon does not
// hold (GAP-0461).
func TestSandboxDaemonGatewayForKeptSandboxes(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.run(t)
	ctx := context.Background()
	c := sandboxapi.NewUnixClient(f.socket)
	_, _ = c.Delete(ctx, "kept1", sandboxapi.DeleteRequest{})
	_, _ = c.Stop(ctx, "kept1")
	if n := f.os.prepared.Load(); n != 2 {
		t.Fatalf("readied %d times for a delete and a stop", n)
	}
	f.os.holder.Store(int64(os.Getuid()))
	if _, _ = c.Stop(ctx, "kept1"); f.os.prepared.Load() != 2 {
		t.Fatal("readied a gateway that listens")
	}
	f.os.holder.Store(4242)
	_, err := c.Delete(ctx, "kept1", sandboxapi.DeleteRequest{})
	if err == nil || !strings.Contains(err.Error(), "one account at a time") || f.os.prepared.Load() != 2 {
		t.Fatalf("delete while another account holds the port: %v", err)
	}
	st, err := c.Status(ctx)
	if err != nil || st.Available || st.GatewayElsewhere != "another account" || st.Reason != sandboxAccountBusyMessage ||
		st.IngressAddr != "" || st.EgressAddr != "" {
		t.Fatalf("status: %+v, %v", st, err)
	}
	if strings.Contains(st.Reason, "certificate") || strings.Contains(st.Reason, " CA") {
		t.Fatalf("status reason: %q", st.Reason)
	}
}

// A second OpenShell gateway the account starts writes its own client
// certificates into the registration of the default name; the next ready
// registers the managed gateway again (GAP-0495).
func TestAccountOpenShellRepairsOverwrittenRegistration(t *testing.T) {
	fastGatewayWaits(t)
	r := newOpenShellRig(t, "linux")
	r.o.adminBinary = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	r.holder = func(int) int { return 5001 }
	r.active = true
	tlsDir := filepath.Join(r.o.home, filepath.FromSlash(openShellTLSDirRel))
	mtls := filepath.Join(r.o.home, ".config", "openshell", "gateways", "openshell", "mtls")
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range [][3]string{{"ca.crt", "ca.crt", "managed ca"}, {"client/tls.crt", "tls.crt", "managed cert"}, {"client/tls.key", "tls.key", "managed key"}} {
		write(filepath.Join(tlsDir, filepath.FromSlash(f[0])), f[2])
		write(filepath.Join(mtls, f[1]), f[2])
	}
	r.o.discover = func(openshell.DiscoverOptions) (*openshell.Registration, error) {
		return &openshell.Registration{Name: "openshell", Endpoint: "https://127.0.0.1:17670", AuthMode: openshell.AuthModeMTLS,
			TLS: &openshell.TLSFiles{CA: filepath.Join(mtls, "ca.crt"), Cert: filepath.Join(mtls, "tls.crt"), Key: filepath.Join(mtls, "tls.key")}}, nil
	}
	add := "openshell gateway add https://127.0.0.1:17670 --local --name openshell"
	if _, err := r.o.Prepare(context.Background(), prerequisiteSettings()); err != nil || strings.Contains(strings.Join(r.ran(), "\n"), add) {
		t.Fatalf("intact registration: %v, %v", err, r.ran())
	}
	write(filepath.Join(mtls, "tls.crt"), "another gateway's cert")
	if _, err := r.o.Prepare(context.Background(), prerequisiteSettings()); err != nil || !strings.Contains(strings.Join(r.ran(), "\n"), add) {
		t.Fatalf("overwritten registration: %v, %v", err, r.ran())
	}
}

// The managed unit's gateway runs the install mode's openshell-gateway with
// --config on the rendered file and nothing else; the account's own
// gateway.toml is not read by it, so the command line is what is compared:
// another configuration or an added flag is drift (GAP-0512).
func TestAccountOpenShellManagedGatewayCommandDrift(t *testing.T) {
	r := newOpenShellRig(t, "linux")
	r.holder = func(int) int { return 5001 }
	r.active, r.pid = true, 77
	r.o.adminBinary = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	r.o.readRendered = func(string, string) (openshell.RenderedGateway, string, error) {
		return openshell.RenderedGateway{BindAddress: "127.0.0.1:17670", ComputeDriver: openshell.DriverVM}, "", nil
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, openshell.GatewayTOMLFile)
	s := sandboxrelay.DaemonSettings{Enterprise: sandboxrelay.EnterpriseOpenShell{Install: "prerequisite", Driver: "vm", GatewayPort: 17670,
		GatewayConfigPath: cfg}}
	for _, tc := range []struct {
		args  string
		drift bool
	}{
		{"/usr/bin/openshell-gateway --config " + cfg, false},
		{"/usr/bin/openshell-gateway --config " + filepath.Join(dir, openshell.GatewayFallbackTOMLFile), false},
		{"/usr/bin/openshell-gateway --config " + filepath.Join(r.o.home, ".config", "openshell", "gateway.toml"), true},
		{"/usr/bin/openshell-gateway --config " + cfg + " --bind-address 0.0.0.0:17670", true},
		{filepath.Join(r.o.home, ".local", "bin", "openshell-gateway") + " --config " + cfg, true},
		{"/usr/libexec/openshell/openshell-driver-vm --serve", false},
	} {
		r.args = tc.args
		drift, err := r.o.Drift(s)
		if err != nil || (len(drift) > 0) != tc.drift || (tc.drift && driftEventField(drift[0].Field) != "gateway_command") {
			t.Errorf("%s: drift %v, %v", tc.args, drift, err)
		}
	}
	s.Enterprise.Install = "setup"
	r.args = filepath.Join(r.o.home, ".local", "bin", "openshell-gateway") + " --config " + cfg
	if drift, err := r.o.Drift(s); err != nil || len(drift) != 0 {
		t.Fatalf("setup mode, the account's install: %v %v", drift, err)
	}
	r.args = "/usr/bin/openshell-gateway --config " + cfg
	if drift, err := r.o.Drift(s); err != nil || len(drift) != 1 {
		t.Fatalf("setup mode, another install: %v %v", drift, err)
	}
}
