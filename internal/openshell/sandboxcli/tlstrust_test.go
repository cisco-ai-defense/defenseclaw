//go:build !windows

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

package sandboxcli

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

// tlsLab is a network behind a TLS-inspecting proxy: the public CA signs
// what providers present unless the host is intercepted, then the corporate
// CA does.
type tlsLab struct {
	public, corp openshelltest.CA
	intercepted  map[string]bool
	down         map[string]bool
	hostTrusts   bool
}

func newTLSLab(t *testing.T) *tlsLab {
	return &tlsLab{public: openshelltest.NewCA(t, "Public Root CA"), corp: openshelltest.NewCA(t, "Corp Inspection Root CA"),
		intercepted: map[string]bool{}, down: map[string]bool{}, hostTrusts: true}
}

func (l *tlsLab) trust(t *testing.T) TLSTrust {
	return TLSTrust{
		Chain: func(_ context.Context, host string) ([]*x509.Certificate, error) {
			if l.down[host] {
				return nil, errors.New("dial tcp: i/o timeout")
			}
			ca := l.public
			if l.intercepted[host] {
				ca = l.corp
			}
			return []*x509.Certificate{openshelltest.NewLeafCert(t, ca, host)}, nil
		},
		SandboxRoots: func() (*x509.CertPool, string, error) {
			pool := x509.NewCertPool()
			pool.AddCert(l.public.Cert)
			return pool, "/usr/share/ca-certificates/mozilla", nil
		},
		HostRoots: func() (*x509.CertPool, error) {
			pool := x509.NewCertPool()
			pool.AddCert(l.public.Cert)
			if l.hostTrusts {
				pool.AddCert(l.corp.Cert)
			}
			return pool, nil
		},
	}
}

func tlsApp(t *testing.T, lab *tlsLab, bundle string) *App {
	cfg := &config.Config{}
	cfg.OpenShell.TrustedCABundle = bundle
	return &App{Cfg: cfg, GOOS: "linux", TLSTrust: lab.trust(t), Now: time.Now}
}

func TestTLSTrustCheck(t *testing.T) {
	ctx := context.Background()
	lab := newTLSLab(t)

	// No proxy: every probed host verifies with the sandbox's roots.
	c := tlsApp(t, lab, "").tlsTrustCheck(ctx, false)
	if c.ID != CheckIDTLSTrust || c.Status != openshell.StatusPass || !strings.Contains(c.Detail, "api.anthropic.com, api.openai.com, api.githubcopilot.com, registry.npmjs.org verify") {
		t.Fatalf("no proxy: %+v", c)
	}

	// The #1296 network: three providers re-signed, the CA not given.
	lab.intercepted = map[string]bool{"api.anthropic.com": true, "api.openai.com": true, "api.githubcopilot.com": true}
	c = tlsApp(t, lab, "").tlsTrustCheck(ctx, false)
	if c.Status != openshell.StatusFail || !strings.Contains(c.Detail, "TLS inspection") || !strings.Contains(c.Detail, `"Corp Inspection Root CA"`) ||
		!strings.Contains(c.Detail, "unable to get local issuer certificate") || c.Fix == nil ||
		c.Fix.Command != "defenseclaw config set openshell.trusted_ca_bundle /path/to/proxy-root-ca.pem" ||
		!strings.Contains(c.Fix.Summary, "exempt api.anthropic.com, api.openai.com, api.githubcopilot.com and the other model provider hosts") {
		t.Fatalf("intercepted: %+v %+v", c, c.Fix)
	}

	// The CA named: programs in sandboxes trust it, but OpenShell's
	// supervisor makes the model calls with its own store (GAP-0065,
	// GAP-0066, GAP-0074), so the row still fails and asks for the
	// providers to be exempt from inspection; no config command helps.
	file := filepath.Join(t.TempDir(), "corp.pem")
	if err := os.WriteFile(file, lab.corp.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	c = tlsApp(t, lab, file).tlsTrustCheck(ctx, false)
	if c.Status != openshell.StatusFail || !strings.Contains(c.Detail, "sandboxes also trust Corp Inspection Root CA from "+file) ||
		!strings.Contains(c.Detail, `api.anthropic.com, api.openai.com, api.githubcopilot.com present a certificate from "Corp Inspection Root CA"; programs in a sandbox trust it`) ||
		!strings.Contains(c.Detail, "made by OpenShell's sandbox supervisor") || strings.Contains(c.Detail, "unable to get local issuer") ||
		c.Fix == nil || c.Fix.Command != "" || !strings.Contains(c.Fix.Summary, "ask your IT department to exempt api.anthropic.com") {
		t.Fatalf("CA named, providers inspected: %+v %+v", c, c.Fix)
	}

	// The CA named and the providers exempt from inspection: the row passes.
	exempt := newTLSLab(t)
	exempt.corp = lab.corp
	if c = tlsApp(t, exempt, file).tlsTrustCheck(ctx, false); c.Status != openshell.StatusPass || c.Fix != nil ||
		!strings.Contains(c.Detail, "verify with the roots sandboxes trust") || !strings.Contains(c.Detail, "sandboxes also trust Corp Inspection Root CA") {
		t.Fatalf("CA named, providers exempt: %+v", c)
	}

	// A named file that cannot be used fails by name: no image builds.
	bad := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(bad, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c = tlsApp(t, lab, bad).tlsTrustCheck(ctx, false)
	if c.Status != openshell.StatusFail || !strings.Contains(c.Detail, "no sandbox image is built") || !strings.Contains(c.Detail, "PRIVATE KEY") ||
		c.Fix == nil || !strings.Contains(c.Fix.Command, "config unset openshell.trusted_ca_bundle") {
		t.Fatalf("bad file: %+v", c)
	}

	// One provider re-signed by a CA this computer does not trust either.
	lab.intercepted = map[string]bool{"api.openai.com": true}
	lab.hostTrusts = false
	c = tlsApp(t, lab, "").tlsTrustCheck(ctx, false)
	if c.Status != openshell.StatusWarn || !strings.Contains(c.Detail, "api.openai.com present a certificate") || c.Fix == nil {
		t.Fatalf("untrusted everywhere: %+v", c)
	}

	// Offline: nothing to judge.
	lab.down = map[string]bool{"api.anthropic.com": true, "api.openai.com": true, "api.githubcopilot.com": true, tlsTrustDownloadHost: true}
	c = tlsApp(t, lab, "").tlsTrustCheck(ctx, false)
	if c.Status != openshell.StatusSkip || !strings.Contains(c.Detail, "did not answer") {
		t.Fatalf("offline: %+v", c)
	}

	// No public root store to compare with.
	a := tlsApp(t, newTLSLab(t), "")
	a.TLSTrust.SandboxRoots = func() (*x509.CertPool, string, error) { return nil, "", errors.New("no public root store") }
	if c = a.tlsTrustCheck(ctx, false); c.Status != openshell.StatusSkip || !strings.Contains(c.Detail, "not checked") {
		t.Fatalf("no roots: %+v", c)
	}

	// One provider intercepted by the trusted corporate CA, another re-signed
	// by a CA nobody trusts: each part of the message names its own issuer.
	mixedLab := newTLSLab(t)
	mixedLab.intercepted = map[string]bool{"api.anthropic.com": true}
	rogue := openshelltest.NewCA(t, "Unknown Root CA")
	mixed := tlsApp(t, mixedLab, "")
	chain := mixed.TLSTrust.Chain
	mixed.TLSTrust.Chain = func(ctx context.Context, host string) ([]*x509.Certificate, error) {
		if host == "api.openai.com" {
			return []*x509.Certificate{openshelltest.NewLeafCert(t, rogue, host)}, nil
		}
		return chain(ctx, host)
	}
	c = mixed.tlsTrustCheck(ctx, false)
	want := `TLS inspection: api.anthropic.com present a certificate from "Corp Inspection Root CA", which this computer trusts but sandboxes do not`
	also := `; api.openai.com present a certificate from "Unknown Root CA", which neither this computer nor sandboxes trust`
	if c.Status != openshell.StatusFail || !strings.Contains(c.Detail, want) || !strings.Contains(c.Detail, also) {
		t.Fatalf("mixed: %+v", c)
	}
}

func TestTLSTrustChecksInspectedDownloadHost(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			lab := newTLSLab(t)
			lab.intercepted[tlsTrustDownloadHost] = true
			app := tlsApp(t, lab, "")
			app.GOOS = goos
			c := app.tlsTrustCheck(context.Background(), false)
			if c.Status != openshell.StatusFail || !strings.Contains(c.Detail, `registry.npmjs.org present a certificate from "Corp Inspection Root CA", which this computer trusts but sandboxes do not`) ||
				c.Fix == nil || c.Fix.Command != "defenseclaw config set openshell.trusted_ca_bundle /path/to/proxy-root-ca.pem" ||
				strings.Contains(c.Fix.Summary, "exempt registry.npmjs.org") {
				t.Fatalf("download host inspected without CA: %+v", c)
			}

			file := filepath.Join(t.TempDir(), "corp.pem")
			if err := os.WriteFile(file, lab.corp.PEM, 0o644); err != nil {
				t.Fatal(err)
			}
			app = tlsApp(t, lab, file)
			app.GOOS = goos
			c = app.tlsTrustCheck(context.Background(), false)
			if c.Status != openshell.StatusPass || c.Fix != nil || !strings.Contains(c.Detail, "registry.npmjs.org verify") {
				t.Fatalf("download host inspected with CA: %+v", c)
			}

			lab.down[tlsTrustDownloadHost] = true
			app = tlsApp(t, lab, "")
			app.GOOS = goos
			c = app.tlsTrustCheck(context.Background(), false)
			if c.Status != openshell.StatusPass || c.Fix != nil || !strings.Contains(c.Detail, "registry.npmjs.org did not answer") {
				t.Fatalf("download host unreachable: %+v", c)
			}
		})
	}
}

// On a managed computer the CAs are the administrator's, as the daemon got
// them from the managed gateway; the account's own configuration is not read.
func TestTLSTrustCheckManaged(t *testing.T) {
	ctx := context.Background()
	lab := newTLSLab(t)
	lab.intercepted = map[string]bool{"api.anthropic.com": true}
	managedApp := func(pem, problem string, ok bool) *App {
		a := tlsApp(t, lab, "/home/user/my-own-ca.pem")
		a.ManagedTrustedCAs = func(context.Context) (string, string, bool) { return pem, problem, ok }
		return a
	}
	c := managedApp("", "", true).tlsTrustCheck(ctx, true)
	if c.Status != openshell.StatusFail || c.Fix == nil || c.Fix.Command != "" || !strings.Contains(c.Fix.Summary, "ask your administrator") {
		t.Fatalf("managed, intercepted: %+v %+v", c, c.Fix)
	}
	if !strings.Contains(c.Fix.Summary, "ask your administrator to exempt api.anthropic.com") || !strings.Contains(c.Fix.Summary, "and to set openshell.trusted_ca_bundle") {
		t.Fatalf("managed, intercepted fix: %+v", c.Fix)
	}
	// The administrator's CA relayed: the inspected provider still fails
	// the supervisor's model calls, so the fix is the exemption alone.
	if c = managedApp(string(lab.corp.PEM), "", true).tlsTrustCheck(ctx, true); c.Status != openshell.StatusFail ||
		!strings.Contains(c.Detail, "your organization's openshell.trusted_ca_bundle") || !strings.Contains(c.Detail, "OpenShell's sandbox supervisor") ||
		c.Fix == nil || c.Fix.Command != "" || !strings.Contains(c.Fix.Summary, "ask your administrator to exempt api.anthropic.com") ||
		strings.Contains(c.Fix.Summary, "and to set") {
		t.Fatalf("managed, CA relayed: %+v %+v", c, c.Fix)
	}
	if c = managedApp("", "openshell.trusted_ca_bundle /etc/corp.pem: writable by group staff", true).tlsTrustCheck(ctx, true); c.Status != openshell.StatusFail ||
		!strings.Contains(c.Detail, "your organization's trusted CAs cannot be used") || !strings.Contains(c.Fix.Summary, "administrator") {
		t.Fatalf("managed, CA refused: %+v", c)
	}
	if c = managedApp("", "", false).tlsTrustCheck(ctx, true); c.Status != openshell.StatusFail || !strings.Contains(c.Detail, "not known here") {
		t.Fatalf("managed, daemon down: %+v", c)
	}
}

// The row is part of `sandbox doctor` (and so setup and `defenseclaw
// doctor`), and the probe runs once per command.
func TestDoctorHasTheTLSTrustRow(t *testing.T) {
	ta := newTestApp(t, "")
	var calls atomic.Int32
	ta.TLSTrust.Chain = func(context.Context, string) ([]*x509.Certificate, error) {
		calls.Add(1)
		return nil, errors.New("offline")
	}
	for range 2 {
		rep := ta.runDoctor(context.Background())
		if c := rep.Get(CheckIDTLSTrust); c == nil || c.Status != openshell.StatusSkip {
			t.Fatalf("row: %+v", c)
		}
	}
	if int(calls.Load()) != len(tlsTrustHosts) {
		t.Fatalf("probed %d times, want %d", calls.Load(), len(tlsTrustHosts))
	}
}
