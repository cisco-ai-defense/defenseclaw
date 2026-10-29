// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type registrationRunner struct{ calls []Command }

func (r *registrationRunner) Output(_ context.Context, cmd Command) ([]byte, error) {
	r.calls = append(r.calls, cmd)
	return nil, nil
}
func (*registrationRunner) Run(context.Context, Command) error { return nil }

// GAP-0319: the Homebrew service writes its TLS bundle in its prefix, not in
// the CLI registration folder. A missing bundle in both locations still
// refuses registration without calling the CLI.
func TestRegisterLocalUsesTheBundleTheCLIWillImport(t *testing.T) {
	for _, tc := range []struct {
		name, goos, location string
		wantCall             bool
	}{
		{"Homebrew TLS", "darwin", "brew", true},
		{"Linux gateway TLS", "linux", "config", true},
		{"no TLS bundle", "darwin", "", false},
		{"no Linux TLS bundle", "linux", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			configDir, brew := filepath.Join(root, "config"), filepath.Join(root, "brew")
			if err := os.MkdirAll(configDir, 0o700); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(configDir, "gateways", DefaultGatewayName, "mtls")
			if tc.location == "brew" {
				dir = filepath.Join(brew, "var", "openshell", "tls")
			}
			if tc.location != "" {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"ca.crt", "tls.crt", "tls.key"} {
					if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			runner := &registrationRunner{}
			r := &doctorRun{Doctor: &Doctor{GOOS: tc.goos, CLI: "openshell", Runner: runner,
				Discover: DiscoverOptions{ConfigDir: configDir},
				Gateway:  &GatewayConfigurator{BrewPrefix: brew, RestartWait: 15 * time.Millisecond}}}
			err := r.registerLocal(context.Background())
			if tc.wantCall {
				if err != nil || len(runner.calls) != 1 || runner.calls[0].Name != "openshell" {
					t.Fatalf("register: %v, calls %v", err, runner.calls)
				}
				if tc.goos == "darwin" && !strings.Contains(strings.Join(runner.calls[0].Env, " "), dir) {
					t.Fatalf("Homebrew TLS was not passed to the CLI: %+v", runner.calls[0])
				}
			} else if err == nil || len(runner.calls) != 0 || !strings.Contains(err.Error(), map[string]string{"darwin": "has no client certificates", "linux": "wrote no client certificates"}[tc.goos]) {
				t.Fatalf("missing TLS bundle: %v, calls %v", err, runner.calls)
			}
		})
	}
}

func TestRegisterLocalWaitsForStandardHomebrewTLS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenShell sandboxes are unsupported on Windows")
	}
	r := &doctorRun{Doctor: &Doctor{GOOS: "darwin", Gateway: &GatewayConfigurator{BrewPrefix: "/opt/homebrew"}}}
	if got, want := r.localRegistrationTLSDir(), "/opt/homebrew/var/openshell/tls"; got != want {
		t.Fatalf("standard Homebrew TLS wait = %q, want %q", got, want)
	}
	if env := r.registerEnv(); len(env) != 0 {
		t.Fatalf("the standard prefix needs no CLI TLS override: %v", env)
	}
}

// GAP-0319: the formula keeps the PKI that openshell-gateway generate-certs
// writes in var/openshell/tls: ca.crt at the top, the client pair in
// client/. Setup registers with it at once, and a Homebrew install without
// it is refused at once with the post-install step: the service never
// writes it, so waiting for it only delayed the refusal by the restart wait.
func TestRegisterLocalTakesTheHomebrewPKILayoutWithoutWaiting(t *testing.T) {
	for _, tc := range []struct {
		name     string
		files    []string
		wantCall bool
	}{
		{"client pair in client/", []string{"ca.crt", "client/tls.crt", "client/tls.key", "server/tls.crt", "server/tls.key"}, true},
		{"server pair only", []string{"ca.crt", "server/tls.crt", "server/tls.key"}, false},
		{"no PKI", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			configDir, brew := filepath.Join(root, "config"), filepath.Join(root, "brew")
			tls := filepath.Join(brew, "var", "openshell", "tls")
			for _, d := range []string{configDir, filepath.Join(tls, "client"), filepath.Join(tls, "server")} {
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range tc.files {
				if err := os.WriteFile(filepath.Join(tls, name), []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			runner := &registrationRunner{}
			r := &doctorRun{Doctor: &Doctor{GOOS: "darwin", CLI: "openshell", Runner: runner,
				Discover: DiscoverOptions{ConfigDir: configDir},
				Gateway:  &GatewayConfigurator{BrewPrefix: brew, RestartWait: time.Minute}}}
			start := time.Now()
			err := r.registerLocal(context.Background())
			if took := time.Since(start); took > 10*time.Second {
				t.Fatalf("registerLocal waited %s for a PKI the service never writes", took)
			}
			if tc.wantCall {
				if err != nil || len(runner.calls) != 1 || !strings.Contains(strings.Join(runner.calls[0].Env, " "), tls) {
					t.Fatalf("register with the Homebrew PKI: %v, calls %+v", err, runner.calls)
				}
				return
			}
			if err == nil || len(runner.calls) != 0 {
				t.Fatalf("an incomplete Homebrew PKI was registered: %v, calls %+v", err, runner.calls)
			}
			for _, want := range []string{"has no client certificates in " + tls, installOpenShellCommand} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("refusal %q does not name %q", err, want)
				}
			}
			// With the formula (its service) installed, its post-install
			// step is the one to run again, then the registration.
			r.service = &ServiceState{Installed: true}
			err = r.registerLocal(context.Background())
			for _, want := range []string{"postinstall " + GatewayFormula, "gateway add"} {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("refusal with the formula installed %v does not name %q", err, want)
				}
			}
			if strings.Contains(err.Error(), "the gateway started") {
				t.Errorf("refusal claims a gateway start: %q", err)
			}
		})
	}
}
