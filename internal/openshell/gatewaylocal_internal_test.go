// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"context"
	"os"
	"path/filepath"
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
			} else if err == nil || len(runner.calls) != 0 || !strings.Contains(err.Error(), "wrote no client certificates") {
				t.Fatalf("missing TLS bundle: %v, calls %v", err, runner.calls)
			}
		})
	}
}

func TestRegisterLocalWaitsForStandardHomebrewTLS(t *testing.T) {
	r := &doctorRun{Doctor: &Doctor{GOOS: "darwin", Gateway: &GatewayConfigurator{BrewPrefix: "/opt/homebrew"}}}
	if got, want := r.localRegistrationTLSDir(), "/opt/homebrew/var/openshell/tls"; got != want {
		t.Fatalf("standard Homebrew TLS wait = %q, want %q", got, want)
	}
	if env := r.registerEnv(); len(env) != 0 {
		t.Fatalf("the standard prefix needs no CLI TLS override: %v", env)
	}
}
