//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func TestGAP0540ManagedHermesDiscoveryUsesCurrentCLIInAccountHome(t *testing.T) {
	for _, tc := range []struct {
		name, stamp, cli string
	}{
		{name: "CLI only", cli: "0.21.5"},
		{name: "older CLI", stamp: "0.21.5", cli: "0.18.0"},
		{name: "newer CLI", stamp: "0.18.0", cli: "0.21.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			bin := filepath.Join(home, ".local", "bin")
			if err := os.MkdirAll(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.stamp != "" {
				stamp := filepath.Join(home, ".hermes", "hermes-agent", "install-stamp.json")
				if err := os.MkdirAll(filepath.Dir(stamp), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(stamp, []byte(`{"baseVersion":"`+tc.stamp+`","displayVersion":"`+tc.stamp+`"}`), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			marker := filepath.Join(home, "version-state")
			cli := filepath.Join(bin, "hermes")
			body := "#!/bin/sh\nprintf '%s\\n' \"${HERMES_HOME-unset}\" > '" + marker + "'\necho 'Hermes Agent v" + tc.cli + "'\n"
			if err := os.WriteFile(cli, []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}

			response := enterpriseHookWorkerDiscoverWithin(context.Background(), enterpriseHookWorkerRequest{
				Home: home, Connectors: []string{"hermes"},
			})
			if got := response.Versions["hermes"]; got != tc.cli {
				t.Fatalf("managed version = %q, want current CLI version %q", got, tc.cli)
			}
			state, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSpace(string(state)); got != "unset" {
				t.Fatalf("managed version command state = %q, want account default", got)
			}

			if err := os.Remove(marker); err != nil {
				t.Fatal(err)
			}
			static := enterpriseHookWorkerDiscoverWithin(context.Background(), enterpriseHookWorkerRequest{
				Home: home, Connectors: []string{"hermes"}, StaticDiscovery: true,
			})
			if got := static.Versions["hermes"]; got != tc.stamp {
				t.Fatalf("static version = %q, want metadata version %q", got, tc.stamp)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("static discovery ran a version command: %v", err)
			}
			if tc.stamp == "" && !strings.HasPrefix(static.Reasons["hermes"], enterprisehooks.UnixAgentUnversionedReasonPrefix) {
				t.Fatalf("static reason = %q, want installed CLI reason", static.Reasons["hermes"])
			}
		})
	}
}

func TestGAP0540ManagedHermesDiscoveryDoesNotTrustStampAfterCLIError(t *testing.T) {
	home := t.TempDir()
	stamp := filepath.Join(home, ".hermes", "hermes-agent", "install-stamp.json")
	bin := filepath.Join(home, ".local", "bin")
	for _, dir := range []string{filepath.Dir(stamp), bin} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(stamp, []byte(`{"baseVersion":"0.21.5","displayVersion":"0.21.5"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(bin, "hermes")
	if err := os.WriteFile(cli, []byte("#!/bin/sh\necho 'no version available'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	response := enterpriseHookWorkerDiscoverWithin(context.Background(), enterpriseHookWorkerRequest{
		Home: home, Connectors: []string{"hermes"},
	})
	if got := response.Versions["hermes"]; got != "" {
		t.Fatalf("managed version = %q after the CLI failed, want no verified version", got)
	}
	if !strings.HasPrefix(response.Reasons["hermes"], enterprisehooks.UnixAgentUnversionedReasonPrefix) {
		t.Fatalf("managed reason = %q, want installed CLI with unreadable version", response.Reasons["hermes"])
	}
}

func TestGAP0540ManagedHermesDiscoveryUsesMetadataWithoutCLI(t *testing.T) {
	home := t.TempDir()
	stamp := filepath.Join(home, ".hermes", "hermes-agent", "install-stamp.json")
	if err := os.MkdirAll(filepath.Dir(stamp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stamp, []byte(`{"baseVersion":"0.21.5","displayVersion":"0.21.5"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	response := enterpriseHookWorkerDiscoverWithin(context.Background(), enterpriseHookWorkerRequest{
		Home: home, Connectors: []string{"hermes"},
	})
	if got := response.Versions["hermes"]; got != "0.21.5" {
		t.Fatalf("metadata-only version = %q, want 0.21.5", got)
	}
}

func TestGAP0540ManagedHermesDiscoveryWithUnavailableAccountState(t *testing.T) {
	for _, mode := range []string{"busy", "read only"} {
		if mode == "read only" && os.Geteuid() == 0 {
			continue
		}
		for _, tc := range []struct{ name, stamp, cli string }{
			{name: "CLI only", cli: "0.21.5"},
			{name: "older CLI", stamp: "0.21.5", cli: "0.18.0"},
			{name: "newer CLI", stamp: "0.18.0", cli: "0.21.5"},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				home := t.TempDir()
				state := filepath.Join(home, ".hermes")
				bin := filepath.Join(home, ".local", "bin")
				for _, dir := range []string{state, bin} {
					if err := os.MkdirAll(dir, 0o755); err != nil {
						t.Fatal(err)
					}
				}
				if tc.stamp != "" {
					stamp := filepath.Join(state, "hermes-agent", "install-stamp.json")
					if err := os.MkdirAll(filepath.Dir(stamp), 0o755); err != nil {
						t.Fatal(err)
					}
					body := `{"baseVersion":"` + tc.stamp + `","displayVersion":"` + tc.stamp + `"}`
					if err := os.WriteFile(stamp, []byte(body), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				cli := filepath.Join(bin, "hermes")
				marker := filepath.Join(home, "version-probe-marker")
				body := "#!/bin/sh\nstate=\"${HERMES_HOME:-$HOME/.hermes}\"\n" +
					"mkdir \"$state/version.lock\" 2>/dev/null || exit 1\n" +
					"printf '%s' \"${DC_AGENT_VERSION_PROBE:-unset}\" > '" + marker + "'\n" +
					"echo 'Hermes Agent v" + tc.cli + "'\n"
				if err := os.WriteFile(cli, []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
				if mode == "busy" {
					if err := os.Mkdir(filepath.Join(state, "version.lock"), 0o700); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Chmod(state, 0o555); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Chmod(state, 0o755) })
				}
				response := enterpriseHookWorkerDiscoverWithin(context.Background(), enterpriseHookWorkerRequest{
					Home: home, Connectors: []string{"hermes"},
				})
				if got := response.Versions["hermes"]; got != tc.cli {
					t.Fatalf("managed version = %q, want current CLI %q with stamp %q; reason=%q", got, tc.cli, tc.stamp, response.Reasons["hermes"])
				}
				value, err := os.ReadFile(marker)
				if err != nil || string(value) != "hermes" {
					t.Fatalf("isolated version marker = %q, error %v", value, err)
				}
			})
		}
	}
}
