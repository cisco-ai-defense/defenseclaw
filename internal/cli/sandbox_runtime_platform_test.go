// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestSandboxRunPlatformChecksConfiguredRuntimeBeforeWindowsOpenShell(t *testing.T) {
	broken := errors.New("fixed configuration load refusal")
	for _, test := range []struct {
		name, goos, requested, configured, want string
		loadErr                                 error
		loads, code                             int
	}{
		{name: "implicit axis", goos: "windows", configured: "axis", loads: 1, code: 3, want: "AXIS sandbox execution is not available"},
		{name: "auto axis", goos: "windows", requested: "auto", configured: "axis", loads: 1, code: 3, want: "AXIS sandbox execution is not available"},
		{name: "legacy default", goos: "windows", loads: 1, code: 3, want: "OpenShell sandboxes run"},
		{name: "configured openshell", goos: "windows", configured: "openshell", loads: 1, code: 3, want: "OpenShell sandboxes run"},
		{name: "invalid configured", goos: "windows", configured: "unknown", loads: 1, code: 2, want: "unknown sandbox runtime"},
		{name: "broken implicit", goos: "windows", loadErr: broken, loads: 1, code: 1, want: broken.Error()},
		{name: "explicit openshell before config", goos: "windows", requested: "openshell", loadErr: broken, code: 3, want: "OpenShell sandboxes run"},
		{name: "explicit axis before config", goos: "windows", requested: "axis", loadErr: broken, code: 3, want: "AXIS sandbox execution is not available"},
		{name: "invalid explicit before config", goos: "windows", requested: "unknown", loadErr: broken, code: 2, want: "unknown sandbox runtime"},
		{name: "supported platform defers config", goos: "linux", configured: "axis", loadErr: broken},
	} {
		t.Run(test.name, func(t *testing.T) {
			loads := 0
			err := sandboxRunPlatformCheck(test.goos, "amd64", test.requested, func() (*config.Config, error) {
				loads++
				if test.loadErr != nil {
					return nil, test.loadErr
				}
				return &config.Config{Sandbox: &config.SandboxConfig{Runtime: test.configured}}, nil
			})
			if loads != test.loads {
				t.Fatalf("configuration loads = %d, want %d", loads, test.loads)
			}
			if test.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.want) || commandExitCode(err) != test.code {
				t.Fatalf("refusal = %v (exit %d), want %q (exit %d)", err, commandExitCode(err), test.want, test.code)
			}
			if test.loadErr != nil && test.loads != 0 && !errors.Is(err, test.loadErr) {
				t.Fatalf("lost original configuration refusal: %v", err)
			}
		})
	}
}

func TestSandboxWindowsPreRunKeepsManagedPolicyBeforePersonalConfig(t *testing.T) {
	previousConfig, previousStandalone, previousSecureClient, previousPermitted := cfg, managedHostWindowsStandalone, secureClientHost, sandboxWindowsPersonalConfigPermitted
	t.Cleanup(func() {
		cfg, managedHostWindowsStandalone, secureClientHost, sandboxWindowsPersonalConfigPermitted = previousConfig, previousStandalone, previousSecureClient, previousPermitted
	})
	for _, lane := range []string{"standalone", "secure-client", "managed-pin", "unconfirmed-deployment"} {
		t.Run(lane, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			t.Setenv(managed.DeploymentModeEnv, "")
			if lane == "managed-pin" {
				t.Setenv(managed.DeploymentModeEnv, "managed_enterprise")
			}
			if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("fixed: [broken yaml\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			managedHostWindowsStandalone = func() (string, bool) { return "fixed trusted record", lane == "standalone" }
			secureClientHost = func() bool { return lane == "secure-client" }
			sandboxWindowsPersonalConfigPermitted = func() bool { return lane != "unconfirmed-deployment" }
			cfg = &config.Config{}
			sentinel := cfg
			for _, requested := range []string{"", "auto"} {
				cmd := newSandboxRunCmd()
				if requested != "" {
					if err := cmd.Flags().Parse([]string{"--runtime", requested}); err != nil {
						t.Fatal(err)
					}
				}
				err := sandboxPreRunForHost(cmd, "windows", "amd64")
				if err == nil || !strings.Contains(err.Error(), "OpenShell sandboxes run") || commandExitCode(err) != 3 || cfg != sentinel {
					t.Fatalf("managed %s runtime %q used personal configuration: %v (exit %d)", lane, requested, err, commandExitCode(err))
				}
			}
		})
	}
}
