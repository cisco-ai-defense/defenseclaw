// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// useConfigValidateLayout points config validate at a goos standalone
// layout under dir; managedHost publishes its runtime descriptor.
func useConfigValidateLayout(t *testing.T, dir, goos string, managedHost bool) managed.StandaloneLayout {
	t.Helper()
	layout, err := managed.StandaloneLayoutFor(goos)
	if goos == "windows" {
		layout, err = managed.StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	}
	if err != nil {
		t.Fatal(err)
	}
	layout.ConfigPath = filepath.Join(dir, "etc", "config.yaml")
	layout.DescriptorPath = filepath.Join(dir, "etc", "managed-runtime.json")
	layout.DataDir = filepath.Join(dir, "state")
	if err := os.MkdirAll(filepath.Dir(layout.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if managedHost {
		if err := os.WriteFile(layout.DescriptorPath, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	} else if err := os.Remove(layout.DescriptorPath); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	previous := configValidateLayout
	configValidateLayout = func() (managed.StandaloneLayout, error) { return layout, nil }
	t.Cleanup(func() {
		configValidateLayout = previous
		configValidateCmd.SetOut(nil)
		configValidateJSON, configValidateDataDir, configValidatePath = false, "", ""
	})
	return layout
}

// GAP-0601: validate refuses what ensure refuses a managed standalone config
// on, in a candidate and in the installed config alike: a bind beyond
// loopback on any computer, another port where the file is for Linux or
// macOS, and on a managed computer also a data_dir outside its layout.
func TestConfigValidateRefusesManagedLayoutValues(t *testing.T) {
	const head = "config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n"
	dir := t.TempDir()
	for _, tc := range []struct {
		name, goos, body, want string
		managedHost            bool
	}{
		{"bind beyond loopback", "linux", "gateway:\n  api_bind: 0.0.0.0\n", `gateway.api_bind "0.0.0.0" must be 127.0.0.1`, false},
		{"bind beyond loopback on Windows", "windows", "gateway:\n  api_bind: 0.0.0.0\n", `gateway.api_bind "0.0.0.0" must be 127.0.0.1`, true},
		{"another port on Linux", "linux", "gateway:\n  api_port: 18971\n", "gateway.api_port 18971 must be 18970", true},
		{"another port on macOS", "darwin", "gateway:\n  api_port: 18971\n", "gateway.api_port 18971 must be 18970", true},
		{"another port in a POSIX file", "linux", "data_dir: /var/lib/defenseclaw\ngateway:\n  api_port: 18971\n", "gateway.api_port 18971 must be 18970", false},
		{"another data_dir", "linux", "data_dir: " + filepath.Join(dir, "elsewhere") + "\n", "must be " + filepath.Join(dir, "managed", "state"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := useConfigValidateLayout(t, filepath.Join(dir, "managed"), tc.goos, tc.managedHost)
			configValidateDataDir = layout.DataDir
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(head+tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, installed := range []string{filepath.Join(dir, "installed.yaml"), path} {
				t.Setenv(managed.ConfigPathEnv, installed)
				configValidateCmd.SetOut(&strings.Builder{})
				if err := configValidateCmd.RunE(configValidateCmd, []string{path}); err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("config validate (installed %s) = %v, want a refusal naming %s", installed, err, tc.want)
				}
			}
		})
	}
	useConfigValidateLayout(t, filepath.Join(dir, "managed"), "linux", true)
	path := filepath.Join(dir, "loopback.yaml")
	if err := os.WriteFile(path, []byte(head+"gateway:\n  api_bind: 127.0.0.1\n  api_port: 18970\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configValidateCmd.SetOut(&strings.Builder{})
	if err := configValidateCmd.RunE(configValidateCmd, []string{path}); err != nil {
		t.Fatalf("the managed layout's own values refused: %v", err)
	}
}

// GAP-0601: Windows Setup takes the gateway.api_port chosen before the first
// install, so validate accepts it on a Windows managed computer, and off a
// managed computer, where the file could be for Windows, it warns that Linux
// and macOS refuse it.
func TestConfigValidateAcceptsAWindowsAPIPort(t *testing.T) {
	const body = "config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\ngateway:\n  api_bind: 127.0.0.1\n  api_port: 18971\n"
	dir := t.TempDir()
	for _, tc := range []struct {
		name, goos, warning string
		managedHost         bool
	}{
		{"Windows managed computer", "windows", "", true},
		{"off a managed computer", "linux", "managed_api_port: gateway.api_port 18971 is refused by Linux and macOS ensure", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := useConfigValidateLayout(t, filepath.Join(dir, tc.goos), tc.goos, tc.managedHost)
			configValidateDataDir = layout.DataDir
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(managed.ConfigPathEnv, path)
			out := &strings.Builder{}
			configValidateCmd.SetOut(out)
			if err := configValidateCmd.RunE(configValidateCmd, []string{path}); err != nil {
				t.Fatalf("config validate of a Windows api_port: %v", err)
			}
			if got := strings.Contains(out.String(), "managed_api_port"); got != (tc.warning != "") ||
				(tc.warning != "" && !strings.Contains(out.String(), tc.warning)) {
				t.Fatalf("config validate output = %q, want warning %q", out.String(), tc.warning)
			}
		})
	}
}

// GAP-0602: with no file, validate on a standalone managed computer reads
// the installed managed config, not the per-user one root has none of.
func TestConfigValidateDefaultsToTheManagedInstalledConfig(t *testing.T) {
	dir := t.TempDir()
	layout := useConfigValidateLayout(t, dir, "linux", true)
	if err := os.WriteFile(layout.ConfigPath, []byte("config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managed.ConfigPathEnv, "")
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(dir, "per-user"))
	out := &strings.Builder{}
	configValidateCmd.SetOut(out)
	if err := configValidateCmd.RunE(configValidateCmd, nil); err != nil {
		t.Fatalf("config validate with no file on a managed computer: %v", err)
	}
	if !strings.Contains(out.String(), layout.ConfigPath+": valid") {
		t.Fatalf("config validate output = %q, want %s validated", out.String(), layout.ConfigPath)
	}
}

// GAP-0605: a path with no file is reported as not found, with the path and
// the next step, not as a config that "could not be compiled safely"; the
// JSON failure carries the same code.
func TestConfigValidateMissingFileIsNotFound(t *testing.T) {
	dir := t.TempDir()
	useConfigValidateLayout(t, dir, "linux", false)
	missing := filepath.Join(dir, "no", "such.yaml")
	for _, asJSON := range []bool{false, true} {
		configValidateJSON = asJSON
		out := &strings.Builder{}
		configValidateCmd.SetOut(out)
		err := configValidateCmd.RunE(configValidateCmd, []string{missing})
		if err == nil || !strings.Contains(err.Error(), "cannot read "+missing+": no file exists at this path") ||
			!strings.Contains(err.Error(), "check the path") || strings.Contains(err.Error(), "compiled safely") {
			t.Fatalf("config validate %s (json %v) = %v, want a not-found error naming the path", missing, asJSON, err)
		}
		if asJSON && !strings.Contains(out.String(), "[config_not_found]") {
			t.Fatalf("config validate --json output = %q, want the config_not_found reason", out.String())
		}
	}
}
