// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const (
	outageNowDefaultConfig = "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n"
	outageNowStrictConfig  = outageNowDefaultConfig + "  rule_pack: strict\n"
)

func writeOutageNowConfig(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if body == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// hookOutageFailModeNow answers from the config of the hook runtime at the
// time of the call, not from what the hooks recorded: a rule pack switched to
// strict after the gateway stopped closes the outage, and a config this
// release cannot load, a managed one or none closes it too.
func TestHookOutageFailModeNowReadsTheConfigOnDisk(t *testing.T) {
	for _, tc := range []struct {
		name, config, connector, want string
	}{
		{"default pack", outageNowDefaultConfig, "codex", "open"},
		{"action mode, default pack", "config_version: 9\nobservability: {}\nguardrail:\n  mode: action\n", "codex", "open"},
		{"permissive pack", outageNowDefaultConfig + "  rule_pack: permissive\n", "claudecode", "open"},
		{"strict pack", outageNowStrictConfig, "codex", "closed"},
		{"saved closed overrides default", outageNowDefaultConfig + "  hook_fail_mode: closed\n", "codex", "closed"},
		{"saved open overrides strict", outageNowStrictConfig + "  hook_fail_mode: open\n", "codex", "open"},
		{"connector closed overrides global open", outageNowDefaultConfig + "  hook_fail_mode: open\n  connectors:\n    codex:\n      hook_fail_mode: closed\n", "codex", "closed"},
		{"strict pack for this connector", outageNowDefaultConfig + "  connectors:\n    codex:\n      rule_pack: strict\n", "codex", "closed"},
		{"strict pack for another connector", outageNowDefaultConfig + "  connectors:\n    codex:\n      rule_pack: strict\n", "claudecode", "open"},
		{"upper-case connector name", outageNowStrictConfig, " CODEX ", "closed"},
		{"no connector", outageNowDefaultConfig, " ", "closed"},
		{"no config", "", "codex", "closed"},
		{"config this release cannot read", "config_version: 9\nguardrail: [\n", "codex", "closed"},
		{"an older config", "config_version: 7\nguardrail:\n  mode: observe\n", "codex", "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			t.Setenv("HOME", home)
			writeOutageNowConfig(t, home, tc.config)
			if got := hookOutageFailModeNow(tc.connector, filepath.Join(home, "hooks")); got != tc.want {
				t.Fatalf("hookOutageFailModeNow(%q) = %q, want %q", tc.connector, got, tc.want)
			}
		})
	}
}

// oss-outage-open review (loop round 3): the policy source of an outage is
// the config of the hook runtime asking (config.yaml in the data directory
// above its hooks folder). The hook process inherits the agent's
// environment, so a DEFENSECLAW_CONFIG or DEFENSECLAW_HOME that names another
// default-tier config must not reopen an outage the runtime's strict config
// closes; nor does it close one the runtime's default config opens. A config
// whose data_dir is another folder is not the runtime's config.
func TestHookOutageFailModeNowReadsOnlyTheRuntimesConfig(t *testing.T) {
	for _, tc := range []struct {
		name, runtime string
		env           func(home, other string) map[string]string
		dataDirOther  bool
		hookDir       func(home string) string
		want          string
	}{
		{name: "DEFENSECLAW_CONFIG names a default config elsewhere", runtime: outageNowStrictConfig,
			env: func(_, other string) map[string]string {
				return map[string]string{"DEFENSECLAW_CONFIG": filepath.Join(other, "config.yaml")}
			}, want: "closed"},
		{name: "DEFENSECLAW_HOME names a default home elsewhere", runtime: outageNowStrictConfig,
			env: func(_, other string) map[string]string { return map[string]string{"DEFENSECLAW_HOME": other} }, want: "closed"},
		{name: "both name a default config elsewhere", runtime: outageNowStrictConfig,
			env: func(_, other string) map[string]string {
				return map[string]string{"DEFENSECLAW_HOME": other, "DEFENSECLAW_CONFIG": filepath.Join(other, "config.yaml")}
			}, want: "closed"},
		// The agent's environment never moves the runtime's data directory
		// either (loadHookRuntimeConfig, the rule hook-data-dir uses too).
		{name: "DEFENSECLAW_CONFIG names this config and DEFENSECLAW_HOME is elsewhere", runtime: outageNowDefaultConfig,
			env: func(home, other string) map[string]string {
				return map[string]string{"DEFENSECLAW_HOME": other, "DEFENSECLAW_CONFIG": filepath.Join(home, "config.yaml")}
			}, want: "open"},
		{name: "the environment names a strict config elsewhere", runtime: outageNowDefaultConfig,
			env: func(_, other string) map[string]string {
				return map[string]string{"DEFENSECLAW_HOME": other, "DEFENSECLAW_CONFIG": filepath.Join(other, "config.yaml")}
			}, want: "open"},
		{name: "the runtime config keeps its data elsewhere", runtime: outageNowDefaultConfig, dataDirOther: true, want: "closed"},
		{name: "relative hook dir", runtime: outageNowDefaultConfig, hookDir: func(string) string { return "hooks" }, want: "closed"},
		{name: "no hook dir", runtime: outageNowDefaultConfig, hookDir: func(string) string { return "" }, want: "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			other := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", "")
			t.Setenv("DEFENSECLAW_CONFIG", "")
			t.Setenv("HOME", home)
			runtimeConfig := tc.runtime
			if tc.dataDirOther {
				runtimeConfig = "data_dir: " + other + "\n" + runtimeConfig
			}
			writeOutageNowConfig(t, home, runtimeConfig)
			otherConfig := outageNowDefaultConfig
			if tc.runtime == outageNowDefaultConfig {
				otherConfig = outageNowStrictConfig
			}
			writeOutageNowConfig(t, other, otherConfig)
			if tc.env != nil {
				for key, value := range tc.env(home, other) {
					t.Setenv(key, value)
				}
			}
			hookDir := filepath.Join(home, "hooks")
			if tc.hookDir != nil {
				hookDir = tc.hookDir(home)
			}
			if got := hookOutageFailModeNow("codex", hookDir); got != tc.want {
				t.Fatalf("hookOutageFailModeNow = %q, want %q", got, tc.want)
			}
		})
	}
}

// A host's managed installation marker is independent of a per-user-looking
// config. A stale per-user hook cannot reopen a managed host's outage.
func TestHookOutageFailModeNowHonorsTheManagedHostMarker(t *testing.T) {
	home := t.TempDir()
	writeOutageNowConfig(t, home, outageNowDefaultConfig)
	marker := filepath.Join(t.TempDir(), "runtime-descriptor")
	oldDescriptor := managedHostDescriptorPath
	oldWindows := managedHostWindowsStandalone
	oldSecureClient := secureClientHost
	oldUncertain := managedHostWindowsMarkerUncertain
	managedHostDescriptorPath = func() string { return marker }
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	secureClientHost = func() bool { return false }
	t.Cleanup(func() {
		managedHostDescriptorPath = oldDescriptor
		managedHostWindowsStandalone = oldWindows
		secureClientHost = oldSecureClient
		managedHostWindowsMarkerUncertain = oldUncertain
	})
	if got := hookOutageFailModeNow("codex", filepath.Join(home, "hooks")); got != "open" {
		t.Fatalf("absent managed marker: got %q, want open", got)
	}
	if err := os.WriteFile(marker, []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := hookOutageFailModeNow("codex", filepath.Join(home, "hooks")); got != "closed" {
		t.Fatalf("present managed marker: got %q, want closed", got)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "missing-target"), marker); err == nil {
		if got := hookOutageFailModeNow("codex", filepath.Join(home, "hooks")); got != "closed" {
			t.Fatalf("broken managed marker link: got %q, want closed", got)
		}
		if err := os.Remove(marker); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS != "windows" {
		parent := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		marker = filepath.Join(parent, "runtime-descriptor")
		if got := hookOutageFailModeNow("codex", filepath.Join(home, "hooks")); got != "closed" {
			t.Fatalf("unreadable managed marker path: got %q, want closed", got)
		}
	}
	marker = filepath.Join(t.TempDir(), "runtime-descriptor")
	managedHostWindowsMarkerUncertain = func() bool { return true }
	if got := hookOutageFailModeNow("codex", filepath.Join(home, "hooks")); got != "closed" {
		t.Fatalf("unreadable Windows managed marker: got %q, want closed", got)
	}
	managedHostWindowsMarkerUncertain = oldUncertain
	managedHostWindowsStandalone = func() (string, bool) { return "HKLM managed marker", true }
	if got := hookOutageFailModeNow("codex", filepath.Join(home, "hooks")); got != "closed" {
		t.Fatalf("Windows managed marker: got %q, want closed", got)
	}
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	secureClientHost = func() bool { return true }
	if got := hookOutageFailModeNow("codex", filepath.Join(home, "hooks")); got != "closed" {
		t.Fatalf("Secure Client marker: got %q, want closed", got)
	}
}

// A per-user native hook whose home comes from the agent's DEFENSECLAW_HOME
// (not the packaged launcher's protected install state) reads that home's
// record for its status, but the agent chose it, so nothing there can open an
// outage: OutageFailModeNow stays unset and the outage closed.
func TestPerUserNativeHookOnAnAgentChosenHomeNeverOpensAnOutage(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	t.Setenv("DEFENSECLAW_CONFIG", filepath.Join(home, "config.yaml"))
	t.Setenv("HOME", home)
	writeOutageNowConfig(t, home, outageNowDefaultConfig)
	writeOutageNowConfig(t, filepath.Join(home, "hooks"), "")
	sidecar, err := json.Marshal(map[string]any{
		"version": 2, "gateway_addr": "127.0.0.1:18970",
		"fail_modes": map[string]string{"codex": "open"}, "fail_mode_sources": map[string]string{"codex": "config"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "hooks", ".hookcfg"), sidecar, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, trusted := trustedNativeHookHome(); trusted {
		t.Skip("this test binary runs from a trusted native hook home")
	}
	opts := buildHookOptions("codex", "PreToolUse", "", "")
	if opts.OutageFailModeNow != nil && opts.OutageFailModeNow() == "open" {
		t.Fatal("an agent-chosen DEFENSECLAW_HOME opened the outage")
	}
}
