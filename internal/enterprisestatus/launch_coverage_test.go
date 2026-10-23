// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A plugin cannot report its own absence. The process scan must name the
// supported launches that bypass plugin loading, including the equivalent
// environment form and the other per-user plugin connector.
func TestPluginLaunchCoverage(t *testing.T) {
	const home = "/home/alice"
	for _, tc := range []struct {
		name, connector string
		argv            []string
		env             map[string]string
		envKnown        bool
		want            string
	}{
		{"OpenCode pure flag", "opencode", []string{"opencode", "--pure"}, nil, false, "opencode_pure"},
		{"OpenCode pure subcommand", "opencode", []string{"opencode", "run", "--pure=true", "hello"}, nil, false, "opencode_pure"},
		{"OpenCode pure environment", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_PURE": "1"}, true, "opencode_pure"},
		{"OpenCode pure uppercase environment", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_PURE": "TRUE"}, true, "opencode_pure"},
		{"OpenCode pure zero is normal", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_PURE": "0"}, true, ""},
		{"OpenCode pure false is normal", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_PURE": "false"}, true, ""},
		{"OpenCode pure yes environment", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_PURE": "yes"}, true, "opencode_pure"},
		{"OpenCode pure on environment", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_PURE": "on"}, true, "opencode_pure"},
		{"OpenCode pure y environment", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_PURE": "y"}, true, "opencode_pure"},
		{"OpenCode pure no is normal", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_PURE": "no"}, true, ""},
		{"OpenCode pure off is normal", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_PURE": "off"}, true, ""},
		{"OpenCode moved managed config", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_TEST_MANAGED_CONFIG_DIR": "/tmp/empty"}, true, "opencode_managed_config_relocated"},
		{"OpenCode default additive config", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_CONFIG_DIR": home + "/.config/opencode"}, true, ""},
		{"OpenCode equivalent additive config", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_CONFIG_DIR": home + "/.config/extra/../opencode"}, true, ""},
		{"OpenCode other additive config", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_CONFIG_DIR": "/tmp/extra"}, true, ""},
		{"OpenCode additive config with moved home", "opencode", []string{"opencode"}, map[string]string{"OPENCODE_CONFIG_DIR": "/tmp/extra", "HOME": "/tmp/other"}, true, "opencode_user_config_relocated"},
		{"OpenCode moved XDG config", "opencode", []string{"opencode"}, map[string]string{"XDG_CONFIG_HOME": "/tmp/empty"}, true, "opencode_user_config_relocated"},
		{"OpenCode environment unreadable", "opencode", []string{"opencode"}, nil, false, "launch_environment_unverified"},
		{"OpenCode arguments unreadable", "opencode", nil, nil, false, "launch_environment_unverified"},
		{"OpenCode normal", "opencode", []string{"opencode", "run", "hello"}, map[string]string{}, true, ""},
		{"OpenCode prompt text", "opencode", []string{"opencode", "run", "please test --pure"}, map[string]string{}, true, ""},
		{"OpenCode false flag", "opencode", []string{"opencode", "--pure=false"}, map[string]string{}, true, ""},
		{"Amp relocated XDG", "amp", []string{"amp"}, map[string]string{"XDG_CONFIG_HOME": "/tmp/amp"}, true, "amp_plugin_config_relocated"},
		{"Amp relocated home", "amp", []string{"amp"}, map[string]string{"HOME": "/tmp/home"}, true, "amp_plugin_config_relocated"},
		{"Amp normal", "amp", []string{"amp"}, map[string]string{"HOME": home, "XDG_CONFIG_HOME": home + "/.config"}, true, ""},
		{"Amp environment unreadable", "amp", []string{"amp"}, nil, false, "launch_environment_unverified"},
		{"Amp home and config unset", "amp", []string{"amp"}, map[string]string{}, true, "launch_environment_unverified"},
		{"Devin config flag", "devin", []string{"devin", "--config", "/tmp/other.json"}, nil, false, "devin_config_override"},
		{"Devin config equals", "devin", []string{"devin", "--config=/tmp/other.json"}, nil, false, "devin_config_override"},
		{"Devin moved home", "devin", []string{"devin"}, map[string]string{"HOME": "/tmp/other"}, true, "user_config_relocated"},
		{"Devin normal", "devin", []string{"devin"}, map[string]string{"HOME": home}, true, ""},
		{"Hermes safe mode", "hermes", []string{"hermes", "--safe-mode"}, nil, false, "hermes_safe_mode"},
		{"Hermes safe abbreviation", "hermes", []string{"hermes", "--sa"}, nil, false, "hermes_safe_mode"},
		{"Hermes safe environment", "hermes", []string{"hermes"}, map[string]string{"HERMES_SAFE_MODE": "1"}, true, "hermes_safe_mode"},
		{"Hermes safe on environment", "hermes", []string{"hermes"}, map[string]string{"HERMES_SAFE_MODE": " On "}, true, "hermes_safe_mode"},
		{"Hermes safe zero is normal", "hermes", []string{"hermes"}, map[string]string{"HERMES_SAFE_MODE": "0", "HOME": home}, true, ""},
		{"Hermes safe false is normal", "hermes", []string{"hermes"}, map[string]string{"HERMES_SAFE_MODE": "false", "HOME": home}, true, ""},
		{"Hermes safe off is normal", "hermes", []string{"hermes"}, map[string]string{"HERMES_SAFE_MODE": "off", "HOME": home}, true, ""},
		{"Hermes default managed dir", "hermes", []string{"hermes"}, map[string]string{"HERMES_MANAGED_DIR": "/etc/hermes", "HOME": home}, true, ""},
		{"Hermes equivalent managed dir", "hermes", []string{"hermes"}, map[string]string{"HERMES_MANAGED_DIR": "/etc/hermes/", "HOME": home}, true, ""},
		{"Hermes default managed dir with moved home", "hermes", []string{"hermes"}, map[string]string{"HERMES_MANAGED_DIR": "/etc/hermes", "HERMES_HOME": "/tmp/other"}, true, "hermes_config_relocated"},
		{"Hermes moved managed dir", "hermes", []string{"hermes"}, map[string]string{"HERMES_MANAGED_DIR": "/tmp/other"}, true, "hermes_config_relocated"},
		{"Hermes ignore user config keeps hooks", "hermes", []string{"hermes", "--ignore-user-config"}, map[string]string{"HOME": home}, true, ""},
		{"Antigravity moved home", "antigravity", []string{"agy"}, map[string]string{"HOME": "/tmp/other"}, true, "user_config_relocated"},
		{"Kiro alternate agent", "kiro", []string{"kiro-cli", "--agent", "mine"}, nil, false, "kiro_alternate_agent"},
		{"Kiro alternate agent equals", "kiro", []string{"kiro-cli", "--agent=mine"}, nil, false, "kiro_alternate_agent"},
		{"Kiro managed agent", "kiro", []string{"kiro-cli", "--agent=defenseclaw"}, map[string]string{}, true, ""},
		{"Kiro cloud", "kiro", []string{"kiro-cli", "--cloud"}, nil, false, "kiro_cloud_session"},
		{"Kiro resume could be cloud", "kiro", []string{"kiro-cli", "--resume-id", "session-id"}, map[string]string{}, true, "kiro_resume_placement_unverified"},
		{"Kiro resume equals could be cloud", "kiro", []string{"kiro-cli", "--resume-id=session-id"}, map[string]string{}, true, "kiro_resume_placement_unverified"},
		{"Kiro prompt mentions resume", "kiro", []string{"kiro-cli", "--", "--resume-id=session-id"}, map[string]string{}, true, ""},
		{"Kiro default home", "kiro", []string{"kiro-cli"}, map[string]string{"KIRO_HOME": home + "/.kiro"}, true, ""},
		{"Kiro default home with moved agents", "kiro", []string{"kiro-cli"}, map[string]string{"KIRO_HOME": home + "/.kiro", "KIRO_AGENT_CONFIG_DIR": "/tmp/agents"}, true, "kiro_hook_config_relocated"},
		{"Kiro moved home", "kiro", []string{"kiro-cli"}, map[string]string{"KIRO_HOME": "/tmp/other"}, true, "kiro_hook_config_relocated"},
		{"Kiro moved agents", "kiro", []string{"kiro-cli"}, map[string]string{"KIRO_AGENT_CONFIG_DIR": "/tmp/agents"}, true, "kiro_hook_config_relocated"},
		{"Kiro moved test agents", "kiro", []string{"kiro-cli"}, map[string]string{"KIRO_TEST_AGENTS_DIR": "/tmp/agents"}, true, "kiro_hook_config_relocated"},
		{"Other connector", "codex", []string{"codex", "--pure"}, nil, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := PluginLaunchCoverage(tc.connector, tc.argv, tc.env, tc.envKnown, home); got != tc.want {
				t.Fatalf("coverage = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPluginLaunchCoverageOpenCodeManagedDirectoryMatchesEnrollment(t *testing.T) {
	managed := "/etc/opencode"
	switch runtime.GOOS {
	case "darwin":
		managed = "/Library/Application Support/opencode"
	case "windows":
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		managed = filepath.Join(programData, "opencode")
	}
	for _, tc := range []struct {
		name, selected, want string
	}{
		{"enrolled directory", managed, ""},
		{"equivalent directory", filepath.Join(managed, "extra", ".."), ""},
		{"other directory", filepath.Join(filepath.Dir(managed), "other"), "opencode_managed_config_relocated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"OPENCODE_TEST_MANAGED_CONFIG_DIR": tc.selected}
			if runtime.GOOS == "windows" {
				env["PROGRAMDATA"] = os.Getenv("ProgramData")
			}
			if got := PluginLaunchCoverage("opencode", []string{"opencode"}, env, true, "/home/alice"); got != tc.want {
				t.Fatalf("coverage = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPluginLaunchCoverageOpenCodeWindowsProgramData(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows managed config path")
	}
	t.Setenv("ProgramData", `C:\ProgramData`)
	for _, tc := range []struct {
		name, programData, selected, want string
	}{
		{"enrolled ProgramData", `c:\programdata`, "", ""},
		{"relocated ProgramData", `C:\Elsewhere`, "", "opencode_managed_config_relocated"},
		{"explicit enrolled directory wins", `C:\Elsewhere`, `C:\ProgramData\opencode`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"PROGRAMDATA": tc.programData, "OPENCODE_TEST_MANAGED_CONFIG_DIR": tc.selected}
			if got := PluginLaunchCoverage("opencode", []string{"opencode"}, env, true, `C:\Users\alice`); got != tc.want {
				t.Fatalf("coverage = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPluginLaunchCoverageKiroWindowsDefaultHome(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows home paths")
	}
	const home = `C:\Users\alice`
	for _, tc := range []struct {
		name, selected, accountHome, want string
	}{
		{"default with different case", `c:\users\ALICE\.kiro\`, home, ""},
		{"relocated home", `C:\Users\bob\.kiro`, home, "kiro_hook_config_relocated"},
		{"unresolved account home", `C:\Users\alice\.kiro`, "", "kiro_hook_config_relocated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{"KIRO_HOME": tc.selected}
			if got := PluginLaunchCoverage("kiro", []string{"kiro-cli"}, env, true, tc.accountHome); got != tc.want {
				t.Fatalf("coverage = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPluginLaunchCoveragePlatformHomeSelectors(t *testing.T) {
	const home = "/home/alice"
	profileOnly := PluginLaunchCoverage("amp", []string{"amp"}, map[string]string{"USERPROFILE": home}, true, home)
	profileMismatch := PluginLaunchCoverage("amp", []string{"amp"}, map[string]string{"HOME": home, "USERPROFILE": "/tmp/other"}, true, home)
	devinAppData := PluginLaunchCoverage("devin", []string{"devin"}, map[string]string{"HOME": home, "APPDATA": "/tmp/other"}, true, home)
	hermesLocalAppData := PluginLaunchCoverage("hermes", []string{"hermes"}, map[string]string{"HOME": home, "LOCALAPPDATA": "/tmp/other"}, true, home)
	if runtime.GOOS == "windows" {
		if profileOnly != "" || profileMismatch != "amp_plugin_config_relocated" ||
			devinAppData != "user_config_relocated" || hermesLocalAppData != "hermes_config_relocated" {
			t.Fatalf("Windows profile selectors: only=%q, mismatch=%q, Devin=%q, Hermes=%q", profileOnly, profileMismatch, devinAppData, hermesLocalAppData)
		}
	} else if profileOnly != "launch_environment_unverified" || profileMismatch != "" || devinAppData != "" || hermesLocalAppData != "" {
		t.Fatalf("Unix profile selectors: only=%q, mismatch=%q, Devin=%q, Hermes=%q", profileOnly, profileMismatch, devinAppData, hermesLocalAppData)
	}
}
