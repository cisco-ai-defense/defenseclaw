// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// PluginLaunchCoverage reports a launch that can omit a managed in-agent
// plugin. It examines only the process's own argv and environment, never a
// prompt, and returns a fixed reason so neither can leak into a status or
// audit record. An unreadable environment is unknown, not proof of coverage.
func PluginLaunchCoverage(connector string, argv []string, env map[string]string, envKnown bool, accountHome string) string {
	switch connector {
	case "opencode":
		args := argv
		if len(args) != 0 {
			args = args[1:]
		}
		for _, arg := range args {
			if arg == "--" {
				break
			}
			if arg == "--pure" || arg == "--pure=true" || arg == "--pure=1" {
				return "opencode_pure"
			}
		}
		if !envKnown {
			return "launch_environment_unverified"
		}
		if openCodePureEnabled(env["OPENCODE_PURE"]) {
			return "opencode_pure"
		}
		if openCodeManagedConfigRelocated(env) {
			return "opencode_managed_config_relocated"
		}
		// OPENCODE_CONFIG_DIR adds a config layer. It does not replace the
		// machine managed directory containing the DefenseClaw plugin.
		if accountHome == "" {
			return "launch_environment_unverified"
		}
		if launchHomeRelocated(env, accountHome) {
			return "opencode_user_config_relocated"
		}
		if xdg := env["XDG_CONFIG_HOME"]; xdg != "" && !sameLaunchPath(xdg, filepath.Join(accountHome, ".config")) {
			return "opencode_user_config_relocated"
		}
	case "amp":
		return userConfigLaunchCoverage(env, envKnown, accountHome, "amp_plugin_config_relocated")
	case "devin":
		for _, arg := range launchOptions(argv) {
			if arg == "--config" || strings.HasPrefix(arg, "--config=") {
				return "devin_config_override"
			}
		}
		if launchWindowsAppDataRelocated(env, accountHome, "APPDATA", "Roaming") {
			return "user_config_relocated"
		}
		return userConfigLaunchCoverage(env, envKnown, accountHome, "user_config_relocated")
	case "antigravity":
		return userConfigLaunchCoverage(env, envKnown, accountHome, "user_config_relocated")
	case "hermes":
		for _, arg := range launchOptions(argv) {
			if (len(arg) >= len("--sa") && strings.HasPrefix("--safe-mode", arg)) ||
				arg == "--safe-mode=true" || arg == "--safe-mode=1" {
				return "hermes_safe_mode"
			}
		}
		if !envKnown {
			return "launch_environment_unverified"
		}
		if hermesSafeModeEnabled(env["HERMES_SAFE_MODE"]) {
			return "hermes_safe_mode"
		}
		// Hermes uses /etc/hermes when this selector is unset or names that
		// same directory; the guard treats it as the default too.
		if managed := env["HERMES_MANAGED_DIR"]; managed != "" && !sameLaunchPath(managed, "/etc/hermes") {
			return "hermes_config_relocated"
		}
		if home := env["HERMES_HOME"]; home != "" &&
			(accountHome == "" || !sameLaunchPath(home, filepath.Join(accountHome, ".hermes"))) {
			return "hermes_config_relocated"
		}
		if launchWindowsAppDataRelocated(env, accountHome, "LOCALAPPDATA", "Local") {
			return "hermes_config_relocated"
		}
		return userConfigLaunchCoverage(env, envKnown, accountHome, "user_config_relocated")
	case "kiro":
		args := argv
		if len(args) != 0 {
			args = args[1:]
		}
		resume := false
		for index, arg := range args {
			if arg == "--" {
				break
			}
			if arg == "--cloud" {
				return "kiro_cloud_session"
			}
			if arg == "--resume-id" || strings.HasPrefix(arg, "--resume-id=") {
				resume = true
			}
			if arg == "--agent" && (index+1 >= len(args) || args[index+1] != "defenseclaw") {
				return "kiro_alternate_agent"
			}
			if selected, ok := strings.CutPrefix(arg, "--agent="); ok && selected != "defenseclaw" {
				return "kiro_alternate_agent"
			}
		}
		if resume {
			return "kiro_resume_placement_unverified"
		}
		if !envKnown {
			return "launch_environment_unverified"
		}
		if home := env["KIRO_HOME"]; home != "" &&
			(accountHome == "" || !sameLaunchPath(home, filepath.Join(accountHome, ".kiro"))) {
			return "kiro_hook_config_relocated"
		}
		if env["KIRO_AGENT_CONFIG_DIR"] != "" || env["KIRO_TEST_AGENTS_DIR"] != "" {
			return "kiro_hook_config_relocated"
		}
	}
	return ""
}

func openCodePureEnabled(value string) bool {
	// The reviewed OpenCode releases use both a legacy flag reader ("1" or
	// case-insensitive "true") and an Effect boolean config reader (also
	// lowercase "yes", "on" and "y") for pure-mode plugin loading.
	return value == "1" || strings.EqualFold(value, "true") ||
		value == "yes" || value == "on" || value == "y"
}

func hermesSafeModeEnabled(value string) bool {
	// Hermes uses its shared truthy set after trimming whitespace.
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func openCodeManagedConfigRelocated(env map[string]string) bool {
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
	// The test selector replaces the managed directory. Without it, Windows
	// OpenCode derives that directory from its process's ProgramData value.
	if selected := env["OPENCODE_TEST_MANAGED_CONFIG_DIR"]; selected != "" {
		return !sameLaunchPath(selected, managed)
	}
	if runtime.GOOS == "windows" {
		processProgramData := env["PROGRAMDATA"]
		if processProgramData == "" {
			processProgramData = `C:\ProgramData`
		}
		return !sameLaunchPath(filepath.Join(processProgramData, "opencode"), managed)
	}
	return false
}

// sameLaunchPath reports whether the directory a launch selected (a) is the
// one the managed install uses (b). Equal clean spellings match
// (case-insensitively on Windows). Other spellings match only when this
// process proves they name one directory: both resolve to the same existing
// directory (a symlink, junction, bind mount, short or case alias, macOS
// /etc -> /private/etc), or neither exists yet and both name the same entry
// of one parent directory. A relative path, one that cannot be resolved,
// and on Windows a network or device path, is not proven and stays
// reported. Unix resolves ".." after links, so a spelling with ".." is
// compared by the directory it resolves to, never by its text.
func sameLaunchPath(a, b string) bool {
	physical := runtime.GOOS != "windows" && (launchPathHasDotDot(a) || launchPathHasDotDot(b))
	if !physical {
		a, b = filepath.Clean(a), filepath.Clean(b)
		if a == b || runtime.GOOS == "windows" && strings.EqualFold(a, b) {
			return true
		}
	}
	return sameLaunchDirectory(a, b, physical, 0)
}

// maxLaunchPathDepth bounds the walk to the nearest existing ancestors.
const maxLaunchPathDepth = 64

func sameLaunchDirectory(a, b string, physical bool, depth int) bool {
	if depth > maxLaunchPathDepth || !launchPathResolvable(a) || !launchPathResolvable(b) {
		return false
	}
	aInfo, aErr := os.Stat(a)
	bInfo, bErr := os.Stat(b)
	if aErr == nil && bErr == nil {
		return aInfo.IsDir() && bInfo.IsDir() && os.SameFile(aInfo, bInfo)
	}
	// A directory the agent has not created yet is the same one only when
	// both spellings name one entry of one existing parent.
	if physical || !errors.Is(aErr, fs.ErrNotExist) || !errors.Is(bErr, fs.ErrNotExist) {
		return false
	}
	aName, bName := filepath.Base(a), filepath.Base(b)
	if aName != bName && (runtime.GOOS != "windows" || !strings.EqualFold(aName, bName)) {
		return false
	}
	aParent, bParent := filepath.Dir(a), filepath.Dir(b)
	if aParent == a || bParent == b {
		return false
	}
	return sameLaunchDirectory(aParent, bParent, false, depth+1)
}

// launchPathResolvable admits only absolute local paths. Status runs
// privileged; on Windows, resolving a UNC or device spelling from a user's
// environment could contact a server the user names.
func launchPathResolvable(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	if runtime.GOOS == "windows" {
		volume := filepath.VolumeName(path)
		return len(volume) == 2 && volume[1] == ':'
	}
	return true
}

func launchPathHasDotDot(path string) bool {
	return path == ".." || strings.HasPrefix(path, "../") || strings.HasSuffix(path, "/..") || strings.Contains(path, "/../")
}

func launchHomeRelocated(env map[string]string, accountHome string) bool {
	keys := []string{"HOME"}
	if runtime.GOOS == "windows" {
		keys = append(keys, "USERPROFILE")
	}
	for _, key := range keys {
		if home := env[key]; home != "" && !sameLaunchPath(home, accountHome) {
			return true
		}
	}
	return false
}

func launchWindowsAppDataRelocated(env map[string]string, accountHome, key, leaf string) bool {
	value := env[key]
	return runtime.GOOS == "windows" && value != "" && accountHome != "" &&
		!sameLaunchPath(value, filepath.Join(accountHome, "AppData", leaf))
}

func launchOptions(argv []string) []string {
	if len(argv) == 0 {
		return nil
	}
	for index, arg := range argv[1:] {
		if arg == "--" {
			return argv[1 : index+1]
		}
	}
	return argv[1:]
}

func userConfigLaunchCoverage(env map[string]string, envKnown bool, accountHome, relocatedReason string) string {
	profileKnown := runtime.GOOS == "windows" && env["USERPROFILE"] != ""
	if !envKnown || accountHome == "" || env["HOME"] == "" && !profileKnown && env["XDG_CONFIG_HOME"] == "" {
		return "launch_environment_unverified"
	}
	if launchHomeRelocated(env, accountHome) {
		return relocatedReason
	}
	if xdg := env["XDG_CONFIG_HOME"]; xdg != "" && !sameLaunchPath(xdg, filepath.Join(accountHome, ".config")) {
		return relocatedReason
	}
	return ""
}
