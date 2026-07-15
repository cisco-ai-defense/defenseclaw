//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

const claudeCodeManagedPreferencesDomain = "com.anthropic.claudecode"

const claudeCodeForcedPreferenceScript = `ObjC.import('Foundation')
function run(argv) {
    const defaults = $.NSUserDefaults.standardUserDefaults
    return defaults.objectIsForcedForKeyInDomain(argv[0], argv[1]) ? "true" : "false"
}`

func claudeCodePlatformManagedSettingsRoot() (string, error) {
	return "/Library/Application Support/ClaudeCode", nil
}

var (
	claudeCodeManagedPreferencesExporter = func() ([]byte, error) {
		cmd := exec.Command("/usr/bin/defaults", "export", claudeCodeManagedPreferencesDomain, "-")
		output, err := cmd.Output()
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			err = fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return output, err
	}
	claudeCodeManagedPreferencesConverter = func(plist []byte) ([]byte, error) {
		cmd := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", "--", "-")
		cmd.Stdin = bytes.NewReader(plist)
		return cmd.Output()
	}
	claudeCodeManagedPreferenceForced = func(key string) (bool, error) {
		cmd := exec.Command(
			"/usr/bin/osascript", "-l", "JavaScript", "-e",
			claudeCodeForcedPreferenceScript, "--", key, claudeCodeManagedPreferencesDomain,
		)
		output, err := cmd.Output()
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			err = fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		if err != nil {
			return false, err
		}
		switch strings.TrimSpace(string(output)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		default:
			return false, fmt.Errorf("unexpected forced-preference result %q", strings.TrimSpace(string(output)))
		}
	}
)

func loadClaudeCodeOSManagedSettings() (claudeCodeOSManagedSources, error) {
	plist, err := claudeCodeManagedPreferencesExporter()
	if err != nil {
		// `defaults export` uses a non-zero exit when the domain is absent. That
		// is ordinary fall-through to file policy, while every other inspection
		// failure remains fail-closed.
		diagnostic := strings.ToLower(err.Error())
		if strings.Contains(diagnostic, "does not exist") || strings.Contains(diagnostic, "not found") {
			return claudeCodeOSManagedSources{}, nil
		}
		return claudeCodeOSManagedSources{}, fmt.Errorf(
			"inspect Claude Code macOS managed preferences domain %s: %w",
			claudeCodeManagedPreferencesDomain,
			err,
		)
	}
	if len(plist) > int(claudeCodeSettingsReadLimit) {
		return claudeCodeOSManagedSources{}, fmt.Errorf(
			"Claude Code macOS managed preferences domain %s exceeds %d bytes",
			claudeCodeManagedPreferencesDomain,
			claudeCodeSettingsReadLimit,
		)
	}
	data, err := claudeCodeManagedPreferencesConverter(plist)
	if err != nil {
		return claudeCodeOSManagedSources{}, fmt.Errorf(
			"convert Claude Code macOS managed preferences domain %s: %w",
			claudeCodeManagedPreferencesDomain,
			err,
		)
	}
	if len(data) > int(claudeCodeSettingsReadLimit) {
		return claudeCodeOSManagedSources{}, fmt.Errorf(
			"Claude Code macOS managed preferences domain %s exceeds %d bytes",
			claudeCodeManagedPreferencesDomain,
			claudeCodeSettingsReadLimit,
		)
	}
	settings, err := decodeClaudeCodeSettings(data, "MDM/OS managed settings (com.anthropic.claudecode managed preferences)")
	if err != nil {
		return claudeCodeOSManagedSources{}, err
	}
	forcedSettings := make(map[string]interface{}, len(settings))
	for key, value := range settings {
		forced, err := claudeCodeManagedPreferenceForced(key)
		if err != nil {
			return claudeCodeOSManagedSources{}, fmt.Errorf(
				"verify Claude Code macOS managed preference %q is administrator-forced: %w",
				key,
				err,
			)
		}
		if forced {
			forcedSettings[key] = value
		}
	}
	if len(forcedSettings) == 0 {
		return claudeCodeOSManagedSources{}, nil
	}
	return claudeCodeOSManagedSources{admin: &claudeCodeSettingsSource{
		name:     "MDM/OS managed settings",
		path:     "com.anthropic.claudecode managed preferences",
		settings: forcedSettings,
	}}, nil
}
