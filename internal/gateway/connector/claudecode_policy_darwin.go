//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const claudeCodeManagedPreferencesDomain = "com.anthropic.claudecode"

const (
	claudeCodeManagedPreferenceCommandTimeout    = 5 * time.Second
	claudeCodeManagedPreferenceDiagnosticLimit   = 64 << 10
	claudeCodeManagedPreferenceScalarOutputLimit = 64 << 10
)

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
		return runClaudeCodeManagedPreferenceCommandWithLimits(
			"/usr/bin/defaults",
			[]string{"export", claudeCodeManagedPreferencesDomain, "-"},
			nil,
			claudeCodeManagedPreferenceCommandTimeout,
			claudeCodeSettingsReadLimit+1,
		)
	}
	claudeCodeManagedPreferencesConverter = func(plist []byte) ([]byte, error) {
		return runClaudeCodeManagedPreferenceCommandWithLimits(
			"/usr/bin/plutil",
			[]string{"-convert", "json", "-o", "-", "--", "-"},
			plist,
			claudeCodeManagedPreferenceCommandTimeout,
			claudeCodeSettingsReadLimit+1,
		)
	}
	claudeCodeManagedPreferenceForced = func(key string) (bool, error) {
		output, err := runClaudeCodeManagedPreferenceCommand(
			"/usr/bin/osascript", "-l", "JavaScript", "-e",
			claudeCodeForcedPreferenceScript, "--", key, claudeCodeManagedPreferencesDomain,
		)
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

type claudeCodeBoundedCommandBuffer struct {
	bytes.Buffer
	limit int64
}

func (b *claudeCodeBoundedCommandBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - int64(b.Len())
	if remaining <= 0 {
		return 0, fmt.Errorf("command output exceeds %d bytes", b.limit)
	}
	if int64(len(p)) > remaining {
		written, _ := b.Buffer.Write(p[:remaining])
		return written, fmt.Errorf("command output exceeds %d bytes", b.limit)
	}
	return b.Buffer.Write(p)
}

func runClaudeCodeManagedPreferenceCommand(executable string, args ...string) ([]byte, error) {
	return runClaudeCodeManagedPreferenceCommandWithLimits(
		executable,
		args,
		nil,
		claudeCodeManagedPreferenceCommandTimeout,
		claudeCodeManagedPreferenceScalarOutputLimit,
	)
}

func runClaudeCodeManagedPreferenceCommandWithLimits(
	executable string,
	args []string,
	stdin []byte,
	timeout time.Duration,
	outputLimit int64,
) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	stdout := &claudeCodeBoundedCommandBuffer{limit: outputLimit}
	stderr := &claudeCodeBoundedCommandBuffer{limit: claudeCodeManagedPreferenceDiagnosticLimit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("command %s timed out after %s", executable, timeout)
	}
	if err != nil {
		if diagnostic := strings.TrimSpace(stderr.String()); diagnostic != "" {
			err = fmt.Errorf("%w: %s", err, diagnostic)
		}
		return nil, err
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

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
