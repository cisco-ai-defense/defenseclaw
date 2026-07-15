//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func stubClaudeManagedPreferencesCommands(
	t *testing.T,
	export func() ([]byte, error),
	convert func([]byte) ([]byte, error),
	forced func(string) (bool, error),
) {
	t.Helper()
	previousExport := claudeCodeManagedPreferencesExporter
	previousConvert := claudeCodeManagedPreferencesConverter
	previousForced := claudeCodeManagedPreferenceForced
	claudeCodeManagedPreferencesExporter = export
	claudeCodeManagedPreferencesConverter = convert
	claudeCodeManagedPreferenceForced = forced
	t.Cleanup(func() {
		claudeCodeManagedPreferencesExporter = previousExport
		claudeCodeManagedPreferencesConverter = previousConvert
		claudeCodeManagedPreferenceForced = previousForced
	})
}

func TestLoadClaudeCodeDarwinManagedPreferences(t *testing.T) {
	stubClaudeManagedPreferencesCommands(
		t,
		func() ([]byte, error) { return []byte("plist fixture"), nil },
		func(plist []byte) ([]byte, error) {
			if string(plist) != "plist fixture" {
				t.Fatalf("converter input = %q", plist)
			}
			return []byte(`{"allowManagedHooksOnly":true}`), nil
		},
		func(key string) (bool, error) { return key == "allowManagedHooksOnly", nil },
	)
	sources, err := loadClaudeCodeOSManagedSettings()
	if err != nil {
		t.Fatal(err)
	}
	if sources.admin == nil || sources.userFallback != nil || sources.admin.settings["allowManagedHooksOnly"] != true {
		t.Fatalf("managed preferences sources = %#v", sources)
	}
}

func TestLoadClaudeCodeDarwinUserDefaultsAreNotAdministratorPolicy(t *testing.T) {
	stubClaudeManagedPreferencesCommands(
		t,
		func() ([]byte, error) { return []byte("user plist fixture"), nil },
		func([]byte) ([]byte, error) { return []byte(`{"disableAllHooks":true}`), nil },
		func(string) (bool, error) { return false, nil },
	)
	sources, err := loadClaudeCodeOSManagedSettings()
	if err != nil || sources.admin != nil || sources.userFallback != nil {
		t.Fatalf("ordinary user defaults classified as managed = (%#v, %v)", sources, err)
	}
}

func TestLoadClaudeCodeDarwinManagedPreferencesMissingDomainFallsThrough(t *testing.T) {
	stubClaudeManagedPreferencesCommands(
		t,
		func() ([]byte, error) { return nil, errors.New("Domain com.anthropic.claudecode does not exist") },
		func([]byte) ([]byte, error) { return nil, errors.New("converter must not run") },
		func(string) (bool, error) { return false, errors.New("forced checker must not run") },
	)
	sources, err := loadClaudeCodeOSManagedSettings()
	if err != nil || sources.admin != nil || sources.userFallback != nil {
		t.Fatalf("missing managed preferences = (%#v, %v)", sources, err)
	}
}

func TestLoadClaudeCodeDarwinManagedPreferencesFailsClosed(t *testing.T) {
	stubClaudeManagedPreferencesCommands(
		t,
		func() ([]byte, error) { return nil, errors.New("defaults unavailable") },
		func([]byte) ([]byte, error) { return nil, nil },
		func(string) (bool, error) { return false, nil },
	)
	if _, err := loadClaudeCodeOSManagedSettings(); err == nil || !strings.Contains(err.Error(), "defaults unavailable") {
		t.Fatalf("inspection error = %v", err)
	}
}

func TestClaudeCodeDarwinManagedPreferenceCommandIsBounded(t *testing.T) {
	if _, err := runClaudeCodeManagedPreferenceCommandWithLimits(
		"/bin/sh",
		[]string{"-c", "sleep 1"},
		nil,
		20*time.Millisecond,
		1024,
	); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout error = %v", err)
	}

	if _, err := runClaudeCodeManagedPreferenceCommandWithLimits(
		"/usr/bin/printf",
		[]string{"%s", "output-over-limit"},
		nil,
		time.Second,
		8,
	); err == nil || !strings.Contains(err.Error(), "exceeds 8 bytes") {
		t.Fatalf("output-limit error = %v", err)
	}
}
