//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedPreferencesFixture points the managed-preferences reader at a temp
// root, makes the converter pass JSON through, names the per-user layer and
// captures resilience markers.
type managedPreferencesFixture struct {
	root    string
	mu      sync.Mutex
	markers []string
}

func newManagedPreferencesFixture(t *testing.T, userName string) *managedPreferencesFixture {
	t.Helper()
	f := &managedPreferencesFixture{root: t.TempDir()}
	previousRoot, previousConvert, previousUser := managedPreferencesRoot, managedPreferencesConverter, managedPreferencesUser
	previousSink := managed.ReportResilienceEvent
	managedPreferencesRoot = f.root
	managedPreferencesConverter = func(plist []byte) ([]byte, error) { return plist, nil }
	managedPreferencesUser = func() string { return userName }
	managed.ReportResilienceEvent = func(marker string, fields map[string]string) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.markers = append(f.markers, managed.FormatResilienceEvent(marker, fields))
	}
	agentPolicyStreaks.Lock()
	agentPolicyStreaks.last = map[string]time.Time{}
	agentPolicyStreaks.Unlock()
	t.Cleanup(func() {
		managedPreferencesRoot, managedPreferencesConverter, managedPreferencesUser = previousRoot, previousConvert, previousUser
		managed.ReportResilienceEvent = previousSink
	})
	return f
}

func (f *managedPreferencesFixture) write(t *testing.T, rel, body string) string {
	t.Helper()
	path := filepath.Join(f.root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func (f *managedPreferencesFixture) lines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.markers...)
}

func TestLoadClaudeCodeDarwinManagedPreferencesDeviceAndUser(t *testing.T) {
	f := newManagedPreferencesFixture(t, "alice")
	f.write(t, "com.anthropic.claudecode.plist", `{"allowManagedHooksOnly":false,"env":{"A":"1"}}`)
	f.write(t, "alice/com.anthropic.claudecode.plist", `{"allowManagedHooksOnly":true}`)
	sources, err := loadClaudeCodeOSManagedSettings()
	if err != nil {
		t.Fatal(err)
	}
	admin := sources.admin
	if admin == nil || sources.userFallback != nil {
		t.Fatalf("sources = %#v", sources)
	}
	if admin.settings["allowManagedHooksOnly"] != true || admin.settings["env"] == nil {
		t.Fatalf("merged settings = %#v", admin.settings)
	}
	if admin.sourceKind("allowManagedHooksOnly") != "mdm-user" || admin.sourceKind("env") != "mdm-device" {
		t.Fatalf("origins = %#v", admin.origins)
	}
	// The block is reported with its exact source and key.
	if err := validateClaudeCodeManagedHookControls(admin, false); err == nil {
		t.Fatal("allowManagedHooksOnly from MDM was not refused")
	}
	got := strings.Join(f.lines(), "\n")
	for _, want := range []string{
		`defenseclaw_prereq check="agent_policy_blocks_user_hooks" connector="claudecode"`,
		`key="allowManagedHooksOnly"`,
		`source="mdm-user"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	// Once per streak.
	_ = validateClaudeCodeManagedHookControls(admin, false)
	if len(f.lines()) != 1 {
		t.Fatalf("prereq repeated in one streak: %v", f.lines())
	}
}

func TestLoadClaudeCodeDarwinManagedPreferencesMissingIsAbsent(t *testing.T) {
	newManagedPreferencesFixture(t, "alice")
	sources, err := loadClaudeCodeOSManagedSettings()
	if err != nil || sources.admin != nil || sources.userFallback != nil {
		t.Fatalf("missing managed preferences = (%#v, %v)", sources, err)
	}
}

func TestGAP0326ManagedPreferenceConversionReusesUnchangedContent(t *testing.T) {
	f := newManagedPreferencesFixture(t, "alice")
	path := f.write(t, "com.anthropic.claudecode.plist", `{"allowManagedHooksOnly":true}`)
	conversions := 0
	managedPreferencesConverter = func(plist []byte) ([]byte, error) {
		conversions++
		return plist, nil
	}
	for range 2 {
		sources, err := claudeCodeOSManagedSettingsLoader()
		if err != nil || sources.admin == nil || sources.admin.settings["allowManagedHooksOnly"] != true {
			t.Fatalf("unchanged policy = (%#v, %v)", sources, err)
		}
	}
	if conversions != 1 {
		t.Fatalf("unchanged policy conversions = %d, want 1", conversions)
	}
	if err := os.WriteFile(path, []byte(`{"allowManagedHooksOnly":false}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sources, err := claudeCodeOSManagedSettingsLoader()
	if err != nil || sources.admin == nil || sources.admin.settings["allowManagedHooksOnly"] != false || conversions != 2 {
		t.Fatalf("changed policy = (%#v, %v), conversions = %d", sources, err, conversions)
	}
}

func TestGAP0326FailedManagedPreferenceConversionRetries(t *testing.T) {
	f := newManagedPreferencesFixture(t, "alice")
	f.write(t, "com.anthropic.claudecode.plist", `{"allowManagedHooksOnly":true}`)
	conversions := 0
	managedPreferencesConverter = func(plist []byte) ([]byte, error) {
		conversions++
		if conversions == 1 {
			return nil, errors.New("conversion unavailable")
		}
		return plist, nil
	}
	first, err := claudeCodeOSManagedSettingsLoader()
	if err != nil || first.admin != nil {
		t.Fatalf("first policy = (%#v, %v)", first, err)
	}
	second, err := claudeCodeOSManagedSettingsLoader()
	if err != nil || second.admin == nil || second.admin.settings["allowManagedHooksOnly"] != true || conversions != 2 {
		t.Fatalf("retried policy = (%#v, %v), conversions = %d", second, err, conversions)
	}
}

func TestLoadClaudeCodeDarwinManagedPreferencesReadFailureNeverFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 0 file")
	}
	f := newManagedPreferencesFixture(t, "alice")
	f.write(t, "com.anthropic.claudecode.plist", `not json`)
	unreadable := f.write(t, "alice/com.anthropic.claudecode.plist", `{"disableAllHooks":true}`)
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o644) })
	sources, err := loadClaudeCodeOSManagedSettings()
	if err != nil {
		t.Fatalf("a failed policy read failed the reconcile: %v", err)
	}
	if sources.admin != nil {
		t.Fatalf("unreadable layers produced policy: %#v", sources.admin)
	}
	lines := f.lines()
	if len(lines) != 2 {
		t.Fatalf("want one skip per unreadable layer, got %v", lines)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "defenseclaw_skip ") || !strings.Contains(line, "policy_read_failed") {
			t.Fatalf("unexpected line %s", line)
		}
	}
	// Once per streak.
	if _, err := loadClaudeCodeOSManagedSettings(); err != nil || len(f.lines()) != 2 {
		t.Fatalf("second read: err=%v lines=%v", err, f.lines())
	}
}

func TestLoadClaudeCodeDarwinManagedPreferencesAsRootReadsDeviceOnly(t *testing.T) {
	f := newManagedPreferencesFixture(t, "")
	f.write(t, "alice/com.anthropic.claudecode.plist", `{"allowManagedHooksOnly":true}`)
	sources, err := loadClaudeCodeOSManagedSettings()
	if err != nil || sources.admin != nil {
		t.Fatalf("per-user layer read without a target user: (%#v, %v)", sources.admin, err)
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
