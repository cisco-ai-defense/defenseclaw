// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// hotConfigHost stages an installed config and a supplied one, and stubs what
// a config-only ensure touches outside them.
type hotConfigHost struct {
	configPath string
	writes     []string
	adopted    bool
}

// digest is what the installed CLI's policy digest prints: the policy the
// installed config computes to, and the one the gateway reports.
func (host *hotConfigHost) digest(context.Context) ([]byte, error) {
	reported := "sha256:" + strings.Repeat("a", 64)
	if host.adopted {
		reported = "sha256:" + strings.Repeat("b", 64)
	}
	return []byte(`{"effective_digest":"sha256:` + strings.Repeat("b", 64) + `","config_generation":2,"config_generation_recorded":true,"gateway_reported_digest":"` + reported + `"}`), nil
}

func newHotConfigHost(t *testing.T, previous, next string) (*hotConfigHost, *windowsEnterpriseLifecycleOptions) {
	t.Helper()
	dir := t.TempDir()
	host := &hotConfigHost{configPath: filepath.Join(dir, "etc", "config.yaml")}
	supplied := filepath.Join(dir, "supplied.yaml")
	for path, body := range map[string]string{host.configPath: previous, supplied: next} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	elevatedSeam := windowsEnterpriseIsElevated
	windowsEnterpriseIsElevated = func() bool { return true }
	layoutSeam, lockSeam := windowsEnterpriseHotConfigLayout, windowsEnterpriseHotConfigLock
	validateSeam, writeSeam := windowsEnterpriseHotConfigValidate, windowsEnterpriseHotConfigWrite
	timeoutSeam, pollSeam := windowsEnterpriseHotConfigTimeout, windowsEnterpriseHotConfigPoll
	sourceSeam := windowsEnterpriseHotConfigSourceCheck
	t.Cleanup(func() {
		windowsEnterpriseIsElevated = elevatedSeam
		windowsEnterpriseHotConfigLayout, windowsEnterpriseHotConfigLock = layoutSeam, lockSeam
		windowsEnterpriseHotConfigValidate, windowsEnterpriseHotConfigWrite = validateSeam, writeSeam
		windowsEnterpriseHotConfigTimeout, windowsEnterpriseHotConfigPoll = timeoutSeam, pollSeam
		windowsEnterpriseHotConfigSourceCheck = sourceSeam
	})
	// The supplied file stands for an administrator-only staged config.
	windowsEnterpriseHotConfigSourceCheck = func(string) error { return nil }
	windowsEnterpriseHotConfigLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{ConfigPath: host.configPath, ConfigDir: filepath.Dir(host.configPath), DataDir: dir, ServiceUser: `NT SERVICE\DefenseClawGateway`}, nil
	}
	windowsEnterpriseHotConfigLock = func(string) (func(), error) { return func() {}, nil }
	windowsEnterpriseHotConfigValidate = func(string, string, string, bool) (windowsServiceConfigValidation, error) {
		return windowsServiceConfigValidation{}, nil
	}
	windowsEnterpriseHotConfigWrite = func(_ context.Context, path string, raw []byte, reason string) error {
		host.writes = append(host.writes, reason)
		// The writer records a generation with every write.
		if err := os.WriteFile(configwrite.GenerationPath(path), []byte(`{"generation":`+strconv.Itoa(len(host.writes)+10)+`}`), 0o600); err != nil {
			return err
		}
		return os.WriteFile(path, raw, 0o600)
	}
	windowsEnterpriseHotConfigTimeout, windowsEnterpriseHotConfigPoll = 50*time.Millisecond, 5*time.Millisecond
	opts := ensureTestOptions()
	opts.configPath, opts.manifestPath, opts.noStart = supplied, "", false
	return host, opts
}

func runHotConfigEnsure(t *testing.T, host *hotConfigHost, opts *windowsEnterpriseLifecycleOptions, stub *ensureStub) *enterprisestatus.Result {
	t.Helper()
	stub.install(t)
	windowsEnterprisePolicyDigest = host.digest
	windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "config", nil }
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	if err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\stage\install-enterprise.ps1`); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	var result enterprisestatus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return &result
}

// GAP-0135: a change the running gateway applies as a generation swap no
// longer runs the upgrade transaction (130 seconds with the gateway down).
// One the gateway cannot take, or does not adopt, still does, with the
// previous config back in place first.
func TestWindowsEnterpriseEnsureAppliesAConfigOnlyChangeInTheRunningGateway(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  mode: observe\n"
	const next = "config_version: 9\nguardrail:\n  mode: action\n"

	host, opts := newHotConfigHost(t, previous, next)
	host.adopted = true
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Verify")}}
	result := runHotConfigEnsure(t, host, opts, stub)
	if len(stub.calls) != 2 || stub.calls[1][1] != "Verify" || len(host.writes) != 1 {
		t.Fatalf("installer runs %q, writes %q: want status and verify only, one write", stub.calls, host.writes)
	}
	if got, _ := os.ReadFile(host.configPath); string(got) != next {
		t.Fatalf("config.yaml = %q, want the supplied config", got)
	}
	if !result.OK || result.Policy == nil || !result.Policy.Applied || !strings.Contains(strings.Join(result.Changes, "\n"), "it was not restarted") {
		t.Fatalf("result = %+v", result)
	}

	// GAP-0312: a supplied config a standard user can write is not
	// installed by the hot path; the transaction gets it and refuses it.
	host, opts = newHotConfigHost(t, previous, next)
	host.adopted = true
	windowsEnterpriseHotConfigSourceCheck = func(string) error { return errors.New("writable by BUILTIN\\Users") }
	stub = &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Upgrade")}}
	runHotConfigEnsure(t, host, opts, stub)
	if len(stub.calls) != 2 || stub.calls[1][1] != "Upgrade" || len(host.writes) != 0 {
		t.Fatalf("untrusted source: installer runs %q, writes %q", stub.calls, host.writes)
	}

	// A key the gateway reads once at start goes through the upgrade.
	host, opts = newHotConfigHost(t, previous, strings.Replace(previous, "mode: observe", "mode: observe\ngateway:\n  api_port: 18971", 1))
	host.adopted = true
	stub = &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Upgrade")}}
	runHotConfigEnsure(t, host, opts, stub)
	if len(stub.calls) != 2 || stub.calls[1][1] != "Upgrade" || len(host.writes) != 0 {
		t.Fatalf("restart-required change: installer runs %q, writes %q", stub.calls, host.writes)
	}

	// A gateway that does not adopt the change gets the old config back and
	// the upgrade. The apply and the restore each record a generation, so the
	// counter moves past the recorded 3 and never reuses a number.
	host, opts = newHotConfigHost(t, previous, next)
	recorded := `{"generation":3,"config_sha256":"` + configwrite.SHA256Hex([]byte(previous)) + `"}`
	if err := os.WriteFile(configwrite.GenerationPath(host.configPath), []byte(recorded), 0o600); err != nil {
		t.Fatal(err)
	}
	stub = &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Upgrade")}}
	runHotConfigEnsure(t, host, opts, stub)
	got, _ := os.ReadFile(host.configPath)
	generation, _ := os.ReadFile(configwrite.GenerationPath(host.configPath))
	if string(got) != previous || string(generation) == recorded || len(host.writes) != 2 ||
		len(stub.calls) != 2 || stub.calls[1][1] != "Upgrade" {
		t.Fatalf("gateway never adopted: config %q, generation %q, writes %q, installer runs %q", got, generation, host.writes, stub.calls)
	}
}

// GAP-0646: a byte-only edit still goes through the running gateway path.
func TestWindowsEnterpriseEnsureAppliesFormattingOnlyConfigWithoutRestart(t *testing.T) {
	const previous = "config_version: 9\nguardrail:\n  mode: observe\n"
	const next = "config_version: 9\r\nguardrail:\r\n  mode: observe # reviewed\r\n"
	host, opts := newHotConfigHost(t, previous, next)
	host.adopted = true
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Verify")}}
	result := runHotConfigEnsure(t, host, opts, stub)
	if len(stub.calls) != 2 || stub.calls[1][1] != "Verify" || len(host.writes) != 1 {
		t.Fatalf("installer runs %q, writes %q: want status and verify only, one write", stub.calls, host.writes)
	}
	if got, _ := os.ReadFile(host.configPath); string(got) != next {
		t.Fatalf("config.yaml = %q, want supplied bytes", got)
	}
	if !result.OK || result.Policy == nil || !result.Policy.Applied {
		t.Fatalf("result = %+v", result)
	}
}

// GAP-0145: the config.yaml an ensure replaces after a hand edit is kept as
// rejected-config.yaml beside it.
func TestWindowsEnterpriseEnsureKeepsAHandEditedConfig(t *testing.T) {
	host, _ := newHotConfigHost(t, "config_version: 9\nguardrail:\n  mode: observe\n", "config_version: 9\n")
	if kept := keepInstalledWindowsEnterpriseEditedConfig(); kept != "" {
		t.Fatalf("a config with no recorded generation was kept: %s", kept)
	}
	recorded := configwrite.GenerationPath(host.configPath)
	if err := os.WriteFile(recorded, []byte(`{"generation":3,"config_sha256":"`+strings.Repeat("0", 64)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	kept := keepInstalledWindowsEnterpriseEditedConfig()
	if want := filepath.Join(filepath.Dir(host.configPath), "rejected-config.yaml"); kept != want {
		t.Fatalf("kept = %q, want %q", kept, want)
	}
	if got, _ := os.ReadFile(kept); !strings.Contains(string(got), "mode: observe") {
		t.Fatalf("rejected-config.yaml = %q", got)
	}
}

// GAP-0180: the policy digest call carries the service pins whichever console
// runs it. An administrator or SYSTEM console carries none of them and the
// managed-host guard refused the call there, so status, verify and every
// ensure but the hot config path left policy out of the result.
func TestWindowsEnterprisePolicyDigestRunsUnderTheServicePins(t *testing.T) {
	host, _ := newHotConfigHost(t, "config_version: 9\n", "config_version: 9\n")
	t.Setenv(managed.ConfigPathEnv, "C:\\console\\other.yaml")
	t.Setenv(managed.DeploymentModeEnv, "")

	command, err := windowsEnterprisePolicyDigestCommand(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, entry := range command.Env {
		name, value, _ := strings.Cut(entry, "=")
		got[strings.ToUpper(name)] = append(got[strings.ToUpper(name)], value)
	}
	layout, _ := windowsEnterpriseHotConfigLayout()
	for name, want := range windowsEnterpriseServicePins(layout) {
		if values := got[strings.ToUpper(name)]; len(values) != 1 || values[0] != want {
			t.Fatalf("%s = %q, want exactly %q", name, values, want)
		}
	}
	if got[managed.ConfigPathEnv][0] != host.configPath || len(got["PATH"]) != 1 {
		t.Fatalf("config %q, PATH %q: want the installed config and the console PATH kept", got[managed.ConfigPathEnv], got["PATH"])
	}
}
