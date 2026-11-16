// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const coworkDriftDetail = "Cowork VM sensor host delivery is not ready (arguments_not_ready, machine_settings_not_ready)"

// stubCoworkEnsureRepair lets a scripted ensure reach its repair: the
// rule-pack preflight passes and no transaction is pending.
func stubCoworkEnsureRepair(t *testing.T, cursorPending bool) {
	t.Helper()
	originalPending, originalElevated := windowsEnterpriseCursorMigrationRepairPending, windowsEnterpriseIsElevated
	originalBuild, originalTransaction := windowsEnterpriseStandaloneRulePackBuild, windowsEnterpriseStandaloneTransactionPending
	t.Cleanup(func() {
		windowsEnterpriseCursorMigrationRepairPending, windowsEnterpriseIsElevated = originalPending, originalElevated
		windowsEnterpriseStandaloneRulePackBuild, windowsEnterpriseStandaloneTransactionPending = originalBuild, originalTransaction
	})
	stubWindowsEnterpriseRulePackPreflight(t, func(string, string, string) error { return nil })
	windowsEnterpriseStandaloneRulePackBuild = func(*config.Config) error { return nil }
	windowsEnterpriseStandaloneTransactionPending = func() bool { return false }
	windowsEnterpriseIsElevated = func() bool { return true }
	windowsEnterpriseCursorMigrationRepairPending = func() (bool, error) { return cursorPending, nil }
}

func coworkEnsureCalls(stub *ensureStub) []string {
	var calls []string
	for _, call := range stub.calls {
		calls = append(calls, call[1])
	}
	return calls
}

func coworkEnsureRepairWarning(result enterprisestatus.Result) string {
	for _, warning := range result.Warnings {
		if warning.Code == "ensure_repair" {
			return warning.Message
		}
	}
	return ""
}

// PowerShell verify does not check the Cowork VM host delivery, so a
// compliant ensure asks the Go host check: drift it can fix is repaired as
// drift:cowork_vm_sensor (a), no drift stays noop (b), and a recorded
// Cursor correction wins without asking (d).
func TestWindowsCompliantEnsureRepairsCoworkDrift(t *testing.T) {
	for _, tc := range []struct {
		name          string
		cursorPending bool
		drift         bool
		calls         []string
		noop          bool
		reason        string
	}{
		{name: "a drift repairs", drift: true, calls: []string{"Status", "Verify", "Repair"}, reason: "drift:cowork_vm_sensor: " + coworkDriftDetail},
		{name: "b no drift is noop", calls: []string{"Status", "Verify"}, noop: true},
		{name: "d recorded Cursor repair wins", cursorPending: true, drift: true, calls: []string{"Status", "Verify", "Repair"}, reason: "recorded_cursor_fail_mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubCoworkEnsureRepair(t, tc.cursorPending)
			replies := make([]map[string]any, 0, len(tc.calls))
			for _, action := range tc.calls {
				replies = append(replies, installedStatus(strings.ToLower(action)))
			}
			stub := &ensureStub{t: t, replies: replies}
			stub.install(t)
			asked := 0
			windowsEnterpriseCoworkEnsureDrift = func() (string, string) {
				asked++
				if tc.cursorPending {
					t.Fatal("a pending Cursor repair asked for Cowork drift")
				}
				if tc.drift {
					return "drift:cowork_vm_sensor", coworkDriftDetail
				}
				return "", ""
			}
			var stdout bytes.Buffer
			command := &cobra.Command{}
			command.SetOut(&stdout)
			command.SetErr(&bytes.Buffer{})
			opts := ensureTestOptions()
			opts.configPath, opts.manifestPath = "", ""
			if err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\stage\install-enterprise.ps1`); err != nil {
				t.Fatalf("ensure: %v\n%s", err, stdout.String())
			}
			if calls := coworkEnsureCalls(stub); !reflect.DeepEqual(calls, tc.calls) {
				t.Fatalf("installer calls %v, want %v", calls, tc.calls)
			}
			if want := map[bool]int{true: 0, false: 1}[tc.cursorPending]; asked != want {
				t.Fatalf("Cowork drift asked %d times, want %d", asked, want)
			}
			var result enterprisestatus.Result
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || !result.OK || result.Noop != tc.noop {
				t.Fatalf("ensure result %+v (%v)", result, err)
			}
			if tc.noop {
				if result.NoopReason != "compliant" {
					t.Fatalf("noop reason %q", result.NoopReason)
				}
				return
			}
			if got := coworkEnsureRepairWarning(result); got != "ensure ran repair: "+tc.reason {
				t.Fatalf("ensure_repair warning %q, want reason %q", got, tc.reason)
			}
		})
	}
}

// (c) A repeat of the confirmed bundle over Cowork drift repairs it too,
// instead of returning already_applied.
func TestWindowsConfirmedBundleEnsureRepairsCoworkDrift(t *testing.T) {
	const current = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n"
	host, opts := newHotConfigHost(t, current, current)
	installedRoot := filepath.Join(t.TempDir(), "installed")
	installedScript := filepath.Join(installedRoot, "libexec", "install-enterprise.ps1")
	opts.bundle = &windowsBundleRun{
		layout:   managed.StandaloneLayout{InstallRoot: installedRoot, ConfigPath: host.configPath},
		driver:   &enterprisebundle.Driver{Store: enterprisebundle.NewStore(t.TempDir(), t.TempDir())},
		prepared: &enterprisebundle.Prepared{AlreadyApplied: true, ConfigSHA256: configwrite.SHA256Hex([]byte(current))},
		unlock:   func() {},
	}
	previousFinder := windowsEnterpriseScriptFinder
	windowsEnterpriseScriptFinder = func(string) (string, error) { return installedScript, nil }
	t.Cleanup(func() { windowsEnterpriseScriptFinder = previousFinder })
	stubCoworkEnsureRepair(t, false)
	stub := &ensureStub{t: t, replies: []map[string]any{installedStatus("status"), installedStatus("Verify"), installedStatus("repair")}}
	stub.install(t)
	windowsEnterprisePolicyDigest = host.digest
	windowsEnterpriseCoworkEnsureDrift = func() (string, string) { return "drift:cowork_vm_sensor", coworkDriftDetail }
	var stdout bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	_ = runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\stage\install-enterprise.ps1`)
	if calls := coworkEnsureCalls(stub); !reflect.DeepEqual(calls, []string{"Status", "Verify", "Repair"}) {
		t.Fatalf("installer calls %v, want Status, Verify and Repair\n%s", calls, stdout.String())
	}
	var result enterprisestatus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.NoopReason == "already_applied" || !strings.HasPrefix(coworkEnsureRepairWarning(result), "ensure ran repair: drift:cowork_vm_sensor: "+coworkDriftDetail) {
		t.Fatalf("confirmed bundle over Cowork drift: %+v", result)
	}
}
