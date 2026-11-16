// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// gap1027Host points the rejected-config seams at a temp deployment: an
// install state folder with deployment.json, an installed config.yaml at
// baseline bytes, and the supplied config at requested bytes.
func gap1027Host(t *testing.T) (installed, supplied, record string) {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "install")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	deployment := filepath.Join(state, "deployment.json")
	installed = filepath.Join(root, "config.yaml")
	supplied = filepath.Join(root, "requested.yaml")
	for path, body := range map[string]string{deployment: "{}\n", installed: "baseline: true\n", supplied: "routing: on\n"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	elevated, dir, write, layout, logDir, now := windowsEnterpriseIsElevated, windowsEnterpriseConfigRejectedDir,
		writeWindowsEnterpriseConfigRejectedFile, windowsEnterpriseHotConfigLayout, windowsEnterpriseLogDirectory, windowsEnterpriseNow
	t.Cleanup(func() {
		windowsEnterpriseIsElevated, windowsEnterpriseConfigRejectedDir = elevated, dir
		writeWindowsEnterpriseConfigRejectedFile, windowsEnterpriseHotConfigLayout = write, layout
		windowsEnterpriseLogDirectory, windowsEnterpriseNow = logDir, now
	})
	windowsEnterpriseIsElevated = func() bool { return true }
	windowsEnterpriseConfigRejectedDir = func() (string, string) { return state, deployment }
	writeWindowsEnterpriseConfigRejectedFile = func(path string, data []byte, _ string) error { return os.WriteFile(path, data, 0o600) }
	windowsEnterpriseHotConfigLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{ConfigPath: installed}, nil
	}
	windowsEnterpriseLogDirectory = func() (string, error) { return filepath.Join(root, "Logs"), nil }
	windowsEnterpriseNow = func() time.Time { return time.Date(2026, 11, 16, 8, 57, 48, 0, time.UTC) }
	return installed, supplied, filepath.Join(state, enterprisestatus.ConfigRejectedFileName)
}

func gap1027EnsureResult(failed bool) *enterprisestatus.Result {
	r := enterprisestatus.New("ensure", "standalone", "windows", "1.0.10")
	r.Installed = true
	if failed {
		r.AddError("lifecycle_error", `protected target coverage is not verified: codex@HOST\dcw-std2 (S-1-5-21-9-9-9-1018): enterprise hooks: route_config_drift: codex route-only is expected for this account but not rendered`)
	}
	r.Finish("windows", 0)
	return r
}

func gap1027ReadStatus(action string) *enterprisestatus.Result {
	r := enterprisestatus.New(action, "standalone", "windows", "1.0.10")
	r.Installed = true
	r.ResetCompleteness()
	applyWindowsEnterpriseConfigRejected(r)
	r.Finish("windows", 0)
	return r
}

func TestGAP1027WindowsRolledBackEnsureMakesStatusAndVerifyTellTheTruth(t *testing.T) {
	_, supplied, record := gap1027Host(t)
	opts := &windowsEnterpriseLifecycleOptions{configPath: supplied}
	noteWindowsEnterpriseConfigRequest("ensure", opts)
	if opts.configRequestedSHA256 == "" || opts.configInstalledSHA256AtStart == "" || opts.configRequestedSHA256 == opts.configInstalledSHA256AtStart {
		t.Fatalf("noted %+v", opts)
	}
	// The transaction rolled back: config.yaml is the baseline again.
	recordWindowsEnterpriseConfigOutcome(gap1027EnsureResult(true), opts)
	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("no record after the failed ensure: %v", err)
	}
	for _, leak := range []string{"dcw-std2", "S-1-5-21", "HOST"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("record carries %q: %s", leak, raw)
		}
	}

	status := gap1027ReadStatus("status")
	if !status.OK || status.ExitCode != 0 || status.CoverageComplete || status.SecurityComplete {
		t.Fatalf("status ok %v exit %d coverage %v security %v", status.OK, status.ExitCode, status.CoverageComplete, status.SecurityComplete)
	}
	found := false
	for _, w := range status.Warnings {
		if w.Code == enterprisestatus.CodeConfigRejected {
			found = true
			for _, want := range []string{"cause route_config_drift", "/ensure", "CONFIG=<approved absolute config path>", "enterprise-lifecycle.log"} {
				if !strings.Contains(w.Message, want) {
					t.Errorf("warning lacks %q: %s", want, w.Message)
				}
			}
		}
	}
	if !found {
		t.Fatalf("status has no config_rejected warning: %+v", status.Warnings)
	}
	verify := gap1027ReadStatus("verify")
	if verify.OK || verify.ExitCode != enterprisestatus.WindowsExitFailure || len(verify.Errors) != 1 || verify.Errors[0].Code != enterprisestatus.CodeConfigRejected {
		t.Fatalf("verify ok %v exit %d errors %+v", verify.OK, verify.ExitCode, verify.Errors)
	}

	// A standard account reads nothing (it is refused before this runs).
	windowsEnterpriseIsElevated = func() bool { return false }
	if r := gap1027ReadStatus("verify"); !r.OK {
		t.Fatalf("unelevated read reported the record: %+v", r.Errors)
	}
	windowsEnterpriseIsElevated = func() bool { return true }

	// The corrected request applies: the record goes.
	next := &windowsEnterpriseLifecycleOptions{configPath: supplied}
	noteWindowsEnterpriseConfigRequest("ensure", next)
	recordWindowsEnterpriseConfigOutcome(gap1027EnsureResult(false), next)
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatalf("record kept after a successful ensure: %v", err)
	}
	if r := gap1027ReadStatus("verify"); !r.OK {
		t.Fatalf("verify after the successful ensure: %+v", r.Errors)
	}
}

func TestGAP1027WindowsRecordOnlyForARolledBackConfig(t *testing.T) {
	installed, supplied, record := gap1027Host(t)
	// Failed after it applied the config: config.yaml changed, no record.
	opts := &windowsEnterpriseLifecycleOptions{configPath: supplied}
	noteWindowsEnterpriseConfigRequest("ensure", opts)
	if err := os.WriteFile(installed, []byte("routing: on # migrated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recordWindowsEnterpriseConfigOutcome(gap1027EnsureResult(true), opts)
	if _, err := os.Stat(record); !os.IsNotExist(err) {
		t.Fatalf("recorded a config the run applied: %v", err)
	}
	// No config supplied, and a status run: nothing noted, nothing recorded.
	for _, tc := range []struct {
		action string
		opts   *windowsEnterpriseLifecycleOptions
	}{{"ensure", &windowsEnterpriseLifecycleOptions{}}, {"status", &windowsEnterpriseLifecycleOptions{configPath: supplied}}} {
		noteWindowsEnterpriseConfigRequest(tc.action, tc.opts)
		result := gap1027EnsureResult(true)
		result.Action = tc.action
		recordWindowsEnterpriseConfigOutcome(result, tc.opts)
		if _, err := os.Stat(record); !os.IsNotExist(err) {
			t.Fatalf("%s recorded: %v", tc.action, err)
		}
	}
	// A record whose config.yaml changed since is stale.
	if err := os.WriteFile(installed, []byte("baseline: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	failed := &windowsEnterpriseLifecycleOptions{configPath: supplied}
	noteWindowsEnterpriseConfigRequest("ensure", failed)
	recordWindowsEnterpriseConfigOutcome(gap1027EnsureResult(true), failed)
	if _, err := os.Stat(record); err != nil {
		t.Fatalf("no record: %v", err)
	}
	if err := os.WriteFile(installed, []byte("edited: elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := gap1027ReadStatus("verify"); !r.OK {
		t.Fatalf("stale record reported: %+v", r.Errors)
	}
}
