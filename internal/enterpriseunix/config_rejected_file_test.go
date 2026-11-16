// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// rel-1-0-10 GAP-1027 on Linux and macOS: an explicit ensure --config whose
// run failed and rolled back left status and verify at ok and
// coverage_complete, as if the requested config were applied. The rejected
// config is now kept as for an in-place edit, and status warns and verify
// fails with config_rejected until a run applies a --config or config.yaml is
// written again.
func TestGAP1027FailedConfigFileEnsureIsReportedUntilApplied(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			applied := h.read(h.env.Layout.ConfigPath)
			requested := []byte(strings.Replace(string(DefaultConfig(h.env.Layout)), "mode: observe", "mode: action", 1))
			source := writeTempConfig(t, requested)

			h.healthy = false
			failed := h.run(Options{Action: ActionEnsure, ConfigFile: source})
			requireError(t, failed, codeActivate)
			if !hasWarning(failed, codeRolledBack) || failed.ExitCode != enterprisestatus.UnixExitFailure {
				t.Fatalf("ensure did not fail and roll back: exit %d %+v", failed.ExitCode, failed.Warnings)
			}
			if got := h.read(h.env.Layout.ConfigPath); got != applied {
				t.Fatal("config.yaml after the rollback is not the applied config")
			}

			h.healthy = true
			status := h.run(Options{Action: ActionStatus})
			if !hasWarning(status, enterprisestatus.CodeConfigRejected) || status.CoverageComplete || status.SecurityComplete {
				t.Fatalf("status after the rolled-back ensure: ok %v coverage %v security %v warnings %+v",
					status.OK, status.CoverageComplete, status.SecurityComplete, status.Warnings)
			}
			verify := h.run(Options{Action: ActionVerify})
			if verify.OK || verify.ExitCode != enterprisestatus.UnixExitFailure {
				t.Fatalf("verify after the rolled-back ensure: ok %v exit %d", verify.OK, verify.ExitCode)
			}
			found := false
			for _, e := range verify.Errors {
				found = found || strings.Contains(e.Message, "is not applied")
			}
			if !found {
				t.Fatalf("verify errors do not say the config is not applied: %+v", verify.Errors)
			}

			if kept, err := os.ReadFile(h.env.rejectedConfigPath()); err != nil || string(kept) != string(requested) {
				t.Fatalf("rejected-config.yaml = %q (%v), want the requested config", kept, err)
			}

			requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: source}))
			if _, err := os.Stat(h.env.rejectedConfigPath()); !os.IsNotExist(err) {
				t.Fatalf("rejected-config.yaml kept after the config applied: %v", err)
			}
			// The test host's guardian and enumerator scan leave other
			// reasons; config_rejected is no longer one of them.
			after := h.run(Options{Action: ActionStatus})
			for _, w := range after.Warnings {
				if w.Code == enterprisestatus.CodeConfigRejected || strings.Contains(w.Message, enterprisestatus.CodeConfigRejected) {
					t.Fatalf("status after the applied config still reports it: %+v", after.Warnings)
				}
			}
		})
	}
}

// A failed --config run whose config is the applied one keeps no record.
func TestGAP1027FailedConfigFileEnsureOfTheAppliedConfigKeepsNothing(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	source := writeTempConfig(t, []byte(h.read(h.env.Layout.ConfigPath)))
	h.healthy = false
	requireError(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0"), ConfigFile: source}), codeActivate)
	if _, err := os.Stat(h.env.rejectedConfigPath()); !os.IsNotExist(err) {
		t.Fatalf("rejected-config.yaml written for the applied config: %v", err)
	}
}

// A --config the plan refuses changes nothing and is reported too.
func TestGAP1027RefusedConfigFileIsReported(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	applied := h.read(h.env.Layout.ConfigPath)
	source := writeTempConfig(t, []byte("config_version: [not, valid\n"))
	refused := h.run(Options{Action: ActionEnsure, ConfigFile: source})
	if refused.OK {
		t.Fatal("the invalid config was accepted")
	}
	if got := h.read(h.env.Layout.ConfigPath); got != applied {
		t.Fatal("config.yaml changed after a refused --config")
	}
	if status := h.run(Options{Action: ActionStatus}); !hasWarning(status, enterprisestatus.CodeConfigRejected) || status.CoverageComplete {
		t.Fatalf("status after a refused --config: coverage %v warnings %+v", status.CoverageComplete, status.Warnings)
	}
}
