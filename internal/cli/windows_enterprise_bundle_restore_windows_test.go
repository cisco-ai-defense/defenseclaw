// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// GAP-0114: on a bundle-mode device the Windows lifecycle wiring puts the
// confirmed bundle's config back over a config.yaml changed outside the
// lifecycle or deleted (ensure and repair), and every health result fails
// with bundle_not_applied while the gateway does not enforce the bundle
// (verify). These tests drive the real ensure, repair and verify entry
// points against a temporary bundle store, with the installer, the gateway
// and its policy report stubbed.

// windowsBundleRestoreHost is a bundle-mode device with a confirmed bundle.
type windowsBundleRestoreHost struct {
	layout       managed.StandaloneLayout
	bundleID     string
	bundleConfig []byte // config.yaml rendered from the confirmed bundle
	digest       string // the confirmed bundle's effective policy digest
	reloads      int
	locks        int
}

// windowsBundleEditedDigest is the policy the gateway enforces from an edit.
var windowsBundleEditedDigest = "sha256:" + strings.Repeat("e", 64)

// newWindowsBundleRestoreHost confirms a signed bundle the way Setup BUNDLE=
// TRUSTANCHORS= does, then stubs what the lifecycle touches outside the
// temporary layout: the installer, elevation, lifecycle.lock, the running
// gateway and the installed CLI's policy digest, which reports the bundle
// digest while config.yaml is the bundle config and another one otherwise.
func newWindowsBundleRestoreHost(t *testing.T) *windowsBundleRestoreHost {
	return newWindowsBundleRestoreHostForVersion(t, "1.0.2")
}

func newWindowsBundleRestoreHostForVersion(t *testing.T, sourceVersion string) *windowsBundleRestoreHost {
	t.Helper()
	e := newBundleCLIEnv(t)
	appVersion = sourceVersion
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d:\n%s", code, out)
	}
	stubWindowsEnterpriseDeployments(t, nil)
	layout := stubWindowsBundleHost(t)
	// A rollback test must not inspect or retire the machine's installed
	// scanner runtime when its stub installer runs as LocalSystem.
	scannerRuntime := windowsScannerRuntimeDir
	t.Cleanup(func() { windowsScannerRuntimeDir = scannerRuntime })
	noScannerRuntime := filepath.Join(t.TempDir(), "absent-scanner-runtime")
	windowsScannerRuntimeDir = func() (string, error) {
		return noScannerRuntime, nil
	}
	// The fixture has no enrolled agents. A managed test host can have real
	// enrollments that would make this fixture's minimal config invalid.
	connectors, targets := windowsEnterpriseEnrolledConnectors, windowsEnterpriseEnrolledTargets
	t.Cleanup(func() {
		windowsEnterpriseEnrolledConnectors, windowsEnterpriseEnrolledTargets = connectors, targets
	})
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return nil, nil }
	windowsEnterpriseEnrolledTargets = func() (map[string]bool, error) { return map[string]bool{}, nil }
	ctx := context.Background()
	cmd, out := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(ctx, cmd, "ensure", opts); done {
		t.Fatalf("prepare ended the run: %v\n%s", err, out.String())
	}
	cleanupPreparedWindowsBundle(t, opts)
	rendered, err := os.ReadFile(opts.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(layout.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.ConfigPath, rendered, 0o600); err != nil {
		t.Fatal(err)
	}
	recordWindowsBundleTestCommit(t, layout, opts.bundle.prepared.Receipt, rendered)
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	expected := opts.bundle.prepared.Receipt.ExpectedDigest
	result.Policy = &enterprisestatus.PolicyState{EffectiveDigest: expected, GatewayReportedDigest: expected, ConfigGeneration: 3, Applied: true}
	finishWindowsEnterpriseBundle(cmd, opts, result)
	if len(result.Errors) != 0 || result.Bundle == nil || result.Bundle.State != enterprisebundle.StateConfirmed {
		t.Fatalf("bundle not confirmed: errors %+v bundle %+v", result.Errors, result.Bundle)
	}
	driver := newWindowsBundleDriver(layout)
	current, ref, err := driver.CurrentConfig()
	if err != nil || ref == nil || !bytes.Equal(current, rendered) {
		t.Fatalf("confirmed bundle config: ref %+v err %v, equal to the installed config %v", ref, err, bytes.Equal(current, rendered))
	}
	host := &windowsBundleRestoreHost{layout: layout, bundleID: ref.BundleID, bundleConfig: current, digest: ref.EffectivePolicyDigest}

	elevated, hotLayout, lock := windowsEnterpriseIsElevated, windowsEnterpriseHotConfigLayout, windowsEnterpriseHotConfigLock
	running, reload, restart := windowsBundleRestoreGatewayRunning, windowsEnterpriseHotBundleReload, windowsEnterpriseHotConfigRestart
	failClosed := windowsEnterpriseHotConfigFailClosed
	timeout, restartTimeout, poll := windowsEnterpriseHotConfigTimeout, windowsEnterpriseHotConfigRestartTimeout, windowsEnterpriseHotConfigPoll
	t.Cleanup(func() {
		windowsEnterpriseIsElevated, windowsEnterpriseHotConfigLayout, windowsEnterpriseHotConfigLock = elevated, hotLayout, lock
		windowsBundleRestoreGatewayRunning, windowsEnterpriseHotBundleReload, windowsEnterpriseHotConfigRestart = running, reload, restart
		windowsEnterpriseHotConfigFailClosed = failClosed
		windowsEnterpriseHotConfigTimeout, windowsEnterpriseHotConfigRestartTimeout, windowsEnterpriseHotConfigPoll = timeout, restartTimeout, poll
	})
	windowsEnterpriseIsElevated = func() bool { return true }
	windowsEnterpriseHotConfigLayout = func() (managed.StandaloneLayout, error) { return layout, nil }
	windowsEnterpriseHotConfigLock = func(string) (func(), error) { host.locks++; return func() {}, nil }
	windowsBundleRestoreGatewayRunning = func() bool { return false }
	windowsEnterpriseHotConfigFailClosed = func() error {
		t.Error("the restore stopped the gateway")
		return nil
	}
	windowsEnterpriseHotBundleReload = func(context.Context, managed.StandaloneLayout) error { host.reloads++; return nil }
	windowsEnterpriseHotConfigRestart = func() (bool, error) {
		t.Error("the restore restarted a gateway that adopted the re-applied bundle")
		return false, nil
	}
	windowsEnterpriseHotConfigTimeout, windowsEnterpriseHotConfigRestartTimeout, windowsEnterpriseHotConfigPoll = 200*time.Millisecond, 200*time.Millisecond, 5*time.Millisecond
	return host
}

// policyDigest is the installed CLI's `policy digest --check-gateway`: the
// gateway enforces the bundle only while config.yaml is the bundle config.
func (host *windowsBundleRestoreHost) policyDigest(context.Context) ([]byte, error) {
	reported := windowsBundleEditedDigest
	bundleID, bundleVersion := "", "0"
	if installed, err := os.ReadFile(host.layout.ConfigPath); err == nil && bytes.Equal(installed, host.bundleConfig) {
		reported = host.digest
		bundleID, bundleVersion = host.bundleID, "5"
	}
	return []byte(`{"effective_digest":"` + reported + `","config_generation":7,"config_generation_recorded":true,` +
		`"gateway_reported_digest":"` + reported + `","gateway_reported_config_generation":7,` +
		`"gateway_reported_bundle_id":"` + bundleID + `","gateway_reported_bundle_version":` + bundleVersion + `}`), nil
}

// installer stubs the PowerShell lifecycle with replies; it must be called
// after the restore host so the policy digest is this host's.
func (host *windowsBundleRestoreHost) installer(t *testing.T, replies ...map[string]any) *ensureStub {
	t.Helper()
	stub := &ensureStub{t: t, replies: replies}
	stub.install(t)
	windowsEnterprisePolicyDigest = host.policyDigest
	return stub
}

func (host *windowsBundleRestoreHost) rejectedPath() string {
	return filepath.Join(host.layout.ConfigDir, "rejected-config.yaml")
}

// tamper edits config.yaml (or deletes it) and returns what it left there.
func (host *windowsBundleRestoreHost) tamper(t *testing.T, deleted bool) []byte {
	t.Helper()
	if deleted {
		if err := os.Remove(host.layout.ConfigPath); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	edited := append(append([]byte(nil), host.bundleConfig...), []byte("# edited outside the lifecycle\n")...)
	if err := os.WriteFile(host.layout.ConfigPath, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	return edited
}

func windowsBundleLifecycleResult(t *testing.T, stdout *bytes.Buffer) enterprisestatus.Result {
	t.Helper()
	var result enterprisestatus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode %q: %v", stdout.String(), err)
	}
	return result
}

func windowsBundleRestoreOptions() *windowsEnterpriseLifecycleOptions {
	opts := ensureTestOptions()
	opts.configPath, opts.manifestPath, opts.installedBeforeRun = "", "", true
	return opts
}

// A confirmed receipt keeps the digest of the build that applied it. After
// an upgrade, all Windows health actions must check the running gateway
// against this build's verified bundle and the exact installed config.
func TestWindowsBundleHealthAfterProductUpgradeUsesCurrentDigest(t *testing.T) {
	for _, sourceVersion := range []string{"1.0.2", "1.0.3"} {
		t.Run(sourceVersion, func(t *testing.T) {
			host := newWindowsBundleRestoreHostForVersion(t, sourceVersion)
			driver := newWindowsBundleDriver(host.layout)
			state, err := driver.Store.LoadState()
			if err != nil || state.Current == nil {
				t.Fatalf("confirmed state: %+v, %v", state, err)
			}
			const oldDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			if host.digest == oldDigest {
				t.Fatal("the upgraded build did not change the effective digest")
			}
			state.Current.EffectivePolicyDigest = oldDigest
			raw, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(driver.Store.StatePath(), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			appVersion = "1.0.4"
			for _, action := range []string{"status", "verify", "ensure", "repair", "upgrade"} {
				result := newWindowsEnterpriseStandaloneResult(action, windowsBundleRestoreOptions())
				result.Installed = true
				result.Readiness.Gateway = true
				result.Policy = &enterprisestatus.PolicyState{EffectiveDigest: host.digest, GatewayReportedDigest: host.digest, Applied: true}
				addWindowsBundleEnforcementError(result, windowsBundleRestoreOptions(), false)
				if windowsBundleHasCode(result.Errors, bundleNotAppliedCode) {
					t.Fatalf("%s rejected the enforced upgraded bundle: %+v", action, result.Errors)
				}
				result.Policy.GatewayReportedDigest = oldDigest
				addWindowsBundleEnforcementError(result, windowsBundleRestoreOptions(), false)
				if !windowsBundleHasCode(result.Errors, bundleNotAppliedCode) {
					t.Fatalf("%s accepted a gateway reporting the old policy", action)
				}
			}
			changed := append(bytes.Clone(host.bundleConfig), []byte("# changed after confirmation\n")...)
			if err := os.WriteFile(host.layout.ConfigPath, changed, 0o600); err != nil {
				t.Fatal(err)
			}
			result := newWindowsEnterpriseStandaloneResult("verify", windowsBundleRestoreOptions())
			result.Installed = true
			result.Readiness.Gateway = true
			result.Policy = &enterprisestatus.PolicyState{EffectiveDigest: host.digest, GatewayReportedDigest: host.digest, Applied: true}
			addWindowsBundleEnforcementError(result, windowsBundleRestoreOptions(), false)
			if !windowsBundleHasCode(result.Errors, bundleNotAppliedCode) {
				t.Fatal("verify accepted changed installed config despite the gateway digest")
			}
		})
	}
}

// assertWindowsBundleRestored checks config.yaml is the bundle config again,
// recorded by the lifecycle writer under the bundle's identity, and that an
// edited file was kept as rejected-config.yaml (a deleted one leaves none).
func (host *windowsBundleRestoreHost) assertRestored(t *testing.T, result enterprisestatus.Result, edited []byte) {
	t.Helper()
	installed, err := os.ReadFile(host.layout.ConfigPath)
	if err != nil || !bytes.Equal(installed, host.bundleConfig) {
		t.Fatalf("config.yaml is not the bundle config after the run (read %v): %q", err, installed)
	}
	if attribution, ok := observabilityruntime.ReadBundleAttribution(host.layout.ConfigPath); !ok || attribution.ID != host.bundleID || attribution.Version != 5 {
		t.Fatalf("the restored config is not recorded as bundle %s version 5: %+v (ok %v)", host.bundleID, attribution, ok)
	}
	rejected, err := os.ReadFile(host.rejectedPath())
	if edited == nil {
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("a deleted config.yaml left rejected-config.yaml (%v)", err)
		}
	} else if err != nil || !bytes.Equal(rejected, edited) {
		t.Fatalf("rejected-config.yaml does not hold the edited bytes (read %v)", err)
	}
	if !result.OK || result.ExitCode != 0 || len(result.Errors) != 0 {
		t.Fatalf("restoring run failed: ok=%v exit=%d errors=%+v", result.OK, result.ExitCode, result.Errors)
	}
	if !windowsBundleHasCode(result.Warnings, "bundle_config_restored") {
		t.Fatalf("no bundle_config_restored warning: %+v", result.Warnings)
	}
	var change bool
	for _, line := range result.Changes {
		change = change || strings.Contains(line, "re-applied signed policy bundle "+host.bundleID+" version 5 from the bundle store")
	}
	if !change {
		t.Fatalf("the re-apply is not in changes: %q", result.Changes)
	}
}

func TestWindowsBundleEnsureRestoresConfigChangedOutsideTheLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name    string
		deleted bool
		running bool
	}{
		{"edited, gateway stopped", false, false},
		{"edited, gateway running", false, true},
		{"deleted, gateway stopped", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := newWindowsBundleRestoreHost(t)
			windowsBundleRestoreGatewayRunning = func() bool { return tc.running }
			edited := host.tamper(t, tc.deleted)
			stub := host.installer(t, installedStatus("status"), installedStatus("verify"))
			command := &cobra.Command{}
			var stdout bytes.Buffer
			command.SetOut(&stdout)
			command.SetErr(&bytes.Buffer{})
			err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, windowsBundleRestoreOptions(), `C:\stage\install-enterprise.ps1`)
			result := windowsBundleLifecycleResult(t, &stdout)
			if err != nil {
				t.Fatalf("ensure: %v\n%s", err, stdout.String())
			}
			host.assertRestored(t, result, edited)
			// The plan after the restore found nothing to do; the run still
			// repaired the device, so it is not a no-op.
			if result.Noop || result.NoopReason != "" {
				t.Fatalf("a restoring ensure reported a no-op (%q)", result.NoopReason)
			}
			if len(stub.calls) != 2 || host.locks != 1 {
				t.Fatalf("installer runs %q, lifecycle.lock taken %d time(s)", stub.calls, host.locks)
			}
			if wantReloads := map[bool]int{false: 0, true: 1}[tc.running]; host.reloads != wantReloads {
				t.Fatalf("gateway reloads %d, want %d", host.reloads, wantReloads)
			}
		})
	}
}

// A plain ensure settles receipts before restoring the confirmed bundle. A
// candidate whose install was committed must remain installed while the
// gateway is unavailable, so the next ensure can confirm that same receipt.
func TestWindowsBundleRestoreKeepsCommittedPendingCandidate(t *testing.T) {
	const candidateID = "b-01JA00000000000000000000D2"
	for _, state := range []string{enterprisebundle.StateStaged, enterprisebundle.StateApplied} {
		t.Run(state, func(t *testing.T) {
			host := newWindowsBundleRestoreHost(t)
			driver := newWindowsBundleDriver(host.layout)
			candidate := append(append([]byte(nil), host.bundleConfig...), []byte("# signed candidate\n")...)
			rc := windowsKilledApplyReceipt(t, driver, candidateID, 6, candidate, state)
			if state == enterprisebundle.StateStaged {
				recordWindowsBundleTestCommit(t, host.layout, rc, candidate)
			}
			livePolicy := windowsBundlePolicy
			windowsBundlePolicy = func(context.Context) *enterprisebundle.GatewayPolicy { return nil }

			cmd, _ := windowsBundleCommand()
			opts := windowsBundleRestoreOptions()
			if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", opts); done || err != nil {
				t.Fatalf("plain ensure prepare: done=%t err=%v", done, err)
			}
			if got := windowsBundleReceiptState(t, host.layout, rc.ReceiptID); got.State != state {
				t.Fatalf("outage settled candidate to %s, want %s", got.State, state)
			}
			if restore := restoreWindowsBundleConfig(t.Context(), windowsBundleSettleReplacing(opts)); restore.failed() || len(restore.changes) != 0 {
				t.Fatalf("outage restored over pending candidate: %+v", restore)
			}
			if installed, err := os.ReadFile(host.layout.ConfigPath); err != nil || !bytes.Equal(installed, candidate) {
				t.Fatalf("pending candidate no longer installed: %q (%v)", installed, err)
			}
			if _, err := os.Stat(host.rejectedPath()); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("pending candidate was rejected: %v", err)
			}
			result := newWindowsEnterpriseStandaloneResult("ensure", opts)
			finishWindowsEnterpriseBundle(cmd, opts, result)
			if !windowsBundleHasCode(result.Warnings, enterprisebundle.WarnBundlePending) {
				t.Fatalf("plain ensure did not report the pending receipt: %+v", result.Warnings)
			}
			result.Installed = true
			addWindowsBundleEnforcementError(result, opts, false)
			var pendingProblem string
			for _, problem := range result.Errors {
				if problem.Code == bundleNotAppliedCode {
					pendingProblem = problem.Message
				}
			}
			if !strings.Contains(pendingProblem, "receipt remains pending") {
				t.Fatalf("plain ensure did not name the pending candidate: %+v", result.Errors)
			}

			windowsBundlePolicy = livePolicy
			next := windowsBundleRestoreOptions()
			if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", next); done || err != nil {
				t.Fatalf("recovered ensure prepare: done=%t err=%v", done, err)
			}
			confirmed := windowsBundleReceiptState(t, host.layout, rc.ReceiptID)
			current, err := driver.Store.LoadState()
			if err != nil || confirmed.State != enterprisebundle.StateConfirmed || current.Current == nil || current.Current.BundleID != candidateID {
				t.Fatalf("candidate was not confirmed after recovery: receipt=%+v state=%+v err=%v", confirmed, current, err)
			}
			if installed, err := os.ReadFile(host.layout.ConfigPath); err != nil || !bytes.Equal(installed, candidate) {
				t.Fatalf("confirmation changed the candidate config: %q (%v)", installed, err)
			}
		})
	}
}

func TestWindowsBundleRestoreReinstallsCurrentAfterCandidateDisproved(t *testing.T) {
	const candidateID = "b-01JA00000000000000000000D3"
	host := newWindowsBundleRestoreHost(t)
	driver := newWindowsBundleDriver(host.layout)
	candidate := append(append([]byte(nil), host.bundleConfig...), []byte("# rejected candidate\n")...)
	rc := windowsKilledApplyReceipt(t, driver, candidateID, 6, candidate, enterprisebundle.StateApplied)
	windowsBundlePolicy = func(context.Context) *enterprisebundle.GatewayPolicy {
		return &enterprisebundle.GatewayPolicy{EffectiveDigest: host.digest, Digest: host.digest, Applied: true,
			BundleID: host.bundleID, BundleVersion: 5}
	}
	cmd, _ := windowsBundleCommand()
	opts := windowsBundleRestoreOptions()
	if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", opts); done || err != nil {
		t.Fatalf("plain ensure prepare: done=%t err=%v", done, err)
	}
	if got := windowsBundleReceiptState(t, host.layout, rc.ReceiptID); got.State != enterprisebundle.StateFailed || got.ErrorCode != enterprisebundle.CodeDigestMismatch {
		t.Fatalf("disproved candidate = %s/%s, want failed/digest_mismatch", got.State, got.ErrorCode)
	}
	if restore := restoreWindowsBundleConfig(t.Context(), windowsBundleSettleReplacing(opts)); restore.failed() || len(restore.changes) != 1 {
		t.Fatalf("confirmed bundle was not restored: %+v", restore)
	}
	if installed, err := os.ReadFile(host.layout.ConfigPath); err != nil || !bytes.Equal(installed, host.bundleConfig) {
		t.Fatalf("confirmed bundle config not restored: %q (%v)", installed, err)
	}
}

func TestWindowsBundleRestoreDoesNotKeepUncommittedCandidate(t *testing.T) {
	const candidateID = "b-01JA00000000000000000000D4"
	host := newWindowsBundleRestoreHost(t)
	driver := newWindowsBundleDriver(host.layout)
	candidate := append(append([]byte(nil), host.bundleConfig...), []byte("# uncommitted candidate\n")...)
	rc := windowsKilledApplyReceipt(t, driver, candidateID, 6, candidate, enterprisebundle.StateStaged)
	// Matching installed bytes alone do not prove that the lifecycle
	// committed this receipt. The generation still belongs to A.
	writeBundleTestFile(t, host.layout.ConfigPath, candidate)
	windowsBundlePolicy = func(context.Context) *enterprisebundle.GatewayPolicy { return nil }
	cmd, _ := windowsBundleCommand()
	opts := windowsBundleRestoreOptions()
	if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", opts); done || err != nil {
		t.Fatalf("plain ensure prepare: done=%t err=%v", done, err)
	}
	if got := windowsBundleReceiptState(t, host.layout, rc.ReceiptID); got.State != enterprisebundle.StateFailed {
		t.Fatalf("uncommitted candidate remained %s, want failed", got.State)
	}
	if restore := restoreWindowsBundleConfig(t.Context(), windowsBundleSettleReplacing(opts)); restore.failed() || len(restore.changes) != 1 {
		t.Fatalf("confirmed bundle was not restored: %+v", restore)
	}
	if installed, err := os.ReadFile(host.layout.ConfigPath); err != nil || !bytes.Equal(installed, host.bundleConfig) {
		t.Fatalf("confirmed bundle config not restored: %q (%v)", installed, err)
	}
}

func TestWindowsBundleRepairRestoresConfigChangedOutsideTheLifecycle(t *testing.T) {
	host := newWindowsBundleRestoreHost(t)
	edited := host.tamper(t, false)
	stub := host.installer(t, installedStatus("repair"))
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	opts := windowsBundleRestoreOptions()
	err := runWindowsEnterpriseStandaloneAction(context.Background(), command, "repair", opts, `C:\x\install-enterprise.ps1`, windowsEnterprisePowerShellArgs("repair", opts))
	result := windowsBundleLifecycleResult(t, &stdout)
	if err != nil {
		t.Fatalf("repair: %v\n%s", err, stdout.String())
	}
	host.assertRestored(t, result, edited)
	if len(stub.calls) != 1 {
		t.Fatalf("installer runs %q", stub.calls)
	}
}

// verify reports, it never repairs: a tampered bundle-mode device fails it
// with bundle_not_applied and keeps its config.yaml.
func TestWindowsBundleVerifyFailsWhileTheGatewayEnforcesAnEdit(t *testing.T) {
	host := newWindowsBundleRestoreHost(t)
	edited := host.tamper(t, false)
	host.installer(t, installedStatus("verify"))
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	opts := windowsBundleRestoreOptions()
	err := runWindowsEnterpriseStandaloneAction(context.Background(), command, "verify", opts, `C:\x\install-enterprise.ps1`, windowsEnterprisePowerShellArgs("verify", opts))
	result := windowsBundleLifecycleResult(t, &stdout)
	if commandExitCode(err) != enterprisestatus.WindowsExitFailure || result.OK || result.ExitCode != enterprisestatus.WindowsExitFailure {
		t.Fatalf("verify of a tampered bundle device: exit %d (%v), ok=%v", commandExitCode(err), err, result.OK)
	}
	var problem string
	for _, m := range result.Errors {
		if m.Code == bundleNotAppliedCode {
			problem = m.Message
		}
	}
	if !strings.Contains(problem, "config.yaml is not the config of signed policy bundle "+host.bundleID+" version 5") {
		t.Fatalf("no bundle_not_applied naming the edit: %+v", result.Errors)
	}
	if installed, err := os.ReadFile(host.layout.ConfigPath); err != nil || !bytes.Equal(installed, edited) {
		t.Fatalf("verify changed config.yaml (read %v)", err)
	}
	if _, err := os.Stat(host.rejectedPath()); !errors.Is(err, fs.ErrNotExist) || host.locks != 0 {
		t.Fatalf("verify wrote rejected-config.yaml (%v) or took lifecycle.lock (%d)", err, host.locks)
	}

	// The same device, untampered, has no bundle_not_applied. (Other verify
	// checks read the host, such as the installed scanner runtime, and may
	// fail on a test host without a deployment.)
	if err := os.WriteFile(host.layout.ConfigPath, host.bundleConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	host.installer(t, installedStatus("verify"))
	stdout.Reset()
	_ = runWindowsEnterpriseStandaloneAction(context.Background(), command, "verify", opts, `C:\x\install-enterprise.ps1`, windowsEnterprisePowerShellArgs("verify", opts))
	result = windowsBundleLifecycleResult(t, &stdout)
	if windowsBundleHasCode(result.Errors, bundleNotAppliedCode) {
		t.Fatalf("verify of the untampered device reported %s: %+v", bundleNotAppliedCode, result.Errors)
	}
}

// A version directory that no longer matches its manifest cannot give the
// config back: ensure stops with bundle_restore_failed before the installer
// runs, so nothing starts on the edited file.
func TestWindowsBundleEnsureFailsClosedWhenTheBundleStoreCannotRestore(t *testing.T) {
	host := newWindowsBundleRestoreHost(t)
	edited := host.tamper(t, false)
	host.damageCurrentVersion(t)
	stub := host.installer(t) // any installer run fails the test
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, windowsBundleRestoreOptions(), `C:\stage\install-enterprise.ps1`)
	result := windowsBundleLifecycleResult(t, &stdout)
	if commandExitCode(err) != enterprisestatus.WindowsExitFailure || !windowsBundleHasCode(result.Errors, "bundle_restore_failed") || len(stub.calls) != 0 {
		t.Fatalf("ensure over a damaged bundle store: exit %d, errors %+v, installer runs %q", commandExitCode(err), result.Errors, stub.calls)
	}
	if installed, err := os.ReadFile(host.layout.ConfigPath); err != nil || !bytes.Equal(installed, edited) {
		t.Fatalf("the failed restore changed config.yaml (read %v)", err)
	}
}

// damageCurrentVersion changes one file of the confirmed version directory
// so it no longer matches its manifest.
func (host *windowsBundleRestoreHost) damageCurrentVersion(t *testing.T) {
	t.Helper()
	driver := newWindowsBundleDriver(host.layout)
	st, err := driver.Store.LoadState()
	if err != nil || st.Current == nil {
		t.Fatalf("state %+v: %v", st, err)
	}
	var damaged bool
	versionDir := driver.Store.VersionDir(st.Current.Dir)
	_ = filepath.WalkDir(versionDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || damaged || entry.IsDir() || entry.Name() == enterprisebundle.ManifestName {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr == nil && os.WriteFile(path, append(raw, '\n'), 0o600) == nil {
			damaged = true
		}
		return nil
	})
	if !damaged {
		t.Fatalf("no bundle file to damage under %s", versionDir)
	}
}

// Repair over a damaged bundle store changes nothing, also when the hook
// runtime folder's permissions drifted: bundle_restore_failed comes before
// the permission repair and the installer, as bundle apply --help says.
func TestWindowsBundleRepairChangesNothingWhenTheBundleStoreCannotRestore(t *testing.T) {
	host := newWindowsBundleRestoreHost(t)
	edited := host.tamper(t, false)
	host.damageCurrentVersion(t)
	// The installer stub clears the hook runtime seam, so the drift is set
	// up after it.
	stub := host.installer(t) // any installer run fails the test
	runtimeDir := t.TempDir()
	dir, inspect, repair := windowsEnterpriseHookRuntimeDir, windowsEnterpriseInspectPublicDir, windowsEnterpriseRepairPublicDir
	t.Cleanup(func() {
		windowsEnterpriseHookRuntimeDir, windowsEnterpriseInspectPublicDir, windowsEnterpriseRepairPublicDir = dir, inspect, repair
	})
	windowsEnterpriseHookRuntimeDir = func() (string, error) { return runtimeDir, nil }
	windowsEnterpriseInspectPublicDir = func(string) (enterprisepolicy.WindowsPublicDirDrift, error) {
		return enterprisepolicy.WindowsPublicDirDrift{UsersReadMissing: true}, nil
	}
	var repaired []string
	windowsEnterpriseRepairPublicDir = func(path string) error {
		repaired = append(repaired, path)
		return nil
	}
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	opts := windowsBundleRestoreOptions()
	err := runWindowsEnterpriseStandaloneAction(context.Background(), command, "repair", opts, `C:\x\install-enterprise.ps1`, windowsEnterprisePowerShellArgs("repair", opts))
	result := windowsBundleLifecycleResult(t, &stdout)
	if commandExitCode(err) != enterprisestatus.WindowsExitFailure || !windowsBundleHasCode(result.Errors, "bundle_restore_failed") || len(stub.calls) != 0 {
		t.Fatalf("repair over a damaged bundle store: exit %d, errors %+v, installer runs %q", commandExitCode(err), result.Errors, stub.calls)
	}
	if len(repaired) != 0 || len(result.Changes) != 0 {
		t.Fatalf("repair changed the host before it stopped: permission repairs %q, changes %q", repaired, result.Changes)
	}
	if installed, err := os.ReadFile(host.layout.ConfigPath); err != nil || !bytes.Equal(installed, edited) {
		t.Fatalf("the failed restore changed config.yaml (read %v)", err)
	}
	// The drift is real: the permission repair on its own fixes it.
	if repairWindowsEnterpriseHookRuntimeAccess() == "" || len(repaired) != 1 || repaired[0] != runtimeDir {
		t.Fatalf("the drifted hook runtime folder was not repairable: %q", repaired)
	}
}

// While an install transaction is pending its recovery restores the config
// it recorded; the restore writes nothing and says the next ensure re-applies
// the bundle.
func TestWindowsBundleRestoreWaitsForAPendingTransaction(t *testing.T) {
	host := newWindowsBundleRestoreHost(t)
	edited := host.tamper(t, false)
	pending := filepath.Join(filepath.Dir(host.layout.ConfigDir), "install", "pending.json")
	if err := os.MkdirAll(filepath.Dir(pending), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pending, []byte(`{"action":"upgrade"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := restoreWindowsBundleConfig(context.Background(), "")
	if restore.failed() || len(restore.changes) != 0 || len(restore.warnings) != 1 || restore.warnings[0].Code != "bundle_restore_deferred" {
		t.Fatalf("restore during a pending transaction: %+v", restore)
	}
	if installed, err := os.ReadFile(host.layout.ConfigPath); err != nil || !bytes.Equal(installed, edited) {
		t.Fatalf("the deferred restore changed config.yaml (read %v)", err)
	}
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}
	if restore := restoreWindowsBundleConfig(context.Background(), ""); restore.failed() || len(restore.changes) != 1 {
		t.Fatalf("restore after the transaction settled: %+v", restore)
	}
}

// GAP-0011: the rollback of a bundle the gateway adopted but the apply could
// not confirm puts the last good bundle's config back recorded as that
// bundle (principal, bundle id, version and signer), also once its receipt
// was pruned. It used to be recorded as a plain lifecycle write, so the
// gateway digested the restored config outside the bundle's scope and
// status, verify and ensure failed with bundle_not_applied.
func TestWindowsBundleRollbackRecordsTheLastGoodBundleAgain(t *testing.T) {
	// GAP-0445: equal bytes, policy digest and generation do not prove a
	// signed bundle. A refused nested ensure must not count as a rollback.
	for _, tc := range []struct {
		name              string
		pruned, identical bool
		identity          string
		version           uint64
		want              bool
	}{
		{name: "receipt kept", version: 5, want: true},
		{name: "receipt pruned", pruned: true, version: 5, want: true},
		{name: "different bundle with identical config", identical: true, identity: "different-bundle", version: 5},
		{name: "different version with identical config", identical: true, version: 4},
		{name: "missing identity", identity: "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := newWindowsBundleRestoreHost(t)
			ctx := context.Background()
			host.tamper(t, false)
			if restore := restoreWindowsBundleConfig(ctx, ""); restore.failed() {
				t.Fatalf("record the confirmed bundle: %+v", restore)
			}
			before, err := configwrite.ReadGenerationState(host.layout.ConfigPath)
			if err != nil || before.BundleID != host.bundleID {
				t.Fatalf("the confirmed bundle config is not recorded as the bundle: %+v (%v)", before, err)
			}
			// The next bundle's config, installed and adopted, then refused.
			failed := append(append([]byte(nil), host.bundleConfig...), []byte("# next bundle\n")...)
			if tc.identical {
				failed = host.bundleConfig
			}
			if err := windowsEnterpriseHotConfigWrite(ctx, host.layout.ConfigPath, failed, configwrite.Options{Actor: configwrite.ActorLifecycle,
				Reason: "next bundle", ExpectSHA256: configwrite.SHA256Hex(host.bundleConfig)}); err != nil {
				t.Fatal(err)
			}
			if tc.pruned {
				receipts, _ := filepath.Glob(filepath.Join(host.layout.LifecycleDir, enterprisebundle.ReceiptsDirName, "*.json"))
				for _, path := range receipts {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
			}
			host.installer(t, installedStatus("status"), installedStatus("Verify"))
			windowsEnterprisePolicyDigest = func(ctx context.Context) ([]byte, error) {
				raw, err := host.policyDigest(ctx)
				if err != nil {
					return nil, err
				}
				var report policyDigestReport
				if err := json.Unmarshal(raw, &report); err != nil {
					return nil, err
				}
				if tc.identity == "missing" {
					report.GatewayReportedBundleID = ""
				} else if tc.identity != "" {
					report.GatewayReportedBundleID = tc.identity
				}
				report.GatewayReportedBundleVersion = tc.version
				return json.Marshal(report)
			}
			source, validate := windowsEnterpriseHotConfigSourceCheck, windowsEnterpriseHotConfigValidate
			t.Cleanup(func() { windowsEnterpriseHotConfigSourceCheck, windowsEnterpriseHotConfigValidate = source, validate })
			windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "config", nil }
			windowsEnterpriseHotConfigSourceCheck = func(string) error { return nil }
			windowsEnterpriseHotConfigValidate = func(string, string, string, bool) (windowsServiceConfigValidation, error) {
				return windowsServiceConfigValidation{}, nil
			}
			opts := windowsBundleRestoreOptions()
			opts.gatewayBinary, opts.acpBinary, opts.hookBinary, opts.sensorHelperBinary, opts.policyCompiler = "", "", "", "", ""
			opts.noStart, opts.resolvedInstaller = false, `C:\stage\install-enterprise.ps1`
			cmd, _ := windowsBundleCommand()
			run := &windowsBundleRun{ctx: ctx, layout: host.layout, driver: newWindowsBundleDriver(host.layout),
				previous: host.bundleConfig, previousGeneration: before}
			if _, ok := rollbackWindowsBundle(cmd, opts, run); ok != tc.want {
				t.Fatalf("rollback applied = %v, want %v", ok, tc.want)
			}
			if !tc.want {
				return
			}
			state, err := configwrite.ReadGenerationState(host.layout.ConfigPath)
			if err != nil || state.ConfigSHA256 != configwrite.SHA256Hex(host.bundleConfig) || state.BundleID != host.bundleID ||
				state.BundleVersion != 5 || state.SignerKeyID != "k1" || !configwrite.IsPrincipalActor(state.Actor) {
				t.Fatalf("after the rollback config.generation.json is %+v (%v), want bundle %s version 5 signed by k1", state, err, host.bundleID)
			}
		})
	}
}
