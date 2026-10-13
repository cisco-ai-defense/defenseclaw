//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Signed policy bundles on Windows (management plane spec P1 section 7).
// Setup /ensure BUNDLE=<file> (enterprise windows ensure --bundle) receives
// the bundle into the store under <state root>\etc\bundles, verifies the
// staged copy against the trust anchors in <state root>\etc\trust, promotes
// it to its read-only version directory and renders its config.yaml there.
// The ordinary ensure then installs that config, so its transaction (and
// its rollback) is the one CONFIG= uses. The bundle becomes current only
// when the running gateway reports the effective policy of the installed
// config; otherwise the last good config is installed again and the receipt
// fails. Both folders inherit the state root ACL: SYSTEM and Administrators
// write, the gateway service reads; receipts live in the administrator-only
// install folder. Standalone only: the Secure Client profile never reaches
// this file.

const (
	windowsBundleConfigName   = "bundle-config.yaml"
	windowsBundleRollbackName = "bundle-rollback-config.yaml"
	windowsBundleLockName     = "bundle.lock"
	windowsBundleMaxConfig    = 4 << 20
	windowsBundleMaxAnchors   = 256 << 10
	// windowsBundlePolicyWaits bounds how often the confirm re-reads the
	// gateway policy after a successful transaction (a hot reload lags).
	windowsBundlePolicyWaits = 4
)

// Seams for tests.
var (
	windowsBundleLayout         = managed.StandaloneWindowsLayout
	windowsBundlePolicy         = readWindowsBundleGatewayPolicy
	windowsBundleSleep          = time.Sleep
	windowsBundleTrust          = func(path string) error { return managed.ValidateTrustedFilePath(path, "policy bundle store") }
	windowsBundlePrivateStage   = privateWindowsBundleStage
	windowsBundleSealVersion    = sealWindowsBundleVersionAssets
	windowsBundlePublishVersion = publishWindowsBundleVersion
)

func init() {
	// bundle status and verify ask whether this is a standalone managed
	// device; on Windows the deployment record answers.
	bundleManagedDevice = windowsEnterpriseStandaloneInstalled
}

// windowsBundleRun is the bundle state of one ensure run.
type windowsBundleRun struct {
	ctx      context.Context
	layout   managed.StandaloneLayout
	driver   *enterprisebundle.Driver
	prepared *enterprisebundle.Prepared
	// previous is the installed config.yaml before the run: the last good
	// config while no bundle is current.
	previous []byte
	warnings []enterprisebundle.Warning
	unlock   func()
}

func (run *windowsBundleRun) release() {
	if run.unlock != nil {
		run.unlock()
		run.unlock = nil
	}
}

func newWindowsBundleDriver(layout managed.StandaloneLayout) *enterprisebundle.Driver {
	store := enterprisebundle.NewStore(filepath.Join(layout.ConfigDir, enterprisebundle.BundlesDirName), layout.LifecycleDir)
	store.PrivateStage = windowsBundlePrivateStage
	store.SealVersion = windowsBundleSealVersion
	store.PublishVersion = windowsBundlePublishVersion
	return &enterprisebundle.Driver{
		Store:       store,
		AnchorsPath: filepath.Join(layout.ConfigDir, "trust", enterprisebundle.AnchorsName),
		AnchorTrust: bundleAnchorTrust, Platform: enterprisebundle.PlatformWindows, ProductVersion: appVersion,
		SecretPresent: bundleSecretPresent, Digester: bundleDigester,
		TrustVersion: func(dir string) error {
			return windowsBundleTrust(filepath.Join(dir, enterprisebundle.ManifestName))
		},
	}
}

// privateWindowsBundleStage removes the service's inherited read access
// before the bundle files are copied into staging.
func privateWindowsBundleStage(root string) error {
	return applyWindowsSDDL(root, windowsBundlePrivateSDDL())
}

func windowsBundlePrivateSDDL() string {
	return "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
}

// sealWindowsBundleVersionAssets grants the gateway service SID read and
// execute on each verified asset. The staging root stays administrator-only
// until the rename has published it as a version directory.
func sealWindowsBundleVersionAssets(root string) error {
	service, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return err
	}
	sddl := windowsBundleVersionSDDL(service.String())
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular bundle asset", path)
		}
		if err := applyWindowsSDDL(path, sddl); err != nil {
			return err
		}
		mode := os.FileMode(0o444)
		if entry.IsDir() {
			mode = 0o555
		}
		return os.Chmod(path, mode)
	})
}

func publishWindowsBundleVersion(root string) error {
	service, err := managed.WindowsServiceAccountSID(`NT SERVICE\` + managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return err
	}
	if err := applyWindowsSDDL(root, windowsBundleVersionSDDL(service.String())); err != nil {
		return err
	}
	return os.Chmod(root, 0o555)
}

func windowsBundleVersionSDDL(serviceSID string) string {
	return "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;" + serviceSID + ")"
}

// prepareWindowsEnterpriseBundle runs before the lifecycle reads --config.
// With --bundle it prepares the bundle and makes its rendered config the
// --config of the run; with --trust-anchors it installs the anchor file
// first. In bundle mode (anchors installed) a --config that is not the
// current bundle config is refused with bundle_required. done is set when
// the run ended here with err as its outcome.
func prepareWindowsEnterpriseBundle(ctx context.Context, cmd *cobra.Command, action string, opts *windowsEnterpriseLifecycleOptions) (done bool, err error) {
	if opts.bundleRollback {
		return false, nil
	}
	requested := opts.bundlePath != "" || opts.trustAnchors != ""
	refuse := func(code, message string) (bool, error) {
		return true, writeWindowsBundleRefusal(cmd, action, opts, code, message)
	}
	if requested && action != "ensure" {
		return refuse("invalid_arguments", "--bundle and --trust-anchors are valid only with ensure")
	}
	if opts.bundlePath != "" && strings.TrimSpace(opts.configPath) != "" {
		return refuse("invalid_arguments", "BUNDLE= (--bundle) cannot be combined with CONFIG= (--config): the signed bundle carries the config")
	}
	if opts.trustAnchors != "" && strings.TrimSpace(opts.configPath) != "" {
		// Installing the anchors puts the computer in bundle mode, which
		// refuses CONFIG=; installing them first would let this one run
		// apply an unsigned config past that check.
		return refuse("invalid_arguments", "TRUSTANCHORS= (--trust-anchors) cannot be combined with CONFIG= (--config): with trust anchors installed the computer takes its policy only from signed bundles; deliver BUNDLE= with TRUSTANCHORS=")
	}
	if !windowsEnterpriseMutationAction(action) {
		return false, nil
	}
	layout, err := windowsBundleLayout()
	if err != nil {
		if requested {
			return refuse(string(enterprisebundle.CodeStateInvalid), "cannot resolve the standalone layout: "+err.Error())
		}
		return false, nil
	}
	driver := newWindowsBundleDriver(layout)
	if !requested {
		return refuseWindowsBundleRequired(cmd, action, opts, driver)
	}
	if !opts.installedBeforeRun {
		return refuse(string(enterprisebundle.CodeNotManaged), "DefenseClaw enterprise is not installed: install it first with /ensure CONFIG=<config.yaml>, then deliver policy bundles with /ensure BUNDLE=<file> TRUSTANCHORS=<bundle-anchors.json>")
	}
	unlock, err := lockWindowsBundleStore(layout.LifecycleDir)
	if err != nil {
		return refuse("lifecycle_busy", err.Error())
	}
	run := &windowsBundleRun{ctx: ctx, layout: layout, driver: driver, unlock: unlock}
	opts.bundle = run
	if opts.trustAnchors != "" {
		if err := installWindowsBundleAnchors(opts.trustAnchors, driver.AnchorsPath); err != nil {
			return refuse(string(windowsBundleCode(err, enterprisebundle.CodeAnchorInsecure)), "the trust anchors were not installed: "+err.Error())
		}
	}
	if opts.bundlePath == "" {
		return false, nil
	}
	installed, _ := readBoundedConfigFile(layout.ConfigPath, windowsBundleMaxConfig)
	run.previous = installed
	report, rollback, err := driver.SettleRun(installed, windowsBundlePolicy(ctx))
	if err != nil {
		return refuse(string(enterprisebundle.CodeStateInvalid), "cannot settle the earlier bundle receipts: "+err.Error())
	}
	if len(report.Interrupted) > 0 {
		run.warnings = append(run.warnings, enterprisebundle.Warning{Code: string(enterprisebundle.CodeInterrupted),
			Message: fmt.Sprintf("%d earlier bundle run(s) ended before they applied; the last good bundle kept enforcing", len(report.Interrupted))})
	}
	if len(rollback) > 0 {
		// The installed config is a bundle that was never confirmed, not a
		// last good config: a rollback of this run must not report it as one.
		run.previous = nil
		run.warnings = append(run.warnings, enterprisebundle.Warning{Code: string(enterprisebundle.CodeNotConfirmed),
			Message: "an earlier bundle was installed but never confirmed; this run installs the new bundle over it"})
	}
	b, readErr := readBundleInput(opts.bundlePath)
	prepared, err := driver.Prepare(ctx, b, readErr)
	run.prepared = prepared
	if prepared != nil {
		run.warnings = append(run.warnings, prepared.Warnings...)
	}
	if err != nil {
		return refuse(string(windowsBundleCode(err, enterprisebundle.CodeApplyFailed)), windowsBundleNotApplied(prepared, err.Error()))
	}
	path := filepath.Join(layout.LifecycleDir, windowsBundleConfigName)
	if err := writeWindowsBundleFile(path, prepared.Config); err != nil {
		if prepared.Receipt != nil {
			_ = driver.Store.Fail(prepared.Receipt, enterprisebundle.CodeApplyFailed, "cannot write the rendered bundle config")
		}
		return refuse(string(enterprisebundle.CodeApplyFailed), "cannot write the rendered bundle config: "+err.Error())
	}
	opts.configPath = path
	return false, nil
}

// refuseWindowsBundleRequired refuses, in bundle mode, a --config that is
// not the config of the current bundle.
func refuseWindowsBundleRequired(cmd *cobra.Command, action string, opts *windowsEnterpriseLifecycleOptions, driver *enterprisebundle.Driver) (bool, error) {
	if strings.TrimSpace(opts.configPath) == "" {
		return false, nil
	}
	if _, err := os.Lstat(driver.AnchorsPath); err != nil {
		return false, nil
	}
	current, _, err := driver.CurrentConfig()
	given, readErr := readBoundedConfigFile(opts.configPath, windowsBundleMaxConfig)
	if err == nil && readErr == nil && current != nil && bytes.Equal(given, current) {
		return false, nil
	}
	return true, writeWindowsBundleRefusal(cmd, action, opts, string(enterprisebundle.CodeBundleRequired), fmt.Sprintf(
		"this device takes its policy from signed bundles (the MDM installed %s), so CONFIG= is not applied; deliver a signed bundle with /ensure BUNDLE=<file>",
		driver.AnchorsPath))
}

// writeWindowsBundleRefusal answers a bundle run that ended before the
// transaction: nothing was installed, so the result is the host as it is
// with the bundle block of the receipt.
func writeWindowsBundleRefusal(cmd *cobra.Command, action string, opts *windowsEnterpriseLifecycleOptions, code, message string) error {
	result := newWindowsEnterpriseStandaloneResult(action, opts)
	applyWindowsEnterpriseRecordedDeployment(result)
	result.AddError(code, message)
	return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
}

func windowsBundleCode(err error, fallback enterprisebundle.Code) enterprisebundle.Code {
	if code := enterprisebundle.CodeOf(err); code != "" {
		return code
	}
	return fallback
}

func windowsBundleNotApplied(p *enterprisebundle.Prepared, message string) string {
	if p == nil || p.Receipt == nil || p.Receipt.BundleID == "" {
		return "the policy bundle was not applied: " + message + "; the last good policy keeps enforcing"
	}
	return fmt.Sprintf("policy bundle %s version %d was not applied: %s; the last good policy keeps enforcing",
		p.Receipt.BundleID, p.Receipt.Version, message)
}

// finishWindowsEnterpriseBundle settles the bundle of a run once its ensure
// ended, before the result is recorded and printed: the bundle is confirmed
// when the transaction installed its config and the gateway enforces it;
// otherwise the last good config goes back and the receipt fails. Every
// standalone result then carries the bundle block.
func finishWindowsEnterpriseBundle(cmd *cobra.Command, opts *windowsEnterpriseLifecycleOptions, result *enterprisestatus.Result) {
	if opts == nil || opts.bundleRollback {
		return
	}
	run := opts.bundle
	if run == nil {
		attachWindowsBundleSummary(result, nil, nil)
		return
	}
	opts.bundle = nil
	defer run.release()
	for _, w := range run.warnings {
		result.AddWarning(w.Code, w.Message)
	}
	p := run.prepared
	if p != nil && p.AlreadyApplied && len(result.Errors) == 0 && result.Noop {
		result.NoopReason = "already_applied"
	}
	if p != nil && p.Receipt != nil && !enterprisebundle.Finished(p.Receipt.State) {
		installed := windowsBundleInstalledSHA(run.layout.ConfigPath)
		var failure []string
		for _, e := range result.Errors {
			failure = append(failure, e.Code)
		}
		policy := windowsBundlePolicyFromResult(result)
		for i := 0; len(failure) == 0 && installed == p.ConfigSHA256 && !windowsBundleEnforces(policy) && i < windowsBundlePolicyWaits; i++ {
			windowsBundleSleep(5 * time.Second)
			if next := windowsBundlePolicy(run.ctx); next != nil {
				policy = *next
			}
		}
		restart := false
		for _, w := range result.Warnings {
			restart = restart || strings.Contains(w.Message, "every service was restarted")
		}
		_, err := run.driver.Finish(p, installed, failure, policy, restart, func() (string, bool) {
			return rollbackWindowsBundle(cmd, opts, run)
		})
		if err != nil {
			code := string(windowsBundleCode(err, enterprisebundle.CodeApplyFailed))
			if !windowsBundleHasCode(result.Errors, code) {
				result.AddError(code, windowsBundleNotApplied(p, err.Error()))
			}
		}
	}
	var receipt *enterprisebundle.Receipt
	if p != nil {
		receipt = p.Receipt
	}
	attachWindowsBundleSummary(result, run.driver.Store, receipt)
}

func windowsBundleEnforces(p enterprisebundle.GatewayPolicy) bool {
	return p.Applied && p.ReloadError == "" && p.Digest != ""
}

func windowsBundleHasCode(messages []enterprisestatus.Message, code string) bool {
	for _, m := range messages {
		if m.Code == code {
			return true
		}
	}
	return false
}

// rollbackWindowsBundle installs the last good config again (the current
// bundle config, or the config installed before the run while no bundle is
// current) with a second ensure whose result is not printed: the result of
// this run reports the failed bundle. It returns the digest the gateway then
// enforces and whether the last good config is installed.
func rollbackWindowsBundle(cmd *cobra.Command, opts *windowsEnterpriseLifecycleOptions, run *windowsBundleRun) (string, bool) {
	last, ref, err := run.driver.CurrentConfig()
	if err != nil {
		return "", false
	}
	if ref == nil {
		last = run.previous
	}
	if len(last) == 0 || opts.resolvedInstaller == "" {
		return "", false
	}
	path := filepath.Join(run.layout.LifecycleDir, windowsBundleRollbackName)
	if err := writeWindowsBundleFile(path, last); err != nil {
		return "", false
	}
	defer os.Remove(path)
	rollback := *opts
	rollback.bundle, rollback.bundleRollback = nil, true
	rollback.bundlePath, rollback.trustAnchors, rollback.configPath = "", "", path
	rollback.jsonOutput = true
	out := cmd.OutOrStdout()
	cmd.SetOut(io.Discard)
	_ = runWindowsEnterpriseStandaloneEnsure(run.ctx, cmd, &rollback, opts.resolvedInstaller)
	cmd.SetOut(out)
	enforcing := ""
	if policy := windowsBundlePolicy(run.ctx); policy != nil {
		enforcing = policy.Digest
	}
	return enforcing, windowsBundleInstalledSHA(run.layout.ConfigPath) == sha256HexBytes(last)
}

// attachWindowsBundleSummary sets the result v2 bundle block: the receipt
// of this run if it reached staging, else the store summary. A store this account
// cannot read (status as a standard user) adds nothing.
func attachWindowsBundleSummary(result *enterprisestatus.Result, store *enterprisebundle.Store, receipt *enterprisebundle.Receipt) {
	if result == nil {
		return
	}
	if store == nil {
		layout, err := windowsBundleLayout()
		if err != nil {
			return
		}
		store = newWindowsBundleDriver(layout).Store
	}
	if _, refusal, err := store.Latest(); err == nil {
		result.LastRefusal = refusal
	}
	if result.Bundle != nil {
		return
	}
	if receipt != nil && !receipt.IsRefusal() {
		if st, err := store.LoadState(); err == nil {
			result.Bundle = receipt.Status(st.Current)
		}
		return
	}
	if summary, err := store.Summary(); err == nil && summary != nil && summary.BundleID != "" {
		result.Bundle = summary
	}
}

func windowsBundlePolicyFromResult(result *enterprisestatus.Result) enterprisebundle.GatewayPolicy {
	if result.Policy == nil {
		return enterprisebundle.GatewayPolicy{}
	}
	p := result.Policy
	return enterprisebundle.GatewayPolicy{Digest: p.GatewayReportedDigest, Generation: p.ConfigGeneration,
		ReloadError: p.LastReloadError, Applied: p.Applied}
}

// readWindowsBundleGatewayPolicy asks the installed CLI for the effective
// policy of the installed config and the digest the gateway reports; nil
// when either cannot be read.
func readWindowsBundleGatewayPolicy(ctx context.Context) *enterprisebundle.GatewayPolicy {
	state := lifecycleGatewayPolicy(ctx)
	if state == nil {
		return nil
	}
	return &enterprisebundle.GatewayPolicy{Digest: state.GatewayReportedDigest, Generation: state.ConfigGeneration,
		ReloadError: state.LastReloadError, Applied: state.Applied}
}

// lifecycleGatewayPolicy is the policy block the Windows lifecycle reports:
// the effective policy digest of the installed config and whether the
// running gateway reports it. nil when it cannot be read.
func lifecycleGatewayPolicy(ctx context.Context) *enterprisestatus.PolicyState {
	out, err := windowsEnterprisePolicyDigest(ctx)
	if err != nil && len(out) == 0 {
		return nil
	}
	scratch := enterprisestatus.New("status", managed.ProfileStandalone, "windows", appVersion)
	return applyEnterprisePolicyReport(scratch, out, false)
}

func windowsBundleInstalledSHA(path string) string {
	raw, err := readBoundedConfigFile(path, windowsBundleMaxConfig)
	if err != nil {
		return ""
	}
	return sha256HexBytes(raw)
}

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// writeWindowsBundleFile replaces path with data. The file inherits the
// ACL of its administrator-only folder.
func writeWindowsBundleFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp-%d", path, os.Getpid())
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// installWindowsBundleAnchors installs the administrator anchor file src
// as <state root>\etc\trust\bundle-anchors.json once it decodes and passes
// the trust check, then checks the installed copy the same way.
func installWindowsBundleAnchors(src, dst string) error {
	if _, err := enterprisebundle.LoadAnchors(src, bundleAnchorTrust); err != nil {
		return err
	}
	raw, err := safefile.ReadRegularFileBounded(src, windowsBundleMaxAnchors)
	if err != nil {
		return &enterprisebundle.Error{Code: enterprisebundle.CodeAnchorInvalid, Detail: err.Error()}
	}
	if err := writeWindowsBundleFile(dst, raw); err != nil {
		return &enterprisebundle.Error{Code: enterprisebundle.CodeStateInvalid, Detail: err.Error()}
	}
	if _, err := enterprisebundle.LoadAnchors(dst, bundleAnchorTrust); err != nil {
		return err
	}
	return nil
}

// lockWindowsBundleStore takes the bundle store lock for the run, or
// returns at once when another bundle run holds it (lifecycle_busy: the
// MDM retries on 1618).
func lockWindowsBundleStore(lifecycleDir string) (func(), error) {
	if err := os.MkdirAll(lifecycleDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(lifecycleDir, windowsBundleLockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	handle := windows.Handle(f.Fd())
	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped); err != nil {
		_ = f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errors.New("another policy bundle run holds the bundle store; retry when it ends")
		}
		return nil, fmt.Errorf("lock the bundle store: %w", err)
	}
	return func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
		_ = f.Close()
	}, nil
}

// writeWindowsBundleMarker publishes the confirmed bundle on the standalone
// marker key for MDM detection (detect.ps1 -RequireBundle): BundleId,
// BundleVersion and BundleState=confirmed, or no bundle values while no
// bundle is current. An unreadable store leaves the values unchanged.
func writeWindowsBundleMarker(marker registry.Key) error {
	layout, err := windowsBundleLayout()
	if err != nil {
		return nil
	}
	st, err := newWindowsBundleDriver(layout).Store.LoadState()
	if err != nil {
		return nil
	}
	if st.Current == nil {
		for _, name := range []string{"BundleId", "BundleVersion", "BundleState"} {
			if err := marker.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
				return fmt.Errorf("remove enterprise marker %s: %w", name, err)
			}
		}
		return nil
	}
	for name, value := range map[string]string{
		"BundleId":      st.Current.BundleID,
		"BundleVersion": strconv.FormatUint(st.Current.Version, 10),
		"BundleState":   enterprisebundle.StateConfirmed,
	} {
		if err := marker.SetStringValue(name, value); err != nil {
			return fmt.Errorf("write enterprise marker %s: %w", name, err)
		}
	}
	return nil
}
