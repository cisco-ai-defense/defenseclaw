// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// A config-only ensure used to run the whole upgrade transaction: it stops
// every service, replaces the payload, validates and starts them again,
// which took about 130 seconds, during which the gateway was down and every
// agent failed closed (GAP-0135). A change the running gateway applies as a
// generation swap (P0 spec section 4) needs none of that. The gateway
// follows config.yaml, so the lifecycle replaces the file under the writer
// lock, with its access control kept, and waits until /health reports the
// policy the installed config computes to. Any doubt (a key the gateway
// reads once at start, a config_version 8 file, a busy lifecycle lock, a
// config that does not validate, a gateway that does not adopt the change,
// a verify that fails) puts the previous config back and leaves the change
// to the upgrade transaction, which is what every change used to do.

// windowsEnterpriseHotConfigMaxBytes bounds the config read for the check.
const windowsEnterpriseHotConfigMaxBytes = 4 << 20

// Seams for tests. The timeout bounds how long the running gateway gets to
// report the policy the new config computes to.
var (
	windowsEnterpriseHotConfigTimeout  = 30 * time.Second
	windowsEnterpriseHotConfigLayout   = managed.StandaloneWindowsLayout
	windowsEnterpriseHotConfigLock     = acquireWindowsEnterpriseLifecycleLock
	windowsEnterpriseHotConfigValidate = validateWindowsServiceConfig
	windowsEnterpriseHotConfigPoll     = 2 * time.Second
	windowsEnterpriseHotConfigWrite    = func(ctx context.Context, path string, raw []byte, reason string) error {
		_, err := configwrite.ReplaceDocument(ctx, path, raw, configwrite.Options{
			Actor: configwrite.ActorLifecycle, Reason: reason,
		})
		return err
	}
	// The upgrade transaction admits --config only from a source that only
	// SYSTEM, Administrators and TrustedInstaller can write
	// (Assert-DefenseClawTrustedSource), as Setup CONFIG= does
	// (ValidateTrustedFilePath). The hot path checks the same, so whether a
	// standard user's edit is installed does not depend on which keys it
	// changed (GAP-0312).
	windowsEnterpriseHotConfigSourceCheck = managed.ValidateTrustedConfigPath
)

// windowsEnterpriseServicePins are the environment pins the gateway service
// starts with. Any process that loads the managed config as the service
// does must carry all five: without them an administrator or SYSTEM is
// refused by the managed-host guard, and without the service account the
// protected credentials the config references are not trusted.
func windowsEnterpriseServicePins(layout managed.StandaloneLayout) map[string]string {
	return map[string]string{
		managed.ConfigPathEnv:            layout.ConfigPath,
		managed.DeploymentModeEnv:        managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv:     managed.ProfileStandalone,
		managed.WindowsServiceAccountEnv: layout.ServiceUser,
		"DEFENSECLAW_HOME":               layout.DataDir,
	}
}

// windowsEnterpriseEnvironmentWith returns base with the pins set,
// replacing any entry of the same name (Windows names are case-insensitive).
func windowsEnterpriseEnvironmentWith(base []string, pins map[string]string) []string {
	environment := make([]string, 0, len(base)+len(pins))
	for _, entry := range base {
		name, _, _ := strings.Cut(entry, "=")
		replaced := false
		for pin := range pins {
			if strings.EqualFold(name, pin) {
				replaced = true
				break
			}
		}
		if !replaced {
			environment = append(environment, entry)
		}
	}
	for name, value := range pins {
		environment = append(environment, name+"="+value)
	}
	return environment
}

// windowsEnterpriseHotConfigCandidate reports whether this ensure is the
// production deployment's config-only change: a healthy, idle deployment, a
// supplied config, and nothing else asked for.
func windowsEnterpriseHotConfigCandidate(opts *windowsEnterpriseLifecycleOptions, status *windowsEnterpriseInstallerReport) bool {
	return windowsEnterpriseIsElevated() &&
		status != nil && status.OK && status.Installed && status.GatewayReady && !status.TransactionPending &&
		strings.TrimSpace(opts.configPath) != "" &&
		strings.TrimSpace(opts.manifestPath) == "" && strings.TrimSpace(opts.mode) == "" && strings.TrimSpace(opts.connector) == "" &&
		!opts.noStart && strings.TrimSpace(opts.installRoot) == "" && strings.TrimSpace(opts.stateRoot) == "" &&
		strings.TrimSpace(opts.gatewayServiceName) == "" && strings.TrimSpace(opts.guardianServiceName) == ""
}

// windowsEnterpriseHotConfigApply applies the supplied config to the running
// gateway and fills result from a verify of the host. It returns false,
// with config.yaml as it was, when the change must go through the upgrade
// transaction, and then the changed keys the services read only at start,
// if that is why.
func windowsEnterpriseHotConfigApply(
	ctx context.Context,
	cmd *cobra.Command,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
	status *windowsEnterpriseInstallerReport,
	result *enterprisestatus.Result,
) (bool, []string) {
	if !windowsEnterpriseHotConfigCandidate(opts, status) {
		return false, nil
	}
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return false, nil
	}
	// An untrusted source goes to the transaction, which refuses it and
	// says why.
	if windowsEnterpriseHotConfigSourceCheck(opts.configPath) != nil {
		return false, nil
	}
	next, err := readWindowsEnterpriseBoundedFile(opts.configPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return false, nil
	}
	previous, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil || config.NeedsMigrationV9(next) || config.NeedsMigrationV9(previous) {
		return false, nil
	}
	changed, err := configwrite.ChangedPaths(previous, next)
	if err != nil {
		return false, nil
	}
	// A file that changes no setting (line endings, comments, formatting)
	// is installed the same way: the gateway reloads it to the same policy
	// (GAP-0601). Who is enrolled and which connectors are is applied too:
	// the gateway reads neither at start on Windows, and the targets are
	// refreshed below (GAP-0716).
	restart := configwrite.ManagedRestartRequired(changed)
	refreshTargets := false
	var startOnly []string
	for _, path := range restart {
		if !windowsEnterpriseHotTargetsPath(path) {
			startOnly = append(startOnly, path)
			continue
		}
		refreshTargets = true
	}
	if len(startOnly) > 0 {
		return false, startOnly
	}
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return false, nil
	}
	release, err := windowsEnterpriseHotConfigLock(filepath.Join(roots.LifecycleDir, "lifecycle.lock"))
	if err != nil {
		return false, nil
	}
	defer release()

	restoreEnvironment := setTemporaryEnvironment(windowsEnterpriseServicePins(layout))
	defer restoreEnvironment()

	kept := keepWindowsEnterpriseEditedConfig(layout, previous)
	generationPath := configwrite.GenerationPath(layout.ConfigPath)
	_, generationErr := os.Stat(generationPath)
	state, stateErr := configwrite.ReadGenerationState(layout.ConfigPath)
	recordedBefore := stateErr == nil && strings.EqualFold(state.ConfigSHA256, configwrite.SHA256Hex(previous))
	if err := windowsEnterpriseHotConfigWrite(ctx, layout.ConfigPath, next, "enterprise windows ensure"); err != nil {
		return false, nil
	}
	// Undoing puts the config back. A config the record named is recorded
	// again as a new generation: the counter never goes back, because the
	// gateway may already have reported the number the attempt took. A hand
	// edit stays unrecorded, and a record the attempt created goes away.
	undo := func() {
		if recordedBefore {
			_ = windowsEnterpriseHotConfigWrite(context.WithoutCancel(ctx), layout.ConfigPath, previous, "enterprise windows ensure (config change not applied)")
		} else {
			_ = writeFileKeepingDACL(layout.ConfigPath, previous, layout.ConfigPath)
		}
		if generationErr != nil {
			_ = os.Remove(generationPath)
		}
	}
	if _, err := windowsEnterpriseHotConfigValidate(layout.ConfigPath, layout.DataDir, layout.ServiceUser, false); err != nil {
		undo()
		return false, nil
	}
	if !windowsEnterpriseHotConfigAdopted(ctx) {
		undo()
		return false, nil
	}
	// The enumerator publishes the targets the new config enrolls, as the
	// upgrade transaction does; the guardian reconciles them with the config
	// it reloads (enterpriseHookStandaloneConfigRefresh).
	if refreshTargets {
		if err := windowsEnterpriseHotConfigRefreshTargets(ctx, layout); err != nil {
			undo()
			return false, nil
		}
	}
	verifyReport, verifyRun, err := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script,
		windowsEnterprisePowerShellArgs("verify", windowsEnterpriseEnsureProbeOptions(opts)))
	if err != nil || !verifyReport.OK {
		undo()
		return false, nil
	}
	applyWindowsEnterpriseInstallerReport(result, opts, verifyReport, verifyRun)
	result.Changes = append(result.Changes, "applied the config change in the running gateway; it was not restarted")
	if kept != "" {
		result.AddWarning("config_reverted", "config.yaml had been changed outside the lifecycle; ensure put the managed config back and kept the edited file at "+kept)
	}
	applyWindowsEnterprisePolicy(ctx, result)
	applied := strings.Join(changed, ", ")
	switch {
	case len(changed) == 0:
		applied = "no setting changed (line endings, comments or formatting only)"
	case refreshTargets:
		result.Changes = append(result.Changes, "refreshed the enrolled targets; the hook guardian registers and removes hooks for them without a restart")
	}
	result.AddWarning("ensure_config_applied", "ensure applied drift:config in the running gateway, without stopping any service: "+applied)
	return true, nil
}

// windowsEnterpriseHotTargetsPath reports a restart-required change
// (configwrite.ManagedRestartRequired) that the Windows hot path applies
// all the same: an enrollment list (enterprise.enrollment include_users,
// exclude_users, include_groups, exclude_groups, exempt_users) or the
// connector set (guardrail.connectors.<name>[.enabled]). The gateway reads
// neither at start here, the enumerator reads config.yaml on every cycle,
// and the guardian reloads a changed config before it reconciles. Every
// other enterprise key still goes through the upgrade transaction.
func windowsEnterpriseHotTargetsPath(path string) bool {
	switch path {
	case "enterprise.enrollment.include_users", "enterprise.enrollment.exclude_users",
		"enterprise.enrollment.include_groups", "enterprise.enrollment.exclude_groups",
		"enterprise.enrollment.exempt_users":
		return true
	}
	parts := strings.Split(path, ".")
	return len(parts) >= 3 && len(parts) <= 4 && parts[0] == "guardrail" && parts[1] == "connectors" &&
		(len(parts) == 3 || parts[3] == "enabled")
}

// windowsEnterpriseHotConfigRefreshTargets runs one enumerator cycle with
// the installed CLI under the service pins, as the upgrade transaction does
// (Invoke-DefenseClawEnumeratorRefresh). A seam for tests.
var windowsEnterpriseHotConfigRefreshTargets = func(ctx context.Context, layout managed.StandaloneLayout) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, managedWindowsAdminCLI(),
		"enterprise", "windows", "enumerate", "--manifest", layout.ManifestPath, "--once")
	command.Env = windowsEnterpriseEnvironmentWith(os.Environ(), windowsEnterpriseServicePins(layout))
	if out, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("refresh the enrolled targets: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// windowsEnterpriseHotConfigAdopted waits for the gateway to report the
// effective policy the installed config computes to, with no rejected reload
// and the config recorded.
func windowsEnterpriseHotConfigAdopted(ctx context.Context) bool {
	deadline := time.Now().Add(windowsEnterpriseHotConfigTimeout)
	for {
		out, _ := windowsEnterprisePolicyDigest(ctx)
		var report policyDigestReport
		if json.Unmarshal(out, &report) == nil && report.Digest != "" && report.Digest == report.GatewayReportedDigest &&
			report.GatewayLastReloadError == "" && (report.ConfigGeneration == 0 || report.ConfigGenerationRecorded) {
			return true
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(windowsEnterpriseHotConfigPoll):
		}
	}
}

// keepInstalledWindowsEnterpriseEditedConfig is keepWindowsEnterpriseEditedConfig
// for the installed config, for the upgrade transaction that restores it.
func keepInstalledWindowsEnterpriseEditedConfig() string {
	layout, err := windowsEnterpriseHotConfigLayout()
	if err != nil {
		return ""
	}
	current, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseHotConfigMaxBytes)
	if err != nil {
		return ""
	}
	return keepWindowsEnterpriseEditedConfig(layout, current)
}

// keepWindowsEnterpriseEditedConfig keeps a config.yaml that was changed
// outside the lifecycle (its sha256 is not the one config.generation.json
// records) as rejected-config.yaml beside it, before ensure replaces it with
// the managed config. It returns the kept path, or "" when the file was not
// edited or could not be kept. The copy has deployment.json's access
// control, administrators only.
func keepWindowsEnterpriseEditedConfig(layout managed.StandaloneLayout, current []byte) string {
	state, err := configwrite.ReadGenerationState(layout.ConfigPath)
	if err != nil || state.ConfigSHA256 == "" || strings.EqualFold(state.ConfigSHA256, configwrite.SHA256Hex(current)) {
		return ""
	}
	sibling := layout.ConfigPath
	if deployment, err := windowsEnterpriseDeploymentInspector(managed.ProfileStandalone); err == nil && deployment.MetadataPath != "" {
		if _, err := os.Stat(deployment.MetadataPath); err == nil {
			sibling = deployment.MetadataPath
		}
	}
	kept := filepath.Join(layout.ConfigDir, "rejected-config.yaml")
	if err := writeFileKeepingDACL(kept, current, sibling); err != nil {
		return ""
	}
	return kept
}

// acquireWindowsEnterpriseLifecycleLock opens the lifecycle lock the way the
// PowerShell lifecycle does for a mutation, exclusively, and does not wait:
// a busy lock sends the change to the upgrade transaction, which waits for
// it.
func acquireWindowsEnterpriseLifecycleLock(path string) (func(), error) {
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("lifecycle lock %s is not a regular file", path)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return func() { _ = windows.CloseHandle(handle) }, nil
}
