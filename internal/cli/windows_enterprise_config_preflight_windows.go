// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsEnterpriseStandaloneLayoutForPreflight is replaceable in tests.
var windowsEnterpriseStandaloneLayoutForPreflight = managed.StandaloneWindowsLayout

// windowsEnterpriseStandaloneConfigSource refuses an administrator config
// that a standard user could change before the lifecycle reads it, naming
// the account and the icacls fix. The installer refused it later, as a
// 1603 lifecycle error that named only a SID (GAP-0562). Tests replace it.
var windowsEnterpriseStandaloneConfigSource = func(path string) error {
	err := managed.ValidateTrustedFilePath(path, "config")
	if err == nil {
		return nil
	}
	if text, ok := managed.DescribeUntrustedSource("config", path, err); ok {
		return errors.New(text)
	}
	return fmt.Errorf("refusing untrusted config: %w", err)
}

// windowsEnterpriseStandaloneConfigPreflight refuses a standalone install or
// ensure whose config the gateway service could not load, before anything
// changes. The compile runs with the pins the gateway service
// starts with. A host whose trusted layout cannot be resolved is left to the
// lifecycle's own checks.
func windowsEnterpriseStandaloneConfigPreflight(configPath string) error {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return nil
	}
	if err := windowsEnterpriseStandaloneConfigSource(configPath); err != nil {
		return err
	}
	layout, err := windowsEnterpriseStandaloneLayoutForPreflight()
	if err != nil {
		return nil
	}
	pins := windowsEnterpriseServicePins(layout)
	pins[managed.ConfigPathEnv] = configPath
	restore := setTemporaryEnvironment(pins)
	defer restore()
	// Before anything is stopped: the enumerator and the gateway refuse a
	// pack a standard user can change, and Setup found out only after it had
	// stopped every service (GAP-0668). A config that does not compile is
	// left to the compiler check below, which names the line.
	if runtime := standaloneGatewayRuntimeCandidate(configPath); runtime != nil {
		if err := windowsEnterpriseStandaloneRulePacksTrusted(runtime); err != nil {
			return err
		}
	}
	// The administrator's config may sit anywhere, so credential references
	// resolve from the deployment's secrets directory, as in the service.
	if err := validateStandaloneGatewayConfig(configPath, layout.DataDir, layout.SecretsDir); err != nil {
		return fmt.Errorf("%v; fix it and run again (nothing was changed)", err)
	}
	return nil
}

// windowsEnterpriseStandaloneKeptConfigPreflight runs that check on the
// installed config.yaml for an upgrade that keeps it: this release's gateway
// must load it, custom_packs pins included, before the lifecycle stops the
// services. Before, a pin the new gateway refused stopped all four services
// and failed only after the 4-minute readiness wait (GAP-0188). A host with
// no installed config has nothing to keep. A config_version 8 file is left to
// the transaction, which migrates it (writing its pins with this release's
// digest) and then runs the same check.
func windowsEnterpriseStandaloneKeptConfigPreflight() error {
	layout, err := windowsEnterpriseStandaloneLayoutForPreflight()
	if err != nil {
		return nil
	}
	raw, err := os.ReadFile(layout.ConfigPath)
	if err != nil || config.NeedsMigrationV9(raw) {
		return nil
	}
	return windowsEnterpriseStandaloneConfigPreflight(layout.ConfigPath)
}

// windowsEnterpriseStandaloneRulePackTrust is managed.ValidateTrustedRulePackTree;
// tests replace it.
var windowsEnterpriseStandaloneRulePackTrust = managed.ValidateTrustedRulePackTree

// windowsEnterpriseStandaloneRulePacksTrusted refuses a config that names a
// rule pack a standard user can change: the pack folder, the folders above
// it, or any file or folder in it (GAP-0668, GAP-0672). The refusal names the
// account, what it can change and the icacls commands that fix it. A pack
// that does not exist is left to the pack loader, which names it.
func windowsEnterpriseStandaloneRulePacksTrusted(runtime *config.Config) error {
	if runtime == nil {
		return nil
	}
	serviceAccount := strings.TrimSpace(os.Getenv(managed.WindowsServiceAccountEnv))
	dirs := runtime.ReferencedRulePackDirs()
	seen := map[string]bool{}
	for _, label := range config.RulePackCheckOrder(dirs) {
		dir := strings.TrimSpace(dirs[label])
		if dir == "" || seen[strings.ToLower(dir)] {
			continue
		}
		seen[strings.ToLower(dir)] = true
		if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := windowsEnterpriseStandaloneRulePackTrust(dir, label, serviceAccount); err != nil {
			if text, ok := managed.DescribeUntrustedRulePack(label, dir, err); ok {
				return errors.New(text)
			}
			return fmt.Errorf("the rule pack %s (%s) is not administrator-controlled: %v; keep the pack, the files and folders in it and the folders above it writable only by Administrators and SYSTEM, and run it again (nothing was changed)", dir, label, err)
		}
	}
	return nil
}

// windowsEnterpriseStandaloneTransactionPending reports a lifecycle
// transaction an interrupted run left: its recovery restores the deployment
// as it was before, config and rule packs included. Tests replace it.
var windowsEnterpriseStandaloneTransactionPending = func() bool {
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil || strings.TrimSpace(roots.MetadataPath) == "" {
		return false
	}
	_, err = os.Lstat(filepath.Join(filepath.Dir(roots.MetadataPath), "pending.json"))
	return err == nil
}

// windowsEnterpriseStandaloneRepairRulePackPreflight checks the rule packs
// of the installed config before a repair stops the services: the trust
// check, and the packs as the gateway builds them at start, digest pins
// included. A pack a standard user changed was rejected by the running
// gateway, which kept its last good policy, but the documented repair then
// restarted the gateway into a failed start and left it stopped for every
// user (GAP-0672). Refused here, the running gateway keeps that policy. A
// pending transaction is left to its recovery, which restores the packs the
// deployment had.
func windowsEnterpriseStandaloneRepairRulePackPreflight() error {
	if windowsEnterpriseStandaloneTransactionPending() {
		return nil
	}
	layout, err := windowsEnterpriseStandaloneLayoutForPreflight()
	if err != nil {
		return nil
	}
	raw, err := os.ReadFile(layout.ConfigPath)
	if err != nil || config.NeedsMigrationV9(raw) {
		return nil
	}
	pins := windowsEnterpriseServicePins(layout)
	pins[managed.ConfigPathEnv] = layout.ConfigPath
	restore := setTemporaryEnvironment(pins)
	defer restore()
	runtime := standaloneGatewayRuntimeCandidate(layout.ConfigPath)
	if runtime == nil {
		return nil
	}
	if err := windowsEnterpriseStandaloneRulePacksTrusted(runtime); err != nil {
		return err
	}
	if !runtime.Guardrail.Enabled {
		return nil
	}
	if err := windowsEnterpriseStandaloneRulePackBuild(runtime); err != nil {
		return fmt.Errorf("the gateway cannot load the guardrail rule packs that the installed config %s selects, so a repair would restart it into a failed start: %v. The running gateway keeps its last good policy. Put the pack back as its digest pin names it, or apply a config with the new digest with Setup /ensure CONFIG=, then run the repair again (nothing was changed)", layout.ConfigPath, err)
	}
	return nil
}

// windowsEnterpriseStandaloneRulePackBuild is gateway.CheckRulePacks; tests
// replace it.
var windowsEnterpriseStandaloneRulePackBuild = gateway.CheckRulePacks
