// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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
	// A destination secret read from an environment variable never
	// resolves in the gateway service, whose environment the lifecycle
	// writes. It passed this check, Setup stopped the services, the gateway
	// failed to start and the rollback ended with 1603 after almost five
	// minutes, advising the per-user `defenseclaw keys set` (GAP-0966).
	if raw, err := os.ReadFile(configPath); err == nil {
		if refusal, found := config.ScanManagedEnvSecretReferences(raw).Refusal(configPath,
			"from an elevated prompt with `defenseclaw.exe enterprise secret set --name <name> --from-file <key file>`",
			config.EnterpriseSettingsReferenceURL); found {
			return fmt.Errorf("%s; fix it and run again (nothing was changed)", refusal)
		}
	}
	return windowsEnterpriseStandaloneConfigCompile(configPath)
}

// windowsEnterpriseStandaloneConfigCompile proves the gateway service can
// load configPath, with the pins it starts with.
func windowsEnterpriseStandaloneConfigCompile(configPath string) error {
	layout, err := windowsEnterpriseStandaloneLayoutForPreflight()
	if err != nil {
		return nil
	}
	pins := windowsEnterpriseServicePins(layout)
	pins[managed.ConfigPathEnv] = configPath
	restore := setTemporaryEnvironment(pins)
	defer restore()
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
	// The installed config is the one the gateway runs now: only the
	// compile is checked, so an upgrade is never refused for a reference
	// the running gateway resolves.
	if err := windowsEnterpriseStandaloneConfigSource(layout.ConfigPath); err != nil {
		return err
	}
	return windowsEnterpriseStandaloneConfigCompile(layout.ConfigPath)
}
