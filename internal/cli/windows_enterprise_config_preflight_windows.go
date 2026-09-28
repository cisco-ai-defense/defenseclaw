// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// windowsEnterpriseStandaloneLayoutForPreflight is replaceable in tests.
var windowsEnterpriseStandaloneLayoutForPreflight = managed.StandaloneWindowsLayout

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
	layout, err := windowsEnterpriseStandaloneLayoutForPreflight()
	if err != nil {
		return nil
	}
	restore := setTemporaryEnvironment(map[string]string{
		managed.ConfigPathEnv:            configPath,
		"DEFENSECLAW_HOME":               layout.DataDir,
		managed.DeploymentModeEnv:        managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv:     managed.ProfileStandalone,
		managed.WindowsServiceAccountEnv: layout.ServiceUser,
	})
	defer restore()
	if err := validateStandaloneGatewayConfig(configPath, layout.DataDir); err != nil {
		return fmt.Errorf("%v; fix the config and run again (nothing was changed)", err)
	}
	return nil
}
