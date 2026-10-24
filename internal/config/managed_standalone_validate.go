// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ValidateManagedStandaloneConfig checks the config-only constraints of the
// standalone lifecycle. Both bundle validation and ensure use this function;
// ensure additionally checks the device's files, accounts and credentials.
// A missing data_dir is resolved by the device from its fixed layout, while
// an explicitly supplied data_dir must name that layout's service state.
func ValidateManagedStandaloneConfig(raw []byte, cfg *Config, plan *ObservabilityV8Plan, layout managed.StandaloneLayout) error {
	if cfg == nil {
		return fmt.Errorf("config is unavailable")
	}
	if !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return fmt.Errorf("config deployment_mode must be %s", managed.DeploymentModeManagedEnterprise)
	}
	if !cfg.StandaloneEnterprise() {
		return fmt.Errorf("config enterprise.profile must be %s", managed.ProfileStandalone)
	}
	if managed.DefaultEnterpriseProfile(layout.GOOS) != managed.ProfileStandalone &&
		cfg.DeclaredEnterpriseProfile() != managed.ProfileStandalone {
		return fmt.Errorf("config must set enterprise.profile: %s: on %s a process that reads it without the service pin treats an unset profile as %s",
			managed.ProfileStandalone, layout.GOOS, managed.DefaultEnterpriseProfile(layout.GOOS))
	}
	document, err := ParseV8YAML(layout.ConfigPath, raw)
	if err != nil {
		return err
	}
	if _, explicit := document.Plain["data_dir"]; explicit {
		dataDir := cfg.DataDir
		if layout.GOOS == "windows" {
			if !strings.EqualFold(strings.TrimRight(dataDir, `\/`), strings.TrimRight(layout.DataDir, `\/`)) {
				return fmt.Errorf("config data_dir %q must be %s: the service sandbox only allows writes there", dataDir, layout.DataDir)
			}
		} else if strings.TrimRight(dataDir, "/") != layout.DataDir {
			return fmt.Errorf("config data_dir %q must be %s: the service sandbox only allows writes there", dataDir, layout.DataDir)
		}
	}
	if err := ValidateManagedStandaloneListener(cfg, layout.GOOS); err != nil {
		return err
	}
	if err := ValidateManagedGuardrailProxyBind(cfg); err != nil {
		return err
	}
	dirs := cfg.ReferencedRulePackDirs()
	for _, label := range RulePackCheckOrder(dirs) {
		dir := dirs[label]
		if dir = strings.TrimSpace(dir); dir == "" || layout.GOOS == "windows" {
			continue
		}
		clean := filepath.Clean(dir)
		if clean == layout.DataDir || strings.HasPrefix(clean, layout.DataDir+"/") {
			return fmt.Errorf("config %s %q is inside data_dir, which the gateway service can write; use %s or an administrator-owned directory under %s", label, dir, filepath.Join(layout.VendorPolicyDir, "guardrail", "default"), layout.PolicyDir)
		}
	}
	return validateManagedStandaloneJSONL(plan, layout)
}

// ValidateManagedStandaloneListener checks the gateway API listener of a
// standalone config for goos. Every OS refuses a bind other than loopback
// 127.0.0.1. Linux and macOS also refuse a port other than 18970, which their
// socket units own; Windows Setup takes the port chosen before the first
// install, so goos "windows" or "" (an OS not known) skips the port.
func ValidateManagedStandaloneListener(cfg *Config, goos string) error {
	if bind := strings.TrimSpace(cfg.Gateway.APIBind); bind != "" && bind != "127.0.0.1" {
		return fmt.Errorf("config gateway.api_bind %q must be 127.0.0.1", bind)
	}
	if goos != "linux" && goos != "darwin" {
		return nil
	}
	if port := cfg.Gateway.APIPort; port != 0 && port != DefaultGatewayAPIPort {
		return fmt.Errorf("config gateway.api_port %d must be %d on %s: the socket unit owns that listener", port, DefaultGatewayAPIPort, goos)
	}
	return nil
}

// validateManagedStandaloneJSONL checks the path restriction imposed by the
// Linux gateway service sandbox. Ensure separately checks the target file,
// its parents, ownership, ACLs and service-account access on the device.
func validateManagedStandaloneJSONL(plan *ObservabilityV8Plan, layout managed.StandaloneLayout) error {
	if plan == nil || layout.GOOS != "linux" {
		return nil
	}
	within := func(path, root string) bool {
		return path == root || strings.HasPrefix(path, strings.TrimRight(root, "/")+"/")
	}
	for _, destination := range plan.Destinations() {
		if destination.Kind != ObservabilityV8DestinationJSONL || !destination.Enabled || destination.Generated {
			continue
		}
		path := filepath.Clean(destination.Transport.Path)
		if !within(path, layout.DataDir) && !within(path, layout.LogDir) {
			return fmt.Errorf("observability destination %q writes %s, outside the folders the gateway service may write (%s and %s); use a path in one of them",
				destination.Name, path, layout.DataDir, layout.LogDir)
		}
	}
	return nil
}
