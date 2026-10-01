// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"fmt"
	"strings"
)

// Enterprise profiles select who decides verdicts and which integration a
// managed_enterprise deployment carries. The deployment mode alone keeps
// meaning "administrator-owned services, protected config, guardian-owned
// hooks"; the profile layers the decision and identity stack on top.
const (
	// EnterpriseProfileEnv pins the profile in every managed service
	// environment, next to DeploymentModeEnv. Like the mode pin, a
	// user-writable config cannot override it.
	EnterpriseProfileEnv = "DEFENSECLAW_ENTERPRISE_PROFILE"

	// ProfileSecureClient is the Cisco Secure Client (AVC) deployment:
	// Cisco AI Defense is the only decision-maker, authenticated with the
	// Secure Client CMID provider. It is the default on Windows and macOS
	// so an existing managed config without an enterprise block keeps its
	// exact behavior.
	ProfileSecureClient = "secure_client"

	// ProfileStandalone is deployable by any MDM: the local policy engine
	// decides, optionally augmented by Cisco AI Defense through an
	// administrator-provisioned API key.
	ProfileStandalone = "standalone"
)

// NormalizeEnterpriseProfile trims and lowercases a profile value. Unknown
// values are returned unchanged so validation can name them.
func NormalizeEnterpriseProfile(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// DefaultEnterpriseProfile is the profile of a managed deployment whose
// service pin and config are both silent. Linux has no Secure Client
// integration, so it is standalone; Windows and macOS keep Secure Client.
func DefaultEnterpriseProfile(goos string) string {
	if goos == "linux" {
		return ProfileStandalone
	}
	return ProfileSecureClient
}

// ResolveEnterpriseProfile returns the effective profile for a deployment.
// A non-managed deployment has no profile and may not name one; a managed
// deployment resolves pin, then config, then the per-OS default, and the pin
// and config must agree when both are set.
func ResolveEnterpriseProfile(goos, deploymentMode, pinned, configured string) (string, error) {
	pinned = NormalizeEnterpriseProfile(pinned)
	configured = NormalizeEnterpriseProfile(configured)
	if !IsManagedEnterprise(deploymentMode) {
		if pinned != "" {
			return "", fmt.Errorf("%s=%q requires deployment_mode %s", EnterpriseProfileEnv, pinned, DeploymentModeManagedEnterprise)
		}
		if configured != "" {
			return "", fmt.Errorf("enterprise.profile=%q requires deployment_mode %s", configured, DeploymentModeManagedEnterprise)
		}
		return "", nil
	}
	for _, candidate := range []struct{ name, value string }{
		{EnterpriseProfileEnv, pinned},
		{"enterprise.profile", configured},
	} {
		if candidate.value == "" {
			continue
		}
		if candidate.value != ProfileSecureClient && candidate.value != ProfileStandalone {
			return "", fmt.Errorf("%s=%q is not a supported enterprise profile (want %s or %s)", candidate.name, candidate.value, ProfileSecureClient, ProfileStandalone)
		}
	}
	if pinned != "" && configured != "" && pinned != configured {
		return "", fmt.Errorf("enterprise.profile=%q conflicts with immutable %s=%q", configured, EnterpriseProfileEnv, pinned)
	}
	profile := pinned
	if profile == "" {
		profile = configured
	}
	if profile == "" {
		profile = DefaultEnterpriseProfile(goos)
	}
	if goos == "linux" && profile == ProfileSecureClient {
		return "", fmt.Errorf("enterprise profile %s is not available on Linux; use %s", ProfileSecureClient, ProfileStandalone)
	}
	return profile, nil
}

// IsStandaloneProfile reports whether a resolved profile is standalone.
func IsStandaloneProfile(profile string) bool {
	return NormalizeEnterpriseProfile(profile) == ProfileStandalone
}

// IsSecureClientProfile reports whether a resolved profile is Secure Client.
func IsSecureClientProfile(profile string) bool {
	return NormalizeEnterpriseProfile(profile) == ProfileSecureClient
}
