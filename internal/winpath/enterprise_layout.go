// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Windows enterprise profiles. The names match
// internal/managed.ProfileSecureClient / ProfileStandalone; winpath cannot
// import internal/managed (managed imports winpath), so a test in
// internal/managed pins the equality.
const (
	EnterpriseProfileSecureClient = "secure_client"
	EnterpriseProfileStandalone   = "standalone"

	// EnterpriseProfileEnv mirrors managed.EnterpriseProfileEnv: the
	// administrator-owned service environment pin a standalone service
	// carries next to DEFENSECLAW_DEPLOYMENT_MODE.
	EnterpriseProfileEnv = "DEFENSECLAW_ENTERPRISE_PROFILE"
)

// EnterpriseRoots are one profile's exact machine roots. Every value is an
// absolute Windows path built from already-trusted Program Files and
// ProgramData roots.
type EnterpriseRoots struct {
	Profile                  string
	InstallRoot              string
	StateRoot                string
	CertificationInstallBase string
	CertificationStateBase   string
	ManagedIPCDir            string
	LifecycleDir             string
	MetadataPath             string
	// PowerShellProfile is the install-enterprise.ps1 -EnterpriseProfile
	// value for this profile.
	PowerShellProfile string
}

// EnterpriseRootsFor builds a profile's roots. It is pure (string-only) so
// it is testable on every platform; production callers pass the trusted
// HKLM-registered roots.
func EnterpriseRootsFor(profile, programFiles, programData string) (EnterpriseRoots, error) {
	programFiles = strings.TrimRight(strings.TrimSpace(programFiles), `\`)
	programData = strings.TrimRight(strings.TrimSpace(programData), `\`)
	if !windowsAbsoluteDrivePath(programFiles) || !windowsAbsoluteDrivePath(programData) {
		return EnterpriseRoots{}, fmt.Errorf("enterprise roots require absolute drive paths: %q, %q", programFiles, programData)
	}
	var vendor, powerShell string
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case EnterpriseProfileSecureClient:
		vendor, powerShell = `Cisco\Cisco Secure Client`, "SecureClient"
	case EnterpriseProfileStandalone:
		vendor, powerShell = `Cisco`, "Standalone"
	default:
		return EnterpriseRoots{}, fmt.Errorf("unknown Windows enterprise profile %q", profile)
	}
	join := func(base string, parts ...string) string {
		return base + `\` + strings.Join(parts, `\`)
	}
	state := join(programData, vendor, "DefenseClaw")
	return EnterpriseRoots{
		Profile:                  strings.ToLower(strings.TrimSpace(profile)),
		InstallRoot:              join(programFiles, vendor, "DefenseClaw"),
		StateRoot:                state,
		CertificationInstallBase: join(programFiles, vendor, "DefenseClaw-Cert"),
		CertificationStateBase:   join(programData, vendor, "DefenseClaw-Cert"),
		ManagedIPCDir:            join(programFiles, vendor, "DefenseClaw", "ipc"),
		LifecycleDir:             join(programData, vendor, "DefenseClaw-Lifecycle"),
		MetadataPath:             join(state, "install", "deployment.json"),
		PowerShellProfile:        powerShell,
	}, nil
}

// ValidateEnterpriseInstallRoot accepts exactly the profile's production
// install root or one run-scoped certification root beneath its
// certification base.
func ValidateEnterpriseInstallRoot(roots EnterpriseRoots, root string) error {
	clean := strings.TrimRight(strings.TrimSpace(root), `\`)
	if strings.EqualFold(clean, roots.InstallRoot) {
		return nil
	}
	prefix := roots.CertificationInstallBase + `\`
	if len(clean) > len(prefix) && strings.EqualFold(clean[:len(prefix)], prefix) {
		runID := clean[len(prefix):]
		if len(runID) == 10 && strings.Trim(runID, "0123456789abcdef") == "" {
			return nil
		}
	}
	return fmt.Errorf("Windows enterprise install root %q is neither %q nor a certification root under %q", root, roots.InstallRoot, roots.CertificationInstallBase)
}

func windowsAbsoluteDrivePath(value string) bool {
	if len(value) < 3 || strings.Contains(value, "/") {
		return false
	}
	drive := value[0]
	return ((drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')) &&
		value[1] == ':' && value[2] == '\\'
}

// EnterpriseDeploymentState classifies one profile's deployment metadata.
type EnterpriseDeploymentState string

const (
	EnterpriseDeploymentAbsent    EnterpriseDeploymentState = "absent"
	EnterpriseDeploymentInstalled EnterpriseDeploymentState = "installed"
	// EnterpriseDeploymentTombstone is metadata an uninstall left behind
	// with installed=false; preserved state remains, services do not.
	EnterpriseDeploymentTombstone EnterpriseDeploymentState = "tombstone"
	// EnterpriseDeploymentUnknown is metadata that exists but cannot be
	// read or parsed. Callers treat it as installed.
	EnterpriseDeploymentUnknown EnterpriseDeploymentState = "unknown"
)

// EnterpriseDeployment is one profile's recorded deployment.
type EnterpriseDeployment struct {
	Profile        string
	State          EnterpriseDeploymentState
	MetadataPath   string
	ProductVersion string
	// Untrusted says why a record found at MetadataPath was ignored (State
	// is then EnterpriseDeploymentAbsent): something other than an
	// administrator could have written it.
	Untrusted string
	// TrustMode is the payload trust standalone metadata records
	// ("authenticode" or "hash_pinned"); Secure Client metadata has none.
	TrustMode string
}

// classifyEnterpriseMetadata interprets deployment.json. Metadata without an
// installed field predates uninstall tombstones and means installed.
func classifyEnterpriseMetadata(body []byte) (EnterpriseDeploymentState, string) {
	var record struct {
		Installed      *bool  `json:"installed"`
		ProductVersion string `json:"product_version"`
	}
	trimmed := body
	if len(trimmed) >= 3 && trimmed[0] == 0xef && trimmed[1] == 0xbb && trimmed[2] == 0xbf {
		trimmed = trimmed[3:]
	}
	if err := json.Unmarshal(trimmed, &record); err != nil {
		return EnterpriseDeploymentUnknown, ""
	}
	if record.Installed != nil && !*record.Installed {
		return EnterpriseDeploymentTombstone, record.ProductVersion
	}
	return EnterpriseDeploymentInstalled, record.ProductVersion
}

// enterpriseMetadataTrustMode reads the payload trust deployment.json
// records. The lifecycle keeps admitting a hash-pinned deployment's payload
// by these pins on later runs without a payload manifest, including over an
// uninstall tombstone, so callers read it for both states.
func enterpriseMetadataTrustMode(body []byte) string {
	var record struct {
		TrustMode string `json:"trust_mode"`
	}
	trimmed := body
	if len(trimmed) >= 3 && trimmed[0] == 0xef && trimmed[1] == 0xbb && trimmed[2] == 0xbf {
		trimmed = trimmed[3:]
	}
	if err := json.Unmarshal(trimmed, &record); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(record.TrustMode))
}
