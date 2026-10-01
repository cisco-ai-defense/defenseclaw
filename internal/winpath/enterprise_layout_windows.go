//go:build windows

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
	"errors"
	"fmt"
	"io"
	"os"
)

// enterpriseMetadataLimit bounds the deployment metadata read; the document
// is a few kilobytes.
const enterpriseMetadataLimit = 1 << 20

// TrustedEnterpriseRoots resolves a profile's roots from the protected HKLM
// Program Files and ProgramData registration, never from the caller's
// ProgramFiles/ProgramData environment variables.
func TrustedEnterpriseRoots(profile string) (EnterpriseRoots, error) {
	programFiles, err := TrustedProgramFiles()
	if err != nil {
		return EnterpriseRoots{}, err
	}
	programData, err := TrustedProgramData()
	if err != nil {
		return EnterpriseRoots{}, err
	}
	return EnterpriseRootsFor(profile, programFiles, programData)
}

// InspectEnterpriseDeployment reads one profile's deployment metadata. It
// does not check who wrote the record; lifecycle and guard decisions must go
// through a caller that validates the record's owner and DACL first (see
// internal/cli inspectTrustedWindowsEnterpriseDeployment).
func InspectEnterpriseDeployment(profile string) (EnterpriseDeployment, error) {
	roots, err := TrustedEnterpriseRoots(profile)
	if err != nil {
		return EnterpriseDeployment{}, err
	}
	return InspectEnterpriseDeploymentAt(roots.Profile, roots.MetadataPath)
}

// InspectEnterpriseDeploymentAt classifies the deployment record at an exact
// metadataPath (such as a certification scope's
// <state-root>\install\deployment.json, or a scratch path in goldens and
// tests) the way InspectEnterpriseDeployment classifies a profile's record
// at its trusted path: absent, installed, tombstone, or unknown (an
// unreadable, oversized, or unparseable record). A path that exists but is
// not a regular file (a directory, a link) is an error. Like
// InspectEnterpriseDeployment it does not check who wrote the record.
func InspectEnterpriseDeploymentAt(profile, metadataPath string) (EnterpriseDeployment, error) {
	deployment := EnterpriseDeployment{Profile: profile, MetadataPath: metadataPath}
	info, err := os.Lstat(metadataPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		deployment.State = EnterpriseDeploymentAbsent
		return deployment, nil
	case errors.Is(err, os.ErrPermission):
		// A standard user cannot read the administrator-only record. Its
		// presence is still a deployment for profile selection.
		deployment.State = EnterpriseDeploymentUnknown
		return deployment, nil
	case err != nil:
		return EnterpriseDeployment{}, fmt.Errorf("inspect enterprise deployment metadata %s: %w", metadataPath, err)
	case !info.Mode().IsRegular():
		return EnterpriseDeployment{}, fmt.Errorf("enterprise deployment metadata is not a regular file: %s", metadataPath)
	}
	file, err := os.Open(metadataPath)
	if err != nil {
		deployment.State = EnterpriseDeploymentUnknown
		return deployment, nil
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, enterpriseMetadataLimit+1))
	if err != nil || len(body) > enterpriseMetadataLimit {
		deployment.State = EnterpriseDeploymentUnknown
		return deployment, nil
	}
	deployment.State, deployment.ProductVersion = classifyEnterpriseMetadata(body)
	deployment.TrustMode = enterpriseMetadataTrustMode(body)
	return deployment, nil
}
