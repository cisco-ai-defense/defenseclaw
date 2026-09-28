// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestFreshIdentityManagedServiceDirectoryIsStandaloneOnly(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\DefenseClawGateway`)

	t.Setenv(managed.EnterpriseProfileEnv, "")
	if handled, err := validateFreshIdentityManagedServiceDirectory(dir); handled || err != nil {
		t.Fatalf("Secure Client service = (%v, %v), want the private-directory check unchanged", handled, err)
	}

	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	handled, err := validateFreshIdentityManagedServiceDirectory(dir)
	if !handled || err == nil {
		t.Fatalf("standalone service on an untrusted temp dir = (%v, %v), want handled and refused", handled, err)
	}

	t.Setenv(managed.WindowsServiceAccountEnv, "")
	if handled, err := validateFreshIdentityManagedServiceDirectory(dir); handled || err != nil {
		t.Fatalf("standalone pin without a service account = (%v, %v), want not handled", handled, err)
	}
}

func TestFreshIdentityManagedServiceFileIsStandaloneOnly(t *testing.T) {
	path := t.TempDir() + `\device.key`
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.WindowsServiceAccountEnv, `NT SERVICE\DefenseClawGateway`)
	t.Setenv(managed.EnterpriseProfileEnv, "")
	if handled, err := writeFreshIdentityManagedServiceFile(path, []byte("x")); handled || err != nil {
		t.Fatalf("Secure Client service = (%v, %v), want the private writer unchanged", handled, err)
	}
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	if handled, err := writeFreshIdentityManagedServiceFile(path, []byte("x")); !handled || err == nil {
		t.Fatalf("standalone service in an untrusted temp dir = (%v, %v), want handled and refused before writing", handled, err)
	}
}
