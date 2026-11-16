//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"path/filepath"
	"strings"
	"testing"
)

// The macOS drift handling belongs to the Secure Client profile. A process
// that pins the standalone profile keeps the strict verdicts.
func TestStandaloneProfileKeepsDarwinTrustVerdictsStrict(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "")
	notAdminForTest(t)
	captureResilienceEvents(t)
	path := filepath.Join(t.TempDir(), "targets.yaml")
	writeTestFile(t, path, 0o666)
	if err := ValidateTrustedPolicyFilePath(path, "manifest"); err != nil {
		t.Fatalf("Secure Client policy validation refused permission drift: %v", err)
	}

	t.Setenv(EnterpriseProfileEnv, ProfileStandalone)
	if err := ValidateTrustedPolicyFilePath(path, "manifest"); err == nil {
		t.Error("standalone policy validation accepted a world-writable file")
	}
	if err := ValidateExecutableFilePath(path, "fixture"); err == nil {
		t.Error("standalone executable validation accepted a world-writable file")
	}
	if err := AcceptTrustedFileDrift(path, "record"); err == nil {
		t.Error("standalone record validation accepted a world-writable file")
	}
	if err := validateExistingServiceRuntimeFile(path, "gateway dotenv", ""); err == nil {
		t.Error("standalone runtime file validation accepted a world-writable file")
	}
	for _, root := range []string{"/", "/opt"} {
		if AdvisoryAncestorPath(root) {
			t.Errorf("AdvisoryAncestorPath(%s) = true for a standalone process", root)
		}
	}
}

func TestStandaloneProfileHasNoPinnedServiceLayout(t *testing.T) {
	t.Setenv(DeploymentModeEnv, DeploymentModeManagedEnterprise)
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	t.Setenv(EnterpriseProfileEnv, "")
	if _, ok := PinnedManagedServiceLayout(); !ok {
		t.Fatal("the Secure Client service layout was not derived")
	}
	t.Setenv(EnterpriseProfileEnv, ProfileStandalone)
	if layout, ok := PinnedManagedServiceLayout(); ok {
		t.Fatalf("a standalone service got the Secure Client repair layout %+v", layout)
	}
}

func TestStandaloneProfileKeepsTheStrictDarwinACLRule(t *testing.T) {
	path := t.TempDir()
	addDarwinACL(t, path, "admin allow add_file,delete_child")
	darwinACLVerdicts, darwinStrictACLVerdicts = aclVerdictCache{}, aclVerdictCache{}
	t.Cleanup(func() { darwinACLVerdicts, darwinStrictACLVerdicts = aclVerdictCache{}, aclVerdictCache{} })

	if err := validateTrustedPathACL(path); err != nil {
		t.Fatalf("Secure Client trust walk refused an admin ACL entry: %v", err)
	}
	if err := ValidatePathACL(path); err == nil || !strings.Contains(err.Error(), "write-capable macOS ACL") {
		t.Fatalf("ValidatePathACL = %v, want main's strict refusal", err)
	}
	t.Setenv(EnterpriseProfileEnv, ProfileStandalone)
	if err := validateTrustedPathACL(path); err == nil || !strings.Contains(err.Error(), "write-capable macOS ACL") {
		t.Fatalf("standalone trust walk = %v, want the strict refusal", err)
	}
}
