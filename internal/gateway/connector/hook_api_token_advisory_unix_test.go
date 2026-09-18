// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func captureConnectorTrustAdvisories(t *testing.T) *[]string {
	t.Helper()
	advisories := make([]string, 0, 4)
	previous := managed.ReportTrustAdvisory
	managed.ReportTrustAdvisory = func(path, label, reason string) {
		advisories = append(advisories, strings.Join([]string{path, label, reason}, " | "))
	}
	t.Cleanup(func() { managed.ReportTrustAdvisory = previous })
	return &advisories
}

// AIFW-34262: an ancestor inside the AVC-owned Cisco tree must not stop the
// gateway from binding its hook API, but the named directory and ancestors
// outside that tree keep refusing.
func TestHookAPIDirectoryMetadataAdvisoryAncestor(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}

	if err := hookAPIValidateDirectoryMetadata(dir, info, false, false); err == nil {
		t.Fatal("group/other writable directory accepted as a named path")
	}

	advisories := captureConnectorTrustAdvisories(t)
	if err := hookAPIValidateDirectoryMetadata(dir, info, false, true); err != nil {
		t.Fatalf("advisory ancestor refused instead of warning: %v", err)
	}
	if len(*advisories) != 1 {
		t.Fatalf("advisories = %v, want exactly one", *advisories)
	}
	if !strings.Contains((*advisories)[0], dir) ||
		!strings.Contains((*advisories)[0], "hook API token path") {
		t.Fatalf("advisory %q does not name the path and label", (*advisories)[0])
	}

	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	if err := hookAPIValidateDirectoryMetadata(dir, info, false, true); err == nil {
		t.Fatal("strict pin did not restore the fatal ancestor verdict")
	}
}

// The relaxation is scoped to the platform installer's tree, so a world-writable
// ancestor anywhere else — a shared temp or home directory above a per-user
// runtime path — is still fatal.
func TestHookAPIDirectoryChainKeepsForeignAncestorsFatal(t *testing.T) {
	if managed.PlatformInstallerOwnedPath(t.TempDir()) {
		t.Skip("test temp dir is inside the platform installer tree")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	child := parent + "/runtime"
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	advisories := captureConnectorTrustAdvisories(t)
	err := hookAPIValidateDirectoryChain(child)
	if err == nil {
		t.Fatal("world-writable non-Cisco ancestor was accepted")
	}
	if !strings.Contains(err.Error(), parent) {
		t.Fatalf("error %v does not name the offending ancestor %s", err, parent)
	}
	if len(*advisories) != 0 {
		t.Fatalf("foreign ancestor emitted advisories: %v", *advisories)
	}
}
