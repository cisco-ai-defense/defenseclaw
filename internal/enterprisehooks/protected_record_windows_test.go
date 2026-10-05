// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"
)

// The unprotected-agents record and the group cache carry the manifest's
// exact SYSTEM and Administrators only protection; a record without it is
// refused, and an unchanged record is not rewritten.
func TestWindowsProtectedRecordsRoundTripUnderTheManifestContract(t *testing.T) {
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	manifest := filepath.Join(dir, "targets.yaml")
	if agents, err := ReadWindowsUnprotectedAgents(manifest); err != nil || len(agents) != 0 {
		t.Fatalf("a missing record is empty: %v %v", agents, err)
	}
	agents := []UnprotectedAgent{{User: "alice", SID: testLocalUserSID, Connector: "cursor", Version: "4.1.0", Reason: "version 4.1.0 is not verified against a known hook contract"}}
	if changed, err := WriteWindowsUnprotectedAgents(manifest, agents); err != nil || !changed {
		t.Fatalf("first write: changed=%t err=%v", changed, err)
	}
	if err := validateWindowsTargetsManifestObject(UnprotectedAgentsPath(manifest), false); err != nil {
		t.Fatalf("record protection: %v", err)
	}
	got, err := ReadWindowsUnprotectedAgents(manifest)
	if err != nil || len(got) != 1 || got[0].Code != UnprotectedCodeHookContractUnverified {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	if changed, err := WriteWindowsUnprotectedAgents(manifest, agents); err != nil || changed {
		t.Fatalf("identical write: changed=%t err=%v", changed, err)
	}

	cache := NewWindowsEnrollmentGroupCache()
	cache.Users[testLocalUserSID] = []string{"S-1-5-32-544"}
	path := WindowsEnrollmentGroupsCachePath(manifest)
	if _, err := SaveWindowsEnrollmentGroupCache(path, cache); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadWindowsEnrollmentGroupCache(path)
	if err != nil || len(loaded.Users[testLocalUserSID]) != 1 {
		t.Fatalf("cache round trip = %+v, %v", loaded, err)
	}

	// A record a user could have planted (default inherited ACL) is refused.
	planted := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(UnprotectedAgentsPath(planted), []byte(`{"version":1,"agents":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadWindowsUnprotectedAgents(planted); err == nil {
		t.Fatal("an unprotected record must be refused")
	}
}
