// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestWindowsManagedRotationRestoreBind(t *testing.T) {
	target := enterpriseHookRotationTarget{
		User:             "alice",
		UserHome:         filepath.Join(string(filepath.Separator), "Users", "alice"),
		SID:              "S-1-5-21-1",
		Connector:        "codex",
		TokenFingerprint: strings.Repeat("ab", 32),
	}
	expectedPath, err := connector.HookAPITokenFilePath(enterpriseHookRotationUserDataDir(target), target.Connector)
	if err != nil {
		t.Fatalf("HookAPITokenFilePath: %v", err)
	}
	record := windowsManagedRotationSecretRecord{
		Target: target,
		Artifact: windowsManagedRotationSnapshot{
			Path:    expectedPath,
			Present: true,
			Identity: windowsManagedRotationFileIdentity{
				VolumeSerial:  1,
				FileIndexHigh: 0,
				FileIndexLow:  2,
				CanonicalPath: expectedPath,
			},
		},
	}
	if err := bindWindowsManagedRotationRestore(record, target); err != nil {
		t.Fatalf("valid restore bind: %v", err)
	}

	other := target
	other.User = "bob"
	if err := bindWindowsManagedRotationRestore(record, other); err == nil || !strings.Contains(err.Error(), "target does not match") {
		t.Fatalf("target mismatch error = %v", err)
	}

	wrongPath := record
	wrongPath.Artifact.Path = filepath.Join(string(filepath.Separator), "tmp", "other.token")
	if err := bindWindowsManagedRotationRestore(wrongPath, target); err == nil || !strings.Contains(err.Error(), "path does not match") {
		t.Fatalf("path mismatch error = %v", err)
	}

	missingIdentity := record
	missingIdentity.Artifact.Identity = windowsManagedRotationFileIdentity{}
	if err := bindWindowsManagedRotationRestore(missingIdentity, target); err == nil || !strings.Contains(err.Error(), "file identity") {
		t.Fatalf("missing identity error = %v", err)
	}

	missingCanonical := record
	missingCanonical.Artifact.Identity.CanonicalPath = ""
	if err := bindWindowsManagedRotationRestore(missingCanonical, target); err == nil || !strings.Contains(err.Error(), "canonical path") {
		t.Fatalf("missing canonical path error = %v", err)
	}

	absent := record
	absent.Artifact.Present = false
	absent.Artifact.Identity = windowsManagedRotationFileIdentity{}
	if err := bindWindowsManagedRotationRestore(absent, target); err != nil {
		t.Fatalf("absent A restore bind: %v", err)
	}
}
