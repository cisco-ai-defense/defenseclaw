// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func awaitingSignInTestPlatformSetup(*testing.T) {}

func awaitingSignInManifestTarget(home, sid, connectorName string) string {
	version := "2.1.187"
	if connectorName == "codex" {
		version = "0.200.0"
	}
	return fmt.Sprintf(
		"  - user_home: %q\n    sid: %s\n    connector: %s\n    agent_version: %s\n    enabled: true\n    deferred: true\n",
		home, sid, connectorName, version)
}

// awaitingSignInDesiredEnrollment is the enabled set the exact publication
// and verify use: windowsEnterpriseDesiredEnrollments itself.
func awaitingSignInDesiredEnrollment(t *testing.T, manifest enterprisehooks.Manifest) awaitingSignInEnrollmentStore {
	t.Helper()
	claude, codex, err := windowsEnterpriseDesiredEnrollments(manifest)
	if err != nil {
		t.Fatal(err)
	}
	desired := awaitingSignInEnrollmentStore{"claudecode": {}, "codex": {}}
	for _, sid := range claude {
		desired.enroll("claudecode", sid)
	}
	for _, target := range codex {
		desired.enroll("codex", target.SID)
	}
	return desired
}
