// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// awaitingSignInTestPlatformSetup lets the manifest carry the Windows
// standalone enumerator's deferred rows off Windows.
func awaitingSignInTestPlatformSetup(t *testing.T) {
	t.Helper()
	previous := enterprisehooks.StandaloneUnix()
	t.Cleanup(func() { enterprisehooks.SetStandaloneUnix(previous) })
	enterprisehooks.SetStandaloneUnix(true)
}

func awaitingSignInManifestTarget(home, sid, connectorName string) string {
	return fmt.Sprintf(
		"  - user_home: %q\n    uid: %d\n    gid: %d\n    sid: %s\n    connector: %s\n    enabled: true\n    deferred: true\n",
		home, os.Getuid(), os.Getgid(), sid, connectorName)
}

// awaitingSignInDesiredEnrollment is the enabled set the Windows exact
// publication and verify use (windowsEnterpriseDesiredEnrollments there).
func awaitingSignInDesiredEnrollment(t *testing.T, manifest enterprisehooks.Manifest) awaitingSignInEnrollmentStore {
	t.Helper()
	desired := awaitingSignInEnrollmentStore{"claudecode": {}, "codex": {}}
	for _, target := range manifest.Targets {
		if target.IsEnabled() {
			desired.enroll(strings.TrimSpace(target.Connector), strings.TrimSpace(target.SID))
		}
	}
	return desired
}
