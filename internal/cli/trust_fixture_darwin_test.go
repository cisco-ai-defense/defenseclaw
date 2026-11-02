// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cli

import (
	"os/exec"
	"testing"
)

// untrustedWriterAcceptedAsBoundary: on macOS the managed trust check for a
// policy or config file accepts an untrusted writer as permission drift and
// logs a MarkerBoundary finding instead of refusing it, so drift never stops
// the services.
const untrustedWriterAcceptedAsBoundary = true

// grantUntrustedWriterForTest gives everyone write access to path through an
// ACL entry. The test user is often an administrator, whose ownership the
// trust check accepts as drift, so a fixture relying on the owner alone
// proves nothing; everyone is a standard-user writer on every runner.
func grantUntrustedWriterForTest(t *testing.T, path string) {
	t.Helper()
	if output, err := exec.Command("/bin/chmod", "+a", "everyone allow write,append", path).CombinedOutput(); err != nil {
		t.Fatalf("grant untrusted writer: %v: %s", err, output)
	}
}
