// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookcli"
)

// isolateOutageHostMarkers makes the build or test host's own machine
// markers (a managed Setup, Secure Client) absent, so the cases read the
// same on a managed lane host as on a build box.
func isolateOutageHostMarkers(t *testing.T) {
	t.Helper()
	oldDescriptor, oldWindows := hookcli.ManagedHostDescriptorPath, hookcli.ManagedHostWindowsStandalone
	oldSecureClient, oldUncertain := hookcli.SecureClientHost, hookcli.ManagedHostWindowsMarkerUncertain
	missing := filepath.Join(t.TempDir(), "no-runtime-descriptor")
	hookcli.ManagedHostDescriptorPath = func() string { return missing }
	hookcli.ManagedHostWindowsStandalone = func() (string, bool) { return "", false }
	hookcli.SecureClientHost = func() bool { return false }
	hookcli.ManagedHostWindowsMarkerUncertain = func() bool { return false }
	t.Cleanup(func() {
		hookcli.ManagedHostDescriptorPath, hookcli.ManagedHostWindowsStandalone = oldDescriptor, oldWindows
		hookcli.SecureClientHost, hookcli.ManagedHostWindowsMarkerUncertain = oldSecureClient, oldUncertain
	})
}

func stubOutageInstallFolders(t *testing.T, account func() string, state func() (string, bool)) {
	t.Helper()
	oldAccount, oldState := hookcli.OutageAccountHome, hookcli.OutageInstalledDataRoot
	hookcli.OutageAccountHome, hookcli.OutageInstalledDataRoot = account, state
	t.Cleanup(func() { hookcli.OutageAccountHome, hookcli.OutageInstalledDataRoot = oldAccount, oldState })
}
