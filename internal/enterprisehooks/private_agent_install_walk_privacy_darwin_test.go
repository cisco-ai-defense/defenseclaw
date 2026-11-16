// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package enterprisehooks

import (
	"path/filepath"
	"testing"
)

// On macOS 15 an account without a GUI session waits on these folders too:
// each open() returns EINTR after about 13 s, which os.Open retries, so the
// home walk timed out and every managed account stayed
// agent_install_scan_incomplete (GAP-1603). They are not opened, as the other
// privacy-protected folders are not.
func TestUnixPrivateWalkSkipsTheFoldersMacOSHoldsWithoutAGUISession(t *testing.T) {
	home := "/Users/alice"
	for _, rel := range []string{"Library/Autosave Information", "Library/ContainerManager", "Library/Caches/com.apple.containermanagerd", "Desktop", "library/mail"} {
		if !unixPrivateWalkPrivacyProtected(home, filepath.Join(home, rel)) {
			t.Errorf("%s is opened by the home walk", rel)
		}
	}
	for _, rel := range []string{"Library", "Library/Caches", "projects/node_modules"} {
		if unixPrivateWalkPrivacyProtected(home, filepath.Join(home, rel)) {
			t.Errorf("%s is skipped by the home walk", rel)
		}
	}
}
