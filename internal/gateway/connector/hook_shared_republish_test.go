// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// The shared-script republish finds the installer's own render for every
// managed profile, the standalone one with its privileged host shebang
// included, so a digest-drifted shared script on a standalone install is
// rewritten instead of matching no profile.
func TestManagedSharedHookScriptsMatchingPinsFindsTheInstalledRender(t *testing.T) {
	const apiAddr = "127.0.0.1:18970"
	for _, profile := range []struct {
		name                     string
		secureClient, scDelivery bool
	}{
		{"standalone", false, false},
		{"secure client", true, false},
		{"secure client delivery", true, true},
	} {
		installed, err := renderHookScripts(apiAddr, "closed", "", nil, true, "claudecode", true, "", "",
			profile.secureClient, profile.scDelivery, "")
		if err != nil {
			t.Fatalf("%s: render: %v", profile.name, err)
		}
		pins := make(map[string]string, len(genericHookScripts))
		for _, script := range installed[:len(genericHookScripts)] {
			sum := sha256.Sum256(script.body)
			pins[script.name] = "sha256:" + hex.EncodeToString(sum[:])
		}
		got, err := managedSharedHookScriptsMatchingPins(apiAddr, pins)
		if err != nil {
			t.Fatalf("%s: %v", profile.name, err)
		}
		for i, file := range got {
			if file.Name != installed[i].name || !bytes.Equal(file.Data, installed[i].body) {
				t.Fatalf("%s: republish render of %s differs from the installed one", profile.name, file.Name)
			}
		}
	}
}
