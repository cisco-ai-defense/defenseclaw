// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"path/filepath"
	"testing"
)

func TestLegacyEditorDetectorKeepsOperatorPackExtension(t *testing.T) {
	home := t.TempDir()
	mustWrite(t, filepath.Join(home, ".vscode", "extensions", "anthropic.claude-code-2.0.0", "package.json"), "{}")
	svc := &ContinuousDiscoveryService{
		opts:    AIDiscoveryOptions{HomeDir: home, HomeDirs: []string{home}, SecureClient: true},
		catalog: []AISignature{{ID: "operator-claude", ExtensionIDs: []string{"anthropic.claude-code"}}},
	}
	got := svc.detectEditorExtensionsLegacy()
	if len(got) != 1 || got[0].SignatureID != "operator-claude" {
		t.Fatalf("operator pack extension signals = %+v", got)
	}
}
