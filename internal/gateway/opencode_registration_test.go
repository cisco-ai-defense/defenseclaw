// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Regression for #743: OpenCode's auto-loaded JavaScript policy is a managed
// plugin artifact, not a shell-hook config document. Gateway readiness must
// reach the managed receipt/digest inspector and recognize the exact v7 bridge
// Setup just published.
func TestVerifyEffectiveHookRegistrationAcceptsOpenCodeManagedV7Plugin(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	pluginPath := filepath.Join(root, ".config", "opencode", "plugins", "defenseclaw.js")
	previousPath := connector.OpenCodePluginPathOverride
	connector.OpenCodePluginPathOverride = pluginPath
	t.Cleanup(func() { connector.OpenCodePluginPathOverride = previousPath })

	conn := connector.NewOpenCodeConnector()
	opts := connector.SetupOpts{
		DataDir:      filepath.Join(root, "state"),
		APIAddr:      "127.0.0.1:18970",
		HookFailMode: "closed",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("OpenCode Setup: %v", err)
	}
	body, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatalf("read managed OpenCode plugin: %v", err)
	}
	if !bytes.Contains(body, []byte("// defenseclaw-managed-plugin v7")) {
		t.Fatal("OpenCode Setup did not publish the exact managed v7 marker")
	}
	if err := verifyEffectiveHookRegistration(opts, conn); err != nil {
		t.Fatalf("verifyEffectiveHookRegistration rejected Setup's managed v7 plugin: %v", err)
	}
}
