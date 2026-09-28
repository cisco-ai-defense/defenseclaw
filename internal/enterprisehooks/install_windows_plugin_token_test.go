// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// windowsGenericPluginTokenTestConnector stands in for an in-agent plugin
// connector (Amp, OpenCode): it requires a connector-scoped token sidecar,
// which its own setup never writes.
type windowsGenericPluginTokenTestConnector struct {
	windowsGenericCodexTestConnector
}

func (c *windowsGenericPluginTokenTestConnector) RequiresScopedHookToken() bool { return true }

func (c *windowsGenericPluginTokenTestConnector) Setup(ctx context.Context, opts connector.SetupOpts) error {
	if err := c.windowsGenericCodexTestConnector.Setup(ctx, opts); err != nil {
		return err
	}
	path, err := connector.HookTokenFilePath(filepath.Join(opts.DataDir, "hooks"), c.Name())
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Live on Windows Server 2025 the standalone guardian enrolled Amp and
// OpenCode but never published the token sidecar their plugins read, so every
// Amp and OpenCode tool call failed closed with "DefenseClaw hook credential
// is unavailable". The guardian now publishes it, and verification binds it.
func TestWindowsGenericInstallPublishesThePluginScopedToken(t *testing.T) {
	fixture := newWindowsGenericCodexFixture(t)
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(&windowsGenericPluginTokenTestConnector{
		windowsGenericCodexTestConnector{configPath: fixture.config},
	})
	opts := fixture.opts
	opts.Registry = registry
	if _, err := installWindowsGenericManagedResult(context.Background(), opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	tokenPath, err := connector.HookTokenFilePath(filepath.Join(fixture.home, ".defenseclaw", "hooks"), windowsGenericTestConnectorName)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("plugin token sidecar was not published: %v", err)
	}
	if strings.TrimSpace(string(body)) != opts.APIToken {
		t.Fatal("published plugin token sidecar does not carry the connector-scoped token")
	}
	if _, err := verifyWindowsGenericManagedResult(context.Background(), opts); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyWindowsGenericManagedResult(context.Background(), opts); err == nil ||
		!strings.Contains(err.Error(), "connector-scoped token") {
		t.Fatalf("Verify without the plugin token sidecar: %v", err)
	}
}

func TestPublishWindowsPluginScopedHookTokenOnlyForPluginConnectors(t *testing.T) {
	original := publishEnterpriseHookAPIToken
	t.Cleanup(func() { publishEnterpriseHookAPIToken = original })
	var calls []string
	publishEnterpriseHookAPIToken = func(dataDir, name, token string) error {
		calls = append(calls, dataDir+"|"+name+"|"+token)
		return nil
	}
	target := windowsGenericManagedTarget{
		conn:    &windowsGenericCodexTestConnector{},
		dataDir: `C:\Users\u\.defenseclaw`,
		setup:   connector.SetupOpts{HookAPIToken: strings.Repeat("a", 64)},
	}
	if err := publishWindowsPluginScopedHookToken(target); err != nil || len(calls) != 0 {
		t.Fatalf("hook connector: err=%v calls=%v", err, calls)
	}
	target.conn = &windowsGenericPluginTokenTestConnector{}
	if err := publishWindowsPluginScopedHookToken(target); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0] != `C:\Users\u\.defenseclaw|codex|`+strings.Repeat("a", 64) {
		t.Fatalf("plugin connector publish calls %v", calls)
	}
}
