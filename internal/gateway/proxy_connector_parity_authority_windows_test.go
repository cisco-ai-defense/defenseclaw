// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// prepareProxyConnectorSwitchAuthorityFixture gives the two native Windows
// connectors whose setup is executable-authority gated the same protected,
// short-lived setup evidence produced by the installer path. The production
// admission checks remain active; these parity tests must satisfy them rather
// than bypass them.
func prepareProxyConnectorSwitchAuthorityFixture(
	t *testing.T,
	target string,
	opts *connector.SetupOpts,
) {
	t.Helper()
	if opts == nil {
		t.Fatal("proxy connector switch authority fixture received nil setup options")
	}

	if target != "opencode" && target != "amp" {
		return
	}
	realLocalAppData, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	if err != nil || strings.TrimSpace(realLocalAppData) == "" {
		t.Fatalf("resolve current-user LocalAppData for connector authority fixture: %v", err)
	}
	previousLocalAppData, hadLocalAppData := os.LookupEnv("LOCALAPPDATA")
	if err := os.Setenv("LOCALAPPDATA", realLocalAppData); err != nil {
		t.Fatalf("bind current-user LocalAppData for connector authority fixture: %v", err)
	}
	defer func() {
		var restoreErr error
		if hadLocalAppData {
			restoreErr = os.Setenv("LOCALAPPDATA", previousLocalAppData)
		} else {
			restoreErr = os.Unsetenv("LOCALAPPDATA")
		}
		if restoreErr != nil {
			t.Errorf("restore hermetic LocalAppData after connector authority fixture: %v", restoreErr)
		}
	}()

	// applyHermeticConnectorHomes intentionally points LOCALAPPDATA beneath a
	// Go test temp tree. That tree has service-runner write ACEs and therefore
	// cannot be executable custody. Keep connector config paths hermetic, but
	// place the protected authority state under the actual current-user known
	// folder, matching the native installer topology.
	opts.DataDir = testenv.PrivateTempDir(t)

	var authority connector.SetupOpts
	switch target {
	case "opencode":
		pluginRoot := testenv.PrivateTempDir(t)
		previousPluginPath := connector.OpenCodePluginPathOverride
		connector.OpenCodePluginPathOverride = filepath.Join(pluginRoot, "plugins", "defenseclaw.js")
		t.Cleanup(func() { connector.OpenCodePluginPathOverride = previousPluginPath })
		authority = prepareOpenCodeSetupAuthorityFixture(t, opts.DataDir)
	case "amp":
		authority = prepareAmpGatewayAuthorityFixture(t, opts.DataDir).opts
	}

	opts.AgentVersion = authority.AgentVersion
	opts.AgentExecutable = authority.AgentExecutable
	opts.HookContractID = authority.HookContractID
}
