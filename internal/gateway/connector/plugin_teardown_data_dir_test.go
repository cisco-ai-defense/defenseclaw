// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// rel-1-0-6 GAP-0117: `config set data_dir` re-renders the OpenCode (or Amp)
// plugin with the other directory's token path. After data_dir went back,
// uninstall found a plugin that differed from the one this directory's setup
// wrote, kept it as an operator edit and aborted: "managed plugin still
// present". A plugin DefenseClaw created that still carries its ownership
// marker is DefenseClaw's and goes, from either data directory. A file
// without the marker stays.
func TestPluginTeardownAfterADataDirRoundTrip(t *testing.T) {
	for _, name := range []string{"opencode", "amp"} {
		for _, from := range []string{"first", "second"} {
			t.Run(name+"/teardown from the "+from+" data dir", func(t *testing.T) {
				root := testenv.PrivateTempDir(t)
				plugin := filepath.Join(root, "plugins", "defenseclaw.js")
				conn := pluginConnectorAt(t, name, plugin)
				first := pluginTestOpts(t, name, filepath.Join(root, ".defenseclaw"))
				second := pluginTestOpts(t, name, filepath.Join(root, "dcdata"))
				if err := conn.Setup(context.Background(), first); err != nil {
					t.Fatalf("Setup in the first data dir: %v", err)
				}
				if err := conn.Setup(context.Background(), second); err != nil {
					t.Fatalf("Setup in the second data dir: %v", err)
				}
				opts := first
				if from == "second" {
					opts = second
				}
				if err := conn.Teardown(context.Background(), opts); err != nil {
					t.Fatalf("Teardown: %v", err)
				}
				if err := conn.VerifyClean(opts); err != nil {
					t.Fatalf("VerifyClean: %v", err)
				}
				if _, err := os.Stat(plugin); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("the plugin survived the teardown: %v", err)
				}
			})
		}
		t.Run(name+"/an operator file without the marker stays", func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			plugin := filepath.Join(root, "plugins", "defenseclaw.js")
			conn := pluginConnectorAt(t, name, plugin)
			opts := pluginTestOpts(t, name, filepath.Join(root, ".defenseclaw"))
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			const operator = "// my own plugin\nexport default {}\n"
			if err := os.WriteFile(plugin, []byte(operator), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if got := readHookFileForTest(t, plugin); got != operator {
				t.Fatalf("the operator's file changed: %q", got)
			}
		})
	}
}

func pluginConnectorAt(t *testing.T, name, plugin string) Connector {
	t.Helper()
	if name == "amp" {
		previous := AMPPluginPathOverride
		AMPPluginPathOverride = plugin
		t.Cleanup(func() { AMPPluginPathOverride = previous })
		return NewAMPConnector()
	}
	previous := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = plugin
	t.Cleanup(func() { OpenCodePluginPathOverride = previous })
	return NewOpenCodeConnector()
}

func pluginTestOpts(t *testing.T, name, dataDir string) SetupOpts {
	t.Helper()
	opts := SetupOpts{
		DataDir:       dataDir,
		ProxyAddr:     "127.0.0.1:4000",
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "api-token",
		OTLPPathToken: strings.Repeat("a", 64),
	}
	if name == "amp" {
		return prepareAmpSetupOptsForTest(t, opts)
	}
	return prepareOpenCodeSetupOptsForTest(t, opts)
}
