// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// scripts/hermes_vendor_plugin_digests.py runs TestGenerateHermesVendorPluginDigests
// with these flags to regenerate hermes_vendor_plugin_digests.go. The digests
// come from the code that decides admission (the rescan enumerator and
// hermesPluginTreeDigest), so they are the digests the gateway computes.
var (
	hermesVendorTrees = flag.String("hermes-vendor-trees", "",
		"folder with one release checkout per Hermes release: <release>/hermes-agent/plugins")
	hermesVendorOut = flag.String("hermes-vendor-out", "",
		"JSON file the shipped-plugin digests of every release are written to")
)

// TestGenerateHermesVendorPluginDigests lists the shipped plugins of every
// release checkout under -hermes-vendor-trees as the rescan does and writes
// {release: {plugin: digest}} to -hermes-vendor-out. A plugin whose tree
// cannot be verified (a link, a special file, an oversize tree) gets an empty
// digest: no copy of it can match, so the tool leaves it out. Without the
// flags the test is skipped.
func TestGenerateHermesVendorPluginDigests(t *testing.T) {
	if *hermesVendorTrees == "" || *hermesVendorOut == "" {
		t.Skip("run by scripts/hermes_vendor_plugin_digests.py")
	}
	t.Setenv("HERMES_BUNDLED_PLUGINS", "")
	releases, err := os.ReadDir(*hermesVendorTrees)
	if err != nil {
		t.Fatal(err)
	}
	// A release checkout has no bytecode cache, so the digest reads no
	// manifest; a call means the tree is not a clean checkout.
	noCache := func(map[string][]byte) ([]string, error) {
		return nil, errors.New("a Hermes release checkout has no bytecode cache")
	}
	out := map[string]map[string]string{}
	for _, release := range releases {
		if !release.IsDir() {
			continue
		}
		root := filepath.Join(*hermesVendorTrees, release.Name(), "hermes-agent", "plugins")
		cfg, store, logger, _ := setupTestEnv(t)
		w := New(cfg, nil, []string{root}, store, logger, nil, nil)
		w.SetRootConnectors(map[string]string{root: "hermes"})
		digests := map[string]string{}
		for _, evt := range w.enumerateTargets() {
			if evt.Type != InstallPlugin {
				continue
			}
			name, ok := w.hermesShippedPlugin(evt)
			if !ok {
				t.Fatalf("release %s: %s is not a shipped plugin of %s", release.Name(), evt.Path, root)
			}
			digest, err := hermesPluginTreeDigest(evt.Path, noCache)
			if err != nil {
				t.Logf("release %s: %s cannot be verified: %v", release.Name(), name, err)
				digest = ""
			}
			digests[name] = digest
		}
		if len(digests) == 0 {
			t.Fatalf("release %s: no shipped plugins under %s", release.Name(), root)
		}
		out[release.Name()] = digests
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(*hermesVendorOut, append(data, 10), 0o600); err != nil {
		t.Fatal(err)
	}
}
