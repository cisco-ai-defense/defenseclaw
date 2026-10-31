//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterpriseunix

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// rel-1-0-2 GAP-0599: the purge left DefenseClaw's OpenShell gateway
// lifecycle lock (~/.config/openshell/.defenseclaw-lifecycle.lock) and the
// hook-fire probe folder of image builds (~/.cache/defenseclaw/hookfire,
// ~/Library/Caches/defenseclaw/hookfire on a Mac) in every sandbox account's
// home. Both go, and so do their folders once empty; an OpenShell config
// folder that holds the account's own files stays with them.
func TestSandboxPurgeRemovesTheLifecycleLockAndTheHookFireProbeFolder(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, ownConfig := range []bool{false, true} {
			name := goos + "/only DefenseClaw files"
			if ownConfig {
				name = goos + "/own OpenShell config"
			}
			t.Run(name, func(t *testing.T) {
				h := newOSHost(t, goos)
				home := h.alice.Home
				cache := ".cache"
				if goos == "darwin" {
					cache = "Library/Caches"
				}
				lock := filepath.Join(home, ".config/openshell/.defenseclaw-lifecycle.lock")
				probe := filepath.Join(home, cache, "defenseclaw/hookfire")
				own := filepath.Join(home, ".config/openshell/gateways/own/metadata.json")
				writeHostFile(t, h.testHost, lock, "")
				writeHostFile(t, h.testHost, filepath.Join(probe, "hosts"), "127.0.0.1 localhost\n")
				if ownConfig {
					writeHostFile(t, h.testHost, own, "{}\n")
				}
				l := &lifecycle{env: h.env, result: &enterprisestatus.Result{}}
				l.purgeAccountSandbox(h.alice)
				for _, gone := range []string{lock, probe, filepath.Join(home, cache, "defenseclaw")} {
					if h.exists(gone) {
						t.Errorf("the purge left %s", gone)
					}
				}
				if h.exists(filepath.Join(home, ".config/openshell")) != ownConfig {
					t.Errorf("OpenShell config folder exists = %v, want %v", !ownConfig, ownConfig)
				}
				if ownConfig && h.read(own) != "{}\n" {
					t.Error("the account's own OpenShell config changed")
				}
				if !h.exists(filepath.Join(home, cache)) && goos == "darwin" {
					t.Error("the purge removed the account's Library/Caches")
				}
			})
		}
	}
}
