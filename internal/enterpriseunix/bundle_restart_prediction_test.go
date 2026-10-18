// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// The restart prediction of bundle verify on Linux and macOS (the installed
// config.yaml against the config Verify rendered, classified with
// configwrite.ManagedConfigRestartRequired, the call hotConfigApply makes)
// is what the apply then does: a hot bundle keeps the gateway running
// (receipt restart false), a restart-required one restarts it.
func TestBundleVerifyPredictionMatchesTheApply(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, v2, restart := bundleConfigs(b.testHost)
			b.mapPromotedBundleOwners(1)
			requireOK(t, b.apply(b.dir(1, v1)))
			for _, tc := range []struct {
				version uint64
				config  string
				restart bool
			}{{2, v2, false}, {3, restart, true}} {
				predicted := b.predictRestart(tc.version, tc.config)
				if predicted != tc.restart {
					t.Fatalf("version %d: predicted restart %v, want %v", tc.version, predicted, tc.restart)
				}
				b.mapPromotedBundleOwners(tc.version)
				requireOK(t, b.apply(b.dir(tc.version, tc.config)))
				if rc := b.receipt(bundleID(tc.version)); rc.Restart != predicted {
					t.Fatalf("version %d: predicted restart %v, the apply recorded %v", tc.version, predicted, rc.Restart)
				}
			}
		})
	}
}

// predictRestart runs what bundle verify --json runs on this device for a
// bundle of cfg: Verify with the device layout, then the classifier on the
// installed config.yaml and the rendered config.
func (b *bundleHost) predictRestart(version uint64, cfg string) bool {
	t := b.t
	t.Helper()
	installed, err := os.ReadFile(b.env.P(b.env.Layout.ConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	anchors, err := enterprisebundle.LoadAnchors(b.env.bundleAnchorsPath(), nil)
	if err != nil {
		t.Fatal(err)
	}
	layout := enterprisebundle.DeviceLayoutFromManaged(b.env.Layout)
	res, err := enterprisebundle.Verify(context.Background(), enterprisebundle.VerifyInput{
		Bundle: b.signed(version, cfg), Anchors: anchors, Platform: b.env.GOOS, Now: b.env.Now().UTC(),
		Confirmed: b.state().Confirmed(), ProductVersion: b.env.ProductVersion, DeviceLayout: &layout,
		Stage: func(bundle *enterprisebundle.Bundle) (string, error) {
			root := t.TempDir()
			for name, data := range bundle.Files {
				full := filepath.Join(root, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
					return "", err
				}
				if err := os.WriteFile(full, data, 0o600); err != nil {
					return "", err
				}
			}
			return root, nil
		},
		Digester: b.env.BundleDigester,
	})
	if err != nil {
		t.Fatalf("verify version %d: %v", version, err)
	}
	restart, err := configwrite.ManagedConfigRestartRequired(installed, res.Rendered)
	if err != nil {
		t.Fatal(err)
	}
	return len(restart) > 0
}
