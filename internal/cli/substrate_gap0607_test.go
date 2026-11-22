// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/configwatch"
)

// substrate-1:GAP-0607 (review 3). For a substrate.extproc change the
// follower advised a rollout restart of the gateway, leader and controller,
// but that key renders the callout's ConfigMap, which only helm upgrade
// writes: no pod restart applies it. The advice for it now names helm
// upgrade only, and the other restart-only keys keep their rollout restart.
func TestGAP0607ExtprocChangeAdviceNamesHelmUpgradeOnly(t *testing.T) {
	boot := gap0276Config("", nil)
	follow := func(t *testing.T, edit func(*config.Config)) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte("boot"), 0o644); err != nil {
			t.Fatal(err)
		}
		next := gap0276Config("", edit)
		w := configwatch.New(path, boot, []byte("boot"))
		w.Load = func(_ string, b []byte) (*config.Config, error) {
			if string(b) == "v2" {
				return next, nil
			}
			return nil, errors.New("does not load")
		}
		now := time.Date(2026, 11, 18, 3, 0, 0, 0, time.UTC)
		w.Now = func() time.Time { return now }
		var out bytes.Buffer
		f := newSubstrateFollower(w, "gateway", &out, func(*config.Config) error { return nil })
		if err := os.WriteFile(path, []byte("v2"), 0o644); err != nil {
			t.Fatal(err)
		}
		now = now.Add(configwatch.DefaultInterval)
		f.step(context.Background())
		return out.String()
	}
	const helmOnly = "apply only by helm upgrade (a pod restart does not change them): substrate.extproc"
	ext := follow(t, func(c *config.Config) { c.Substrate.Extproc.FailureMode = "open" })
	if !strings.Contains(ext, helmOnly) || strings.Contains(ext, "rollout restart") {
		t.Errorf("substrate.extproc change: want helm upgrade only, no rollout restart: %q", ext)
	}
	both := follow(t, func(c *config.Config) {
		c.Substrate.Extproc.FailureMode = "open"
		c.Substrate.RateLimits.PerActorRPS = 5
	})
	if !strings.Contains(both, helmOnly) || !strings.Contains(both, "substrate.rate_limits (helm upgrade rolls the pods; after a direct ConfigMap edit run kubectl rollout restart deploy/defenseclaw-gateway)") ||
		strings.Contains(both, "defenseclaw-controller") {
		t.Errorf("substrate.extproc and rate_limits change: want the gateway's restart for rate_limits and helm upgrade for extproc: %q", both)
	}
}
