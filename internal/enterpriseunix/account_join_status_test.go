// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// rel-1-0-6:GAP-0344 (Linux and macOS side): account-keys and status read
// the identity spool in the folder the guardian is pinned to
// (DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR of the service environment), the
// layout's guardian folder: /var/lib/defenseclaw-hook-guardian on Linux and
// /opt/cisco/defenseclaw/hook-guardian-state on macOS, which is not data_dir
// plus -hook-guardian there.
func TestAccountJoinReadsTheSpoolTheGuardianWrites(t *testing.T) {
	for goos, want := range map[string]string{
		"linux":  "/var/lib/defenseclaw-hook-guardian/identity",
		"darwin": "/opt/cisco/defenseclaw/hook-guardian-state/identity",
	} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			pinned := ""
			for _, entry := range h.env.serviceEnvironment() {
				if value, ok := strings.CutPrefix(entry, "DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR="); ok {
					pinned = value
				}
			}
			if got := enterprisehooks.IdentitySpoolDir(pinned); got != want {
				t.Fatalf("the guardian writes %s, want %s", got, want)
			}
			if got := h.env.accountJoinSources(&config.Config{DataDir: h.env.Layout.DataDir}).SpoolDir; got != h.env.P(want) {
				t.Fatalf("account-keys reads %s, want %s", got, h.env.P(want))
			}
		})
	}
}

// rel-1-0-6:GAP-0277: the status inputs ask this deployment's bundle store
// for the signing time of the confirmed bundle that carries next_not_after.
func TestAccountJoinSourcesAskTheConfirmedBundleForTheSigningTime(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			signed := time.Date(2026, 10, 25, 8, 30, 0, 0, time.UTC)
			notAfter := signed.Add(29 * 24 * time.Hour)
			var asked *enterprisebundle.Store
			previous := confirmedAccountJoinSignedAt
			confirmedAccountJoinSignedAt = func(s *enterprisebundle.Store, generation int, at time.Time) (time.Time, bool) {
				if generation != 2 || !at.Equal(notAfter) {
					t.Errorf("asked for generation %d at %v", generation, at)
				}
				asked = s
				return signed, true
			}
			t.Cleanup(func() { confirmedAccountJoinSignedAt = previous })
			sources := h.env.accountJoinSources(&config.Config{})
			if sources.SignedAt == nil {
				t.Fatal("the status inputs have no signing time")
			}
			if at, ok := sources.SignedAt(2, notAfter); !ok || !at.Equal(signed) {
				t.Fatalf("signing time %v, %v", at, ok)
			}
			if asked == nil || asked.LifecycleDir != h.env.P(h.env.Layout.LifecycleDir) {
				t.Fatalf("asked the store %+v, want the deployment's (%s)", asked, h.env.P(h.env.Layout.LifecycleDir))
			}
		})
	}
}
