// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

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
