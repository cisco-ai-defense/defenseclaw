// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// GAP-0311 (R13's TestR13SweepPurgesAMissedDelete, an F20 regression: the
// probe passed at 1ab25d7838 and failed at a632e56828): the controller keeps
// its actor list in memory, so an actor deleted while it was down or
// restarting is never reported gone. Its clock is frozen, so a window with a
// secret read held forever and Sweep never purged it. Sweep now purges such
// an actor past PurgeAfter when its registration confirms it gone, and only
// then.
func TestGAP0311SweepPurgesAMissedDelete(t *testing.T) {
	t.Parallel()
	errLookup := errors.New("registrations unavailable")
	for _, c := range []struct {
		name       string
		tombstone  bool
		lookupErr  error
		wantPurged bool
	}{
		{name: "deleted, no delete event", tombstone: true, wantPurged: true},
		{name: "still exists"},
		{name: "the lookup fails", tombstone: true, lookupErr: errLookup},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			n := newNames()
			deleted := func(ctx context.Context, atespace, uid string) (bool, error) {
				if c.lookupErr != nil {
					return false, c.lookupErr
				}
				return n.isDeleted(ctx, atespace, uid)
			}
			warn := &syncBuffer{}
			h := newHarness(t, t.TempDir(), Options{PurgeAfter: time.Hour, Deleted: deleted, Warn: warn})
			n.register("w1", actorA)
			h.hook(actorA, "s1", secretRead(t))
			if c.tombstone {
				n.tombstone(actorA)
			}
			h.advance(8 * 24 * time.Hour)
			res, err := h.svc.Sweep(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			_, statErr := os.Stat(h.svc.statePath(actorA))
			if c.wantPurged {
				if res.Purged != 1 || statErr == nil {
					t.Fatalf("sweep %+v, state file err=%v: want the deleted actor purged", res, statErr)
				}
				// As after its delete event: no fresh, empty entry answers allow.
				if v, err := h.egress(actorA); err != nil || !v.Deny || !v.Stale {
					t.Fatalf("egress of the purged UID: %+v err=%v, want stale", v, err)
				}
				return
			}
			if res.Purged != 0 || statErr != nil {
				t.Fatalf("sweep %+v, state file err=%v: want the actor kept", res, statErr)
			}
			h.wantEgressRefused(actorA, "kept by the sweep")
			if c.lookupErr != nil && !strings.Contains(warn.String(), "could not be read") {
				t.Fatalf("no warning for the failed lookup: %q", warn.String())
			}
		})
	}
}
