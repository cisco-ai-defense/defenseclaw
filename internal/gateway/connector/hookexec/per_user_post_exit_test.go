// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

// GAP-2083: hook-post gives a failed connected-peer proof (nothing sent) its
// own exit status, the only one the plugins send again; an outage keeps 7
// and every other failure (the gateway may have taken the call) is neither.
func TestPerUserPostPeerUnverifiedIsOnlyAFailedPeerProof(t *testing.T) {
	if PerUserPostPeerUnverifiedExit == PerUserPostOutageExit || PerUserPostPeerUnverifiedExit == 1 {
		t.Fatalf("peer-proof exit %d collides with the outage or generic status", PerUserPostPeerUnverifiedExit)
	}
	for _, tc := range []struct {
		name string
		err  error
		peer bool
	}{
		{"peer proof failed", fmt.Errorf("%w: %w", errPerUserPeerUnverified, errors.New("connected gateway socket belongs to another account")), true},
		{"peer check unfinished at the deadline", fmt.Errorf("dial: %w", errPerUserPeerCheckUnfinished), true},
		{"answer cut off", fmt.Errorf("%w: %w", errPerUserAnswerIncomplete, errors.New("unexpected EOF")), false},
		{"refused connection", syscall.ECONNREFUSED, false},
		{"redirected", errors.New("per-user gateway hook response redirected"), false},
		{"nil", nil, false},
	} {
		if got := PerUserPostPeerUnverified(tc.err); got != tc.peer {
			t.Fatalf("%s: PerUserPostPeerUnverified = %v, want %v", tc.name, got, tc.peer)
		}
		if tc.peer && PerUserPostOutage(tc.err) {
			t.Fatalf("%s: a failed peer proof is an outage", tc.name)
		}
	}
}
