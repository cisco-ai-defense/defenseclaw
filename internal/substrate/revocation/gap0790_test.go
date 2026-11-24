// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package revocation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// GAP-0790 (RV3-03): Check looked an ended token up by its key alone. A
// cluster JWT is keyed by the cluster and its jti, and two issuers the
// cluster trusts can issue one jti to two people, so one person's logout
// refused the other's token. A token end now applies to the person who
// ended it.
func TestGAP0790TokenEndIsPerPerson(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	s := newStore(t, t.TempDir(), c)
	const alice, bob = "kubernetes#oidc:alice", "kubernetes#bob"
	key := identity.TokenKey(identity.KubeIssuer, "J", "")
	if _, err := s.Put(context.Background(), Entry{Person: alice, Token: key}); err != nil {
		t.Fatal(err)
	}
	snap := synced(t, s, c)
	iat := c.t.Add(-time.Minute)
	if err := snap.Check(alice, key, iat); !errors.Is(err, ErrEnded) {
		t.Fatalf("the ended token: %v", err)
	}
	if err := snap.Check(bob, key, iat); err != nil {
		t.Fatalf("another person's token with the same key: %v", err)
	}
}
