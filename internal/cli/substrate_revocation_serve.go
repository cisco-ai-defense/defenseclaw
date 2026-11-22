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

package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
	"github.com/defenseclaw/defenseclaw/internal/substrate/revocation"
)

// substrateRevocationWiring is a replica's ended sign-ins list (B5.1): its
// copy, the leader it pulls from, and its open attach streams. All nil
// when substrate.identity.revocation.enabled is false: no pull loop runs.
type substrateRevocationWiring struct {
	snap    *revocation.Snapshot
	src     revocation.Source
	streams *revocation.Streams
}

// newSubstrateRevocation starts the replica's pull loop (until ctx ends)
// when revocation is on.
func newSubstrateRevocation(ctx context.Context, rc config.SubstrateRevocationConfig, src revocation.Source) substrateRevocationWiring {
	if !rc.EffectiveEnabled() {
		return substrateRevocationWiring{}
	}
	snap := revocation.NewSnapshot(rc.EffectiveMaxStale())
	go snap.Sync(ctx, src, rc.EffectiveSyncInterval())
	return substrateRevocationWiring{snap: snap, src: src, streams: revocation.NewStreams(snap)}
}

// serveSubstrateRevocations serves the list from the leader's store volume
// (storeDir/revocations) when revocation is on.
func serveSubstrateRevocations(srv *leader.Server, c *config.Config, storeDir string) error {
	var rc config.SubstrateRevocationConfig
	if c != nil {
		rc = c.Substrate.Identity.Revocation
	}
	if !rc.EffectiveEnabled() {
		return nil
	}
	store, err := revocation.OpenFileStore(filepath.Join(storeDir, "revocations"))
	if err != nil {
		return fmt.Errorf("serve: ended sign-ins list: %w", err)
	}
	store.MaxTokensPerPerson = rc.EffectiveMaxTokensPerPerson()
	revocation.Serve(srv, store)
	return nil
}
