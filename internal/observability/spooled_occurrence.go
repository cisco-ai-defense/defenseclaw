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

package observability

import "context"

type skipLocalWriteKey struct{}

type pinnedProvenanceKey struct{}

// WithSkipLocalWrite marks an offer of an occurrence whose producer keeps it
// in a durable spool under a stable id and offers it until every sink has
// it (a trust anchor or credential change event), when the local store is
// not to be written on this offer: it already holds the occurrence under
// that id, or it could not say whether it does. The local store is one sink
// of the spooled occurrence and the remote destinations do not wait for it:
// the pipeline writes nothing locally and hands back only the
// optional-destination projections, which the runtime sends to the
// destinations that do not have it yet (RemoteDelivery). The producer
// records no metric for the offer: they are recorded with the row.
//
// A correlation relationship change uses it too: its row is in its own audit
// table (correlation_relationships), committed before the export.
func WithSkipLocalWrite(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, skipLocalWriteKey{}, true)
}

// SkipLocalWrite reports whether ctx carries WithSkipLocalWrite.
func SkipLocalWrite(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	marked, _ := ctx.Value(skipLocalWriteKey{}).(bool)
	return marked
}

// PinnedProvenance is the config generation and digest the record of a
// spooled occurrence was first built on. Its producer pins that record
// before any sink gets it and builds every later offer on the same config,
// so a reload or a restart never makes another record under its id.
type PinnedProvenance struct {
	ConfigGeneration uint64
	ConfigDigest     string
}

// WithPinnedProvenance marks an offer of a spooled occurrence whose record
// is pinned: the runtime accepts a record that names pinned in place of the
// generation it runs, and no other.
func WithPinnedProvenance(ctx context.Context, pinned PinnedProvenance) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, pinnedProvenanceKey{}, pinned)
}

// PinnedProvenanceFrom returns the pinned config of ctx, if any.
func PinnedProvenanceFrom(ctx context.Context) (PinnedProvenance, bool) {
	if ctx == nil {
		return PinnedProvenance{}, false
	}
	pinned, ok := ctx.Value(pinnedProvenanceKey{}).(PinnedProvenance)
	return pinned, ok
}
