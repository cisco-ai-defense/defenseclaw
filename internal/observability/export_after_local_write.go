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

type exportAfterLocalWriteKey struct{}

// WithExportAfterLocalWrite marks a log occurrence whose producer keeps it
// queued under a stable id and offers it again until the local store
// records it (a trust anchor or credential change event). Its optional
// destinations get it only once the local write succeeded: a failed write
// exports nothing, so a retry cannot export the same occurrence again, and
// the stable id keeps the retry after a success to one local row. Other
// occurrences are still exported when the local write fails (GAP-1536).
func WithExportAfterLocalWrite(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, exportAfterLocalWriteKey{}, true)
}

// ExportAfterLocalWrite reports whether ctx carries WithExportAfterLocalWrite.
func ExportAfterLocalWrite(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	marked, _ := ctx.Value(exportAfterLocalWriteKey{}).(bool)
	return marked
}

type storedReplayKey struct{}

// WithStoredReplay marks an offer of an occurrence the local store already
// holds under its stable id (an earlier offer stored it, then a destination
// failed or the process stopped before every destination had it). The
// pipeline does not write it locally again and hands back only its
// optional-destination projections; the producer emits no metric for it.
// It implies WithExportAfterLocalWrite.
func WithStoredReplay(ctx context.Context) context.Context {
	return context.WithValue(WithExportAfterLocalWrite(ctx), storedReplayKey{}, true)
}

// StoredReplay reports whether ctx carries WithStoredReplay.
func StoredReplay(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	marked, _ := ctx.Value(storedReplayKey{}).(bool)
	return marked
}

type storedReplayFormKey struct{}

// WithStoredReplayForm records the admission form of a durable row. A replay
// keeps that form even if the current collection policy has changed.
func WithStoredReplayForm(ctx context.Context, floorOnly bool) context.Context {
	return context.WithValue(WithStoredReplay(ctx), storedReplayFormKey{}, floorOnly)
}

// StoredReplayForm returns the original floor form when a replay has one.
func StoredReplayForm(ctx context.Context) (floorOnly bool, present bool) {
	if !StoredReplay(ctx) {
		return false, false
	}
	floorOnly, present = ctx.Value(storedReplayFormKey{}).(bool)
	return floorOnly, present
}
