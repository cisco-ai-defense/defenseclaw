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

package gateway

import (
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

const (
	sandboxEventReplayWindow = 10 * time.Minute
	sandboxEventReplayMax    = 4096
)

// sandboxEventReplay bounds exact replay of a registered daemon batch.
// The key includes the kernel-verified uid, registration and event times.
type sandboxEventReplay struct {
	mu   sync.Mutex
	seen map[[32]byte]time.Time
}

func (d *sandboxEventReplay) duplicate(uid int, batch sandboxrelay.EventBatch, now time.Time) bool {
	if batch.Registration == "" {
		return false
	}
	raw, err := json.Marshal(struct {
		UID   int                     `json:"uid"`
		Batch sandboxrelay.EventBatch `json:"batch"`
	}{uid, batch})
	if err != nil {
		return false
	}
	key := sha256.Sum256(raw)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.seen == nil {
		d.seen = map[[32]byte]time.Time{}
	}
	if at, ok := d.seen[key]; ok && now.Sub(at) < sandboxEventReplayWindow {
		return true
	}
	if len(d.seen) >= sandboxEventReplayMax {
		for key, at := range d.seen {
			if now.Sub(at) >= sandboxEventReplayWindow {
				delete(d.seen, key)
			}
		}
		if len(d.seen) >= sandboxEventReplayMax {
			var oldest [32]byte
			var at time.Time
			for key, seenAt := range d.seen {
				if at.IsZero() || seenAt.Before(at) {
					oldest, at = key, seenAt
				}
			}
			delete(d.seen, oldest)
		}
	}
	d.seen[key] = now
	return false
}
