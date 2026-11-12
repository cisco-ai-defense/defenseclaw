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

package extproc

import (
	"sync"
	"time"
)

// Body mode detection (D9). The egress filter honours a mode_override only
// when it was rendered with allow_mode_override (upstream #3817's
// --experimental-additional-egress-extproc-allow-mode-override); stock
// v1.0.0 ignores it. Nothing in a request says which, so the callout
// watches: after an override on a request with a body, the next message is
// the body when it was honoured; when it was not, the stream ends without
// one (stock skips the response phases, so it half-closes) or a response
// phase arrives first.
//
// An actor controls when its own requests end, so the signals an actor can
// produce do not count alone (GAP-0045):
//   - a cancelled or failed stream (the client aborted, Envoy reset) is
//     never a miss;
//   - a clean end without the body is a miss, and the replica is marked
//     unsupported only after bodyMissLimit misses from at least
//     bodyMissActors different actors, with no body in between;
//   - a response phase before the body proves the filter sent the request
//     on without it, and marks the replica unsupported at once.
//
// A body marks it supported, and supported is never undone by misses.
// Unsupported is probed again after bodyReprobe, so a filter redeployed with
// the setting is picked up without a restart. Managed installs should pin
// body_inspection on, which skips detection.
const (
	bodyMissLimit  = 3
	bodyMissActors = 2
	bodyReprobe    = 10 * time.Minute
)

// Stream end signals.
const (
	signalEOF      = "eof"
	signalCanceled = "canceled"
	signalError    = "error"
	signalResponse = "response_before_body"
)

type bodyMode struct {
	setting string
	now     func() time.Time

	mu        sync.Mutex
	supported int // 0 unknown, 1 supported, -1 unsupported
	misses    int
	actors    map[string]bool
	since     time.Time
}

func newBodyMode(setting string, now func() time.Time) *bodyMode {
	return &bodyMode{setting: setting, now: now, actors: map[string]bool{}}
}

// want reports whether to ask for the body of a qualifying request.
func (b *bodyMode) want() bool {
	switch b.setting {
	case BodyOff:
		return false
	case BodyOn:
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.supported >= 0 {
		return true
	}
	if b.now().Sub(b.since) >= bodyReprobe {
		b.reset(0)
		return true
	}
	return false
}

func (b *bodyMode) reset(state int) {
	b.supported, b.misses = state, 0
	b.actors = map[string]bool{}
}

// arrived records a requested body that came.
func (b *bodyMode) arrived() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reset(1)
}

// missed records a requested body that did not come: how the stream ended
// and whose request it was.
func (b *bodyMode) missed(actor, signal string) {
	if b.setting != BodyAuto {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.supported > 0 {
		return
	}
	switch signal {
	case signalResponse:
		b.reset(-1)
		b.since = b.now()
	case signalEOF:
		b.misses++
		b.actors[actor] = true
		if b.misses >= bodyMissLimit && len(b.actors) >= bodyMissActors {
			b.reset(-1)
			b.since = b.now()
		}
	}
}

func (b *bodyMode) status() string {
	if b.setting == BodyOff {
		return "off"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.supported {
	case 1:
		return "supported"
	case -1:
		return "unsupported"
	}
	return "unknown"
}
