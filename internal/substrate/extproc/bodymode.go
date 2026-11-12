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
// the body when it was honoured, and the stream ends without one when it was
// not. bodyMissLimit misses in a row mark it unsupported; a body marks it
// supported. Unsupported is probed again after bodyReprobe, so a filter
// redeployed with the setting is picked up without a restart.
const (
	bodyMissLimit = 3
	bodyReprobe   = 10 * time.Minute
)

type bodyMode struct {
	setting string
	now     func() time.Time

	mu        sync.Mutex
	supported int // 0 unknown, 1 supported, -1 unsupported
	misses    int
	since     time.Time
}

func newBodyMode(setting string, now func() time.Time) *bodyMode {
	return &bodyMode{setting: setting, now: now}
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
		b.supported, b.misses = 0, 0
		return true
	}
	return false
}

// observe records whether a requested body arrived.
func (b *bodyMode) observe(arrived bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if arrived {
		b.supported, b.misses = 1, 0
		return
	}
	b.misses++
	if b.misses >= bodyMissLimit && b.supported <= 0 {
		b.supported, b.since = -1, b.now()
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
