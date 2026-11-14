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

import "sync"

// Body mode (D9). The egress filter honours a mode_override only when it
// was rendered with allow_mode_override (upstream #3817's
// --experimental-additional-egress-extproc-allow-mode-override); stock
// v1.0.0 ignores it. With body_inspection auto or on, the callout asks for
// the body of every qualifying request; off never asks.
//
// Nothing turns body mode off at run time (GAP-0045). Every way a requested
// body fails to arrive can be produced by an actor, as measured on cluster
// a4: stock v1.0.0 ends the stream as cancelled, exactly like a client
// abort; on #3817 an abort mid-body ends it cleanly; and a chunked body over
// Envoy's buffer gets a local 413, which reaches the callout as a response
// phase before the body. So a missing body only makes that request's event
// an alert (body_not_received:<signal>), and a body that arrives marks the
// filter supported for the readiness check. On a stock filter set
// body_inspection off (headers only, recorded on every MCP request).
//
// on and auto differ only in a managed enterprise callout that fails
// closed (GAP-0146): on
// says the admin knows the filter sends bodies (defenseclaw substrate setup
// rendered the opt-in); auto does not know, so until a body has arrived an
// MCP request to a listed MCP host is refused at its headers, because a
// stock filter would forward its body unread. With failure mode open, auto
// asks for the body and a body that never comes is an alert.

// Stream end signals, recorded on the request's event.
const (
	signalEOF      = "eof"
	signalCanceled = "canceled"
	signalError    = "error"
	signalResponse = "response_before_body"
)

type bodyMode struct {
	setting string

	mu       sync.Mutex
	received bool
}

func newBodyMode(setting string) *bodyMode { return &bodyMode{setting: setting} }

// want reports whether to ask for the body of a qualifying request.
func (b *bodyMode) want() bool { return b.setting != BodyOff }

// arrived records a requested body that came.
func (b *bodyMode) arrived() {
	b.mu.Lock()
	b.received = true
	b.mu.Unlock()
}

// confirmed reports whether a requested body has reached the callout: the
// egress filter honours the body opt-in (#3817).
func (b *bodyMode) confirmed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.received
}

// status is off, supported (a body has arrived) or unknown, for the
// readiness check and doctor.
func (b *bodyMode) status() string {
	if b.setting == BodyOff {
		return "off"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.received {
		return "supported"
	}
	return "unknown"
}
