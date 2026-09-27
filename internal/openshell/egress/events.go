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

package egress

import "time"

// EventKind classifies a proxy event.
type EventKind string

const (
	// EventAllowed: the upstream connection is established (CONNECT) or the
	// upstream response arrived (absolute-form). One per tunnel or request.
	EventAllowed EventKind = "allowed"
	// EventBlocked: a policy or limit refused the destination; the client
	// got a 403 (or 429) JSON body. When an established CONNECT tunnel is
	// refused for its TLS server name, the event carries the tunnel's
	// TunnelID and the refused name as Host, and the client got a TLS alert
	// instead. A tunnel refused for its plaintext content (an HTTP request
	// for another host, or a protocol its port does not carry) carries its
	// TunnelID too; its client got a 400 JSON response inside the tunnel.
	EventBlocked EventKind = "blocked"
	// EventClosed: an allowed tunnel or request finished; carries byte
	// counts and duration.
	EventClosed EventKind = "closed"
	// EventFailed: the destination was allowed but DNS, connect, TLS or the
	// upstream failed; the client got a 502 or 504.
	EventFailed EventKind = "failed"
	// EventAuthFailed: a request presented a proxy credential that was
	// malformed, unknown, revoked or wrong, and got a 407. Requests without
	// any credential also get a 407 challenge but no event: that is the
	// normal first leg of the handshake for clients such as git.
	EventAuthFailed EventKind = "auth_failed"
	// EventLargeUpload: bytes sent to a first-seen destination crossed the
	// large-upload threshold, counted per host and, across a binding's
	// first-seen hosts, per registrable domain and per resolved address.
	// Emitted once per binding and host, domain or address; Reason names
	// the domain or address when one of those crossed, and BytesUp is the
	// total that did.
	EventLargeUpload EventKind = "large_upload"
)

// Event is one proxy observation. Events never carry credentials, URL paths
// or query strings.
type Event struct {
	Kind EventKind
	Time time.Time
	// TunnelID correlates the allowed, closed and large_upload events of one
	// tunnel or forwarded request.
	TunnelID    string
	BindingID   string
	SandboxID   string
	SandboxName string
	// Method is CONNECT or the forwarded HTTP method.
	Method string
	Host   string
	Port   int
	// RemoteAddr is the upstream address actually dialed, when known.
	RemoteAddr  string
	Mode        Mode
	Category    Category
	Reason      string
	Rule        string
	Source      Source
	Feed        string
	FeedVersion string
	Entry       string
	// Status is the HTTP status the proxy returned to the sandbox (200 for
	// an established tunnel, the upstream status for forwarded requests).
	Status int
	// BytesUp and BytesDown count payload bytes sent to and received from
	// the destination. For large_upload they are the destination totals.
	BytesUp   int64
	BytesDown int64
	Duration  time.Duration
	// FirstSeen marks the first contact with the destination by this
	// binding (allowed), or a destination that was first-seen when the
	// large upload happened (large_upload).
	FirstSeen bool
	// Terminated marks a tunnel or request cut by the large-upload block, by
	// the tunnel idle timeout, or refused inside the tunnel (its TLS server
	// name or its plaintext content).
	Terminated bool
	// Error is a bounded failure description for failed events.
	Error string
}

// EventSink receives proxy events. EgressEvent is called synchronously on
// the proxy's connection goroutines, so implementations must be safe for
// concurrent use and must not block (buffer and drop instead). A panicking
// sink is recovered and ignored.
type EventSink interface {
	EgressEvent(Event)
}

// EventSinkFunc adapts a function to EventSink.
type EventSinkFunc func(Event)

// EgressEvent implements EventSink.
func (f EventSinkFunc) EgressEvent(e Event) { f(e) }

type nopSink struct{}

func (nopSink) EgressEvent(Event) {}
