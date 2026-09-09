// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

// Package plane is the Plane C acquisition seam: kernel process, file, and
// identity events, normalised into one platform-neutral stream.
//
// Every backend produces the same Event values, so the classification above it
// -- tactics, agent lineage, chain scoring -- never branches on the operating
// system. What varies is only how the events are obtained: Endpoint Security
// on macOS, the netlink process connector plus fanotify on Linux, and the
// Security event log on Windows.
//
// # Degradation is a value, not a silence
//
// A source that cannot start says why, and a source that starts with only part
// of its coverage says which part. A blinded plane reporting nothing is
// indistinguishable, on a dashboard, from a host where nothing happened, and
// that is the confusion this whole subsystem exists to prevent.
package plane

import (
	"context"
	"time"
)

// Kind is the category of a kernel observation.
type Kind string

const (
	// KindExec is a process replacing its image. This is the authoritative
	// lineage source: it carries the parent at the moment of exec, which a
	// later process-table poll cannot recover once the parent has exited, and
	// it catches the eight-millisecond `cat` that polling never sees.
	KindExec Kind = "exec"
	// KindExit is a process ending.
	KindExit Kind = "exit"
	// KindFileRead is a process reading a file.
	KindFileRead Kind = "file_read"
	// KindFileWrite is a process creating, writing, renaming, or unlinking one.
	KindFileWrite Kind = "file_write"
	// KindIdentity is an account or credential principal being created or
	// modified.
	KindIdentity Kind = "identity"
	// KindPrivilege is a process acquiring rights it did not start with.
	KindPrivilege Kind = "privilege"
)

// Event is one normalised kernel observation.
//
// Deliberately flat and small. Everything a backend cannot supply is left
// zero, and the classifier treats a zero field as "not observed" rather than
// as a value -- a backend that guessed would put a fabricated fact into a
// finding.
type Event struct {
	Kind Kind
	PID  int
	PPID int
	// ResponsiblePID is the process the platform holds answerable, where it
	// differs from the parent. On macOS a shell spawned by an agent is
	// reparented, and this is what survives that.
	ResponsiblePID int
	// Name is the executable basename.
	Name string
	// Cmdline is the argument vector, when the backend supplies one.
	Cmdline string
	// Path is the file an event concerns, for file kinds.
	Path string
	// Detail carries backend-specific context an operator would want in the
	// finding -- the account name for an identity event, the privilege for a
	// privilege event.
	Detail string
	// User is the owning username, when cheaply available.
	User string
	At   time.Time
}

// Coverage describes what a running source can and cannot see.
//
// Both halves matter. A source can be up and still be missing an entire class
// of events -- fanotify without CAP_SYS_ADMIN, or a Windows Security log
// without Advanced Audit Policy -- and reporting that as full coverage would
// be the substitution this package refuses.
type Coverage struct {
	// Mechanism names what is actually running.
	Mechanism string
	// Kinds are the event kinds this source can currently deliver.
	Kinds []Kind
	// MissingKinds are the kinds it cannot, paired with Limitations.
	MissingKinds []Kind
	// Limitations are operator-facing reasons, one per missing capability.
	Limitations []string
}

// Complete reports whether the source is delivering every kind it knows about.
func (c Coverage) Complete() bool { return len(c.MissingKinds) == 0 }

// Source is one platform's Plane C acquisition.
type Source interface {
	// Start begins delivery. It returns an error the operator can act on when
	// the source cannot run at all.
	Start(ctx context.Context) error
	// Events is the delivery channel. It is closed when the source stops.
	Events() <-chan Event
	// Coverage describes what this source is delivering, and what it is not.
	// Valid only after a successful Start.
	Coverage() Coverage
	// Close stops delivery and releases resources.
	Close() error
}

// eventBuffer bounds how many events a source may queue.
//
// A busy host can produce kernel events faster than the classifier drains
// them. Dropping the newest event under pressure is wrong -- the interesting
// one is usually the most recent -- so backends drop the oldest and count what
// they dropped, which the service reports as reduced coverage rather than
// hiding.
const eventBuffer = 4096

// Buffer is a bounded, oldest-dropping event queue shared by the backends.
type Buffer struct {
	events  chan Event
	dropped int64
}

// NewBuffer returns an empty buffer.
func NewBuffer() *Buffer { return &Buffer{events: make(chan Event, eventBuffer)} }

// Push enqueues an event, evicting the oldest when full.
func (b *Buffer) Push(event Event) {
	select {
	case b.events <- event:
		return
	default:
	}
	select {
	case <-b.events:
		b.dropped++
	default:
	}
	select {
	case b.events <- event:
	default:
		b.dropped++
	}
}

// Events is the delivery channel.
func (b *Buffer) Events() <-chan Event { return b.events }

// Dropped is how many events were discarded under back-pressure.
func (b *Buffer) Dropped() int64 { return b.dropped }

// Close closes the delivery channel.
func (b *Buffer) Close() { close(b.events) }
