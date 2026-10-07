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
// Security event log on Windows. The managed Linux sensor helper can also use
// a customer-run Tetragon for the process half (NewTetragonSource), with the
// native halves live inside the same stream as its fallback.
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
	"sync/atomic"
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
	// KindConnect is a process opening a TCP connection to a peer outside
	// the host (Remote). Only the Tetragon backend's connect policy produces
	// it; the classifier has no tactic for it, so it never scores alone.
	KindConnect Kind = "connect"
)

// EventSource names the backend that produced an event.
type EventSource string

const (
	// SourceTetragon is a customer-run Tetragon agent, read by the managed
	// Linux sensor helper.
	SourceTetragon EventSource = "tetragon"
	// SourceCNProc is the netlink process connector.
	SourceCNProc EventSource = "cn_proc"
	// SourceFanotify is a fanotify notification group.
	SourceFanotify EventSource = "fanotify"
)

// KernelOutcome is what a kernel policy did to the access an event reports.
type KernelOutcome string

const (
	// OutcomeObserved is a post-only policy recording the access.
	OutcomeObserved KernelOutcome = "observed"
	// OutcomeWouldBlock is a deny selector that matched while its policy ran
	// in monitor mode: counted, not applied.
	OutcomeWouldBlock KernelOutcome = "would_block"
	// OutcomeBlocked is a deny selector that matched while its policy was
	// enforcing: the kernel returned EPERM.
	OutcomeBlocked KernelOutcome = "blocked"
)

// HookMark is the self-filter's verdict on a process at or under a
// DefenseClaw hook (section 8.1 of the Tetragon spec).
type HookMark string

const (
	// HookVerified is the exec or exit of a verified hook: the exact rendered
	// hook command, launched by the agent root (or its one sh -c launcher)
	// as the root's own uid. Its argv is reduced to the fixed hook tokens.
	HookVerified HookMark = "verified"
	// HookUnexpected is a process under a verified hook that is not one of
	// the hook's own tools. It is forwarded like any other event, marked.
	HookUnexpected HookMark = "hook_subtree_unexpected"
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

	// Exe is the executable path the backend resolved: Tetragon's binary,
	// or /proc/<pid>/exe for a native Linux event read in the helper.
	// Identity prefers it to Name, whose basename can be a version number
	// (a native Claude install runs as .../versions/2.1.292).
	Exe string
	// UID and AUID are the process's kernel uid and audit login uid. nil is
	// "not observed": uid 0 is root, which is a value, not an absence.
	UID  *int
	AUID *int
	// ExecID and ParentExecID are the backend's process identities (Tetragon
	// exec_id). Unlike a pid they are never reused, so lineage keyed on them
	// does not have to guess at pid reuse.
	ExecID       string
	ParentExecID string
	// StartNS is the process start time in Unix nanoseconds.
	StartNS int64
	// ContainerID is set for a process inside a container. Such an event is
	// counted in the container bucket and never joins a host agent session.
	ContainerID string
	// Source names the backend that produced the event.
	Source EventSource

	// Policy, Outcome and Control are set only on events of DefenseClaw's
	// own Tetragon policies: the policy name, what the policy did, and for
	// the controls policy the control id (kernel.ssh_private_key_read or
	// kernel.persistence_write).
	Policy  string
	Outcome KernelOutcome
	Control string
	// Remote is the peer of a KindConnect event, as host:port.
	Remote string

	// Self marks DefenseClaw's own gateway, helper and ACP processes. They
	// are excluded from scoring, never hidden.
	Self bool
	// Hook is the self-filter's verdict (empty for everything else).
	Hook HookMark
	// HookTools, on a verified hook's exit, counts the hook's own tool
	// processes (jq, curl, ...) that were summarized instead of forwarded.
	HookTools int
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
	// Backend describes the process backend of the managed Linux sensor
	// helper: Tetragon, or the native one with the reason Tetragon is not in
	// use. nil everywhere else.
	Backend *Backend
}

// Backend kinds.
const (
	BackendTetragon = "tetragon"
	BackendNative   = "native"
)

// Backend is what the managed Linux helper's Plane C process half runs on.
type Backend struct {
	// Kind is BackendTetragon or BackendNative.
	Kind string
	// Version is Tetragon's version (v1.7.1) when it answered GetVersion.
	Version string
	// Mode is the effective enterprise.tetragon mode the helper runs:
	// off, consume, observe or enforce.
	Mode string
	// Socket is the unix socket the helper dialled.
	Socket string
	// PID is the Tetragon agent's pid from its info file. The helper's
	// reconciler reports it; it does not travel to the gateway.
	PID int
	// EventsLost is how many events the backend reported losing since the
	// stream opened: rate-limit drops in the stream, plus Tetragon's own
	// loss counters when LossKnown.
	EventsLost int64
	// LossKnown is true when Tetragon's loss counters could be read
	// (metrics on loopback, served by the Tetragon pid). Display only.
	LossKnown bool
	// FallbackReason says why the native backend runs although Tetragon is
	// wanted: a reason code, a colon and the detail
	// ("tetragon_unavailable: no /var/run/tetragon/tetragon-info.json").
	FallbackReason string
	// Policies are the DefenseClaw policies Tetragon has loaded.
	Policies []BackendPolicy
}

// BackendPolicy is one loaded Tetragon policy as ListTracingPolicies
// reported it.
type BackendPolicy struct {
	Name string
	// Mode is enforce, monitor or unknown. TP_MODE_MONITOR_ONLY and an
	// unknown mode both count as not enforcing.
	Mode string
	// State is enabled, disabled, load_error, error, loading, unloading or
	// unknown.
	State string
	Error string
}

// CoverageWatcher is implemented by a source whose coverage can change while
// it runs: the Tetragon backend falling back to the native one and back, or
// handing the file half from fanotify to its observe policy. A receive on
// the channel means "read Coverage again"; it is closed when the source
// stops.
type CoverageWatcher interface {
	CoverageChanges() <-chan struct{}
}

// KernelFeed is one connected session to a kernel event backend that runs
// outside DefenseClaw (a customer's Tetragon). The backend's own client
// package implements it; this package only consumes it, so the plane
// carries no gRPC dependency.
type KernelFeed interface {
	// Recv blocks for the next batch. An error ends the session.
	Recv() (KernelBatch, error)
	// Backend describes the connected backend now: version, socket, the
	// DefenseClaw policies it has loaded and what it lost.
	Backend() Backend
	// Close ends the session and unblocks Recv.
	Close() error
}

// KernelBatch is what one backend message became.
type KernelBatch struct {
	// Events are the plane events, already mapped, filtered and redacted.
	Events []Event
	// ThrottleStart and ThrottleStop report the backend starting or
	// stopping to throttle a cgroup's events.
	ThrottleStart, ThrottleStop bool
	// Dropped counts events the backend says it dropped (rate limiting).
	Dropped int64
}

// KernelDialer opens a KernelFeed. Its error starts with the reason code the
// coverage reports (tetragon_unavailable, tetragon_tcp_api,
// tetragon_untrusted_endpoint, tetragon_unsupported_version).
type KernelDialer func(ctx context.Context) (KernelFeed, error)

// TetragonOptions configure NewTetragonSource.
type TetragonOptions struct {
	// Mode is the effective enterprise.tetragon mode: consume, observe or
	// enforce. Off never builds this source.
	Mode string
	// Dial opens the Tetragon session. Required.
	Dial KernelDialer
	// OwnObservePolicy reports whether a loaded policy is DefenseClaw's
	// observe policy, as the helper recorded it. nil keeps fanotify running
	// for as long as the source runs: the hand-off never happens.
	OwnObservePolicy func(name string) bool
	// Tap, when set, sees every Tetragon batch before it is forwarded: the
	// helper's kernel-policy reconciler counts its controls hits and the
	// loss signals there, from the stream it can vouch for. It must not
	// block.
	Tap func(KernelBatch)
	// Stream, when set, is told when the Tetragon event stream connects,
	// when it ends and when a dial fails with a new reason: burn-in time
	// accrues only while it is up, and in consume the helper's published
	// Tetragon status comes from it. It must not block.
	Stream func(StreamState)
}

// StreamState is the Tetragon event stream as the source sees it.
type StreamState struct {
	Connected bool
	// Version and PID describe the connected Tetragon.
	Version string
	PID     int
	// Reason says why the stream is down: a reason code, a colon and the
	// detail ("tetragon_unavailable: ..."). Empty when the source closed.
	Reason string
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
	events chan Event
	// dropped is atomic because the Linux source runs two readers over one
	// buffer -- cn_proc and fanotify -- and both call Push. A plain counter
	// races, and lost increments understate the drop count, which is the
	// number reported as reduced coverage. Undercounting the drops is the
	// silent degradation this package exists to make impossible.
	dropped atomic.Int64
}

// NewBuffer returns an empty buffer.
func NewBuffer() *Buffer { return &Buffer{events: make(chan Event, eventBuffer)} }

// Push enqueues an event. When the buffer is full, what gets dropped
// depends on what the event is for.
//
// Exec and exit events are not interchangeable with file events. They build
// the process tree, and the process tree is the lineage gate -- the control
// that decides whether any other event is attributable to an agent at all.
// Lose a file read and one signal is missing; lose the exec above it and
// every signal from that subtree becomes unattributable, so the plane gates
// them all and reports a busy machine as quiet.
//
// That is not a theoretical ordering. Measured on macOS with an AI agent
// running: 18,546 file reads against 41 execs in fifteen seconds, nearly
// all of them the agent reading its own config directory. Uniform
// drop-oldest evicted the execs first, and the host plane classified
// nothing while Endpoint Security was delivering perfectly.
//
// So a lineage event may evict to make room, and a file event may not. The
// bias costs nothing when the buffer is keeping up and preserves
// attribution when it is not.
func (b *Buffer) Push(event Event) {
	select {
	case b.events <- event:
		return
	default:
	}
	if !event.Kind.lineage() {
		// A file event that arrives at a full buffer is simply late. It does
		// not get to displace the tree.
		b.dropped.Add(1)
		return
	}
	select {
	case <-b.events:
		b.dropped.Add(1)
	default:
	}
	select {
	case b.events <- event:
	default:
		b.dropped.Add(1)
	}
}

// lineage reports whether an event kind builds the process tree.
func (k Kind) lineage() bool { return k == KindExec || k == KindExit }

// Events is the delivery channel.
func (b *Buffer) Events() <-chan Event { return b.events }

// Dropped is how many events were discarded under back-pressure.
func (b *Buffer) Dropped() int64 { return b.dropped.Load() }

// Close closes the delivery channel.
func (b *Buffer) Close() { close(b.events) }
