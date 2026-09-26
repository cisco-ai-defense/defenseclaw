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

// Package stream follows one OpenShell sandbox through the raw
// WatchSandbox RPC: status snapshots, supervisor log lines (with OCSF
// shorthand parsed into ocsf.Record), platform events, draft-policy
// notifications and server warnings, delivered as typed Events.
//
// The SDK's Sandboxes().Watch only follows status, so the watcher uses the
// generated openshellv1 stub over its own connection (see
// openshell.Registration.DialGRPC). It resumes after the highest cursor it
// has processed, persists that cursor through a callback, and survives
// gateway restarts: OpenShell answers a cursor from a previous cursor space
// with OUT_OF_RANGE, which the watcher reports as a Gap before
// resubscribing without a cursor. Transport failures back off
// exponentially.
package stream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"time"

	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
)

// ErrSandboxNotFound ends a watch whose sandbox no longer exists.
var ErrSandboxNotFound = errors.New("stream: sandbox not found")

// Kind classifies an Event.
type Kind string

// Event kinds. Status, Log, Platform, Warning and Draft mirror the
// WatchSandbox payloads; Gap, Connected and Disconnected are produced by
// the watcher itself.
const (
	KindStatus       Kind = "status"
	KindLog          Kind = "log"
	KindPlatform     Kind = "platform"
	KindWarning      Kind = "warning"
	KindDraft        Kind = "draft"
	KindGap          Kind = "gap"
	KindConnected    Kind = "connected"
	KindDisconnected Kind = "disconnected"
)

// Event is one typed stream item. Exactly the field matching Kind is set.
type Event struct {
	Kind    Kind
	Sandbox string
	// Cursor is the resume position of Log and Platform events.
	Cursor string
	// Time is the event time reported by OpenShell, or the receive time
	// for payloads without one.
	Time time.Time

	Status     *Status
	Log        *Log
	Platform   *Platform
	Warning    *Warning
	Draft      *DraftUpdate
	Gap        *Gap
	Connection *Connection
}

// Status is a sandbox status snapshot.
type Status struct {
	ID             string
	Name           string
	Phase          openshell.SandboxPhase
	PolicyVersion  uint32
	ExitCode       *int32
	Conditions     []Condition
	Admission      openshell.ConfigAdmissionState
	AdmissionError string
}

// Condition is one sandbox condition.
type Condition struct {
	Type, Status, Reason, Message string
}

// Log is one log line correlated to the sandbox.
type Log struct {
	SandboxID string
	Level     string
	Target    string
	Message   string
	// Source is "sandbox" (supervisor) or "gateway".
	Source string
	Fields map[string]string
	// OCSF is the parsed shorthand for OCSF lines; nil for other lines and
	// for OCSF lines the parser could not recognize.
	OCSF *ocsf.Record
}

// Platform is a compute-driver or gateway event.
type Platform struct {
	Source, Type, Reason, Message string
	Metadata                      map[string]string
}

// Warning is a recoverable server warning (for example dropped messages
// after a lagging receiver) or, with Local set, a watcher-side problem
// such as a failed cursor save. The stream continues either way.
type Warning struct {
	Message string
	Local   bool
}

// DraftUpdate announces new proposed policy chunks.
type DraftUpdate struct {
	DraftVersion uint64
	NewChunks    uint32
	TotalPending uint32
	Summary      string
}

// Gap reasons.
const (
	// GapCursorOutOfRange: the resume cursor was trimmed or belongs to a
	// previous cursor space (gateway restart); events after it are lost.
	GapCursorOutOfRange = "cursor_out_of_range"
	// GapCursorRejected: the gateway could not have issued the cursor (a
	// different gateway, or a corrupted state file).
	GapCursorRejected = "cursor_rejected"
)

// Gap reports that events may have been lost between LostCursor and the
// resubscription.
type Gap struct {
	Reason     string
	LostCursor string
}

// Connection describes a (re)subscription or a disconnect.
type Connection struct {
	// Attempt counts subscriptions since Run started, from 1.
	Attempt int
	// Resumed reports that the subscription asked for events after Cursor.
	Resumed bool
	Cursor  string
	// Err and Backoff are set on Disconnected events.
	Err     error
	Backoff time.Duration
}

// Follow selects the WatchSandbox sources. The zero value follows all
// three.
type Follow struct {
	Status bool
	Logs   bool
	Events bool
}

// Backoff paces reconnects. The zero value means 500ms doubling to 30s
// with 20% jitter.
type Backoff struct {
	Initial    time.Duration
	Max        time.Duration
	Multiplier float64
	// Jitter is the random fraction (0..1) subtracted from each delay.
	Jitter float64
}

// Config configures a Watcher.
type Config struct {
	// Conn is a connection to the gateway (Registration.DialGRPC). The
	// watcher does not close it.
	Conn      grpc.ClientConnInterface
	Workspace string
	Sandbox   string
	Follow    Follow
	// LogSources defaults to ["sandbox"], the supervisor's OCSF lines.
	LogSources  []string
	LogMinLevel string
	// TailLines and EventTail replay recent history when subscribing
	// without a cursor.
	TailLines uint32
	EventTail uint32
	// Cursor resumes a previous watch.
	Cursor string
	// SaveCursor persists the resume cursor: throttled to SaveInterval
	// while events flow, and always on disconnect, on a gap (with "") and
	// when Run returns.
	SaveCursor   func(cursor string) error
	SaveInterval time.Duration
	Backoff      Backoff
	// DedupeWindow is how many recent cursors are remembered to drop
	// replayed duplicates (default 4096).
	DedupeWindow int
}

// Watcher follows one sandbox. It is not safe for concurrent Run calls.
type Watcher struct {
	cfg    Config
	client pb.OpenShellClient
	sleep  func(context.Context, time.Duration) error
	now    func() time.Time

	cursor    string
	dirty     bool
	lastSave  time.Time
	seen      map[string]struct{}
	seenOrder []string
}

// New validates cfg and returns a Watcher.
func New(cfg Config) (*Watcher, error) {
	if cfg.Conn == nil {
		return nil, errors.New("stream: a gateway connection is required")
	}
	if !openshell.ValidSandboxName(cfg.Sandbox) {
		return nil, fmt.Errorf("stream: invalid sandbox name %q", cfg.Sandbox)
	}
	if cfg.Workspace == "" {
		cfg.Workspace = openshell.DefaultWorkspace
	}
	if cfg.Follow == (Follow{}) {
		cfg.Follow = Follow{Status: true, Logs: true, Events: true}
	}
	if len(cfg.LogSources) == 0 {
		cfg.LogSources = []string{"sandbox"}
	}
	if cfg.SaveInterval <= 0 {
		cfg.SaveInterval = 2 * time.Second
	}
	if cfg.Backoff.Initial <= 0 {
		cfg.Backoff = Backoff{Initial: 500 * time.Millisecond, Max: 30 * time.Second, Multiplier: 2, Jitter: 0.2}
	}
	if cfg.Backoff.Max < cfg.Backoff.Initial {
		cfg.Backoff.Max = cfg.Backoff.Initial
	}
	if cfg.Backoff.Multiplier < 1 {
		cfg.Backoff.Multiplier = 1
	}
	if cfg.DedupeWindow <= 0 {
		cfg.DedupeWindow = 4096
	}
	return &Watcher{
		cfg:    cfg,
		client: pb.NewOpenShellClient(cfg.Conn),
		sleep:  sleepContext,
		now:    time.Now,
		cursor: cfg.Cursor,
		seen:   make(map[string]struct{}),
	}, nil
}

// Cursor returns the highest cursor processed so far.
func (w *Watcher) Cursor() string { return w.cursor }

// Run follows the sandbox until ctx ends (returning ctx.Err()) or the
// watch hits a terminal error: the sandbox is gone (ErrSandboxNotFound),
// or the gateway refuses the caller (permission, authentication,
// unimplemented). handle runs synchronously on the receive loop.
func (w *Watcher) Run(ctx context.Context, handle func(Event)) error {
	if handle == nil {
		return errors.New("stream: nil event handler")
	}
	defer w.flush(handle)
	delay := w.cfg.Backoff.Initial
	for attempt := 1; ; attempt++ {
		delivered, err := w.subscribe(ctx, attempt, handle)
		w.flush(handle)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if delivered {
			delay = w.cfg.Backoff.Initial
		}

		code := status.Code(err)
		switch {
		case code == codes.OutOfRange && w.cursor != "":
			w.gap(GapCursorOutOfRange, handle)
			continue
		case code == codes.InvalidArgument && w.cursor != "":
			w.gap(GapCursorRejected, handle)
			continue
		case code == codes.NotFound:
			return fmt.Errorf("%w: %s: %s", ErrSandboxNotFound, w.cfg.Sandbox, status.Convert(err).Message())
		case code == codes.PermissionDenied, code == codes.Unauthenticated, code == codes.Unimplemented, code == codes.InvalidArgument:
			return fmt.Errorf("stream: watch %s: %w", w.cfg.Sandbox, err)
		}

		wait := w.jitter(delay)
		handle(Event{Kind: KindDisconnected, Sandbox: w.cfg.Sandbox, Time: w.now(),
			Connection: &Connection{Attempt: attempt, Cursor: w.cursor, Err: err, Backoff: wait}})
		if err := w.sleep(ctx, wait); err != nil {
			return err
		}
		delay = time.Duration(float64(delay) * w.cfg.Backoff.Multiplier)
		if delay > w.cfg.Backoff.Max {
			delay = w.cfg.Backoff.Max
		}
	}
}

// subscribe runs one WatchSandbox call to its end. It reports whether any
// payload arrived and the terminating error (io.EOF for a clean close).
func (w *Watcher) subscribe(ctx context.Context, attempt int, handle func(Event)) (bool, error) {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	resumed := w.cursor != ""
	stream, err := w.client.WatchSandbox(sctx, w.request())
	if err != nil {
		return false, err
	}
	delivered := false
	for {
		ev, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return delivered, io.EOF
			}
			return delivered, err
		}
		if !delivered {
			delivered = true
			handle(Event{Kind: KindConnected, Sandbox: w.cfg.Sandbox, Time: w.now(),
				Connection: &Connection{Attempt: attempt, Resumed: resumed, Cursor: w.cursorIf(resumed)}})
		}
		w.dispatch(ev, handle)
	}
}

func (w *Watcher) cursorIf(ok bool) string {
	if ok {
		return w.cursor
	}
	return ""
}

func (w *Watcher) request() *pb.WatchSandboxRequest {
	req := &pb.WatchSandboxRequest{
		WorkspaceScope:    &dm.WorkspaceSelector{Selection: &dm.WorkspaceSelector_Workspace{Workspace: w.cfg.Workspace}},
		Sandbox:           w.cfg.Sandbox,
		FollowStatus:      w.cfg.Follow.Status,
		FollowLogs:        w.cfg.Follow.Logs,
		FollowEvents:      w.cfg.Follow.Events,
		LogSources:        append([]string(nil), w.cfg.LogSources...),
		LogMinLevel:       w.cfg.LogMinLevel,
		ResumeAfterCursor: w.cursor,
	}
	if w.cursor == "" {
		req.LogTailLines = w.cfg.TailLines
		req.EventTail = w.cfg.EventTail
	}
	return req
}

// gap reports lost events, forgets the cursor and persists that.
func (w *Watcher) gap(reason string, handle func(Event)) {
	lost := w.cursor
	w.cursor = ""
	w.dirty = true
	handle(Event{Kind: KindGap, Sandbox: w.cfg.Sandbox, Time: w.now(), Gap: &Gap{Reason: reason, LostCursor: lost}})
	w.flush(handle)
}

func (w *Watcher) dispatch(ev *pb.SandboxStreamEvent, handle func(Event)) {
	if c := ev.GetCursor(); c != "" {
		if _, dup := w.seen[c]; dup {
			return
		}
		w.remember(c)
	}
	out := Event{Sandbox: w.cfg.Sandbox, Cursor: ev.GetCursor(), Time: w.now()}
	switch p := ev.GetPayload().(type) {
	case *pb.SandboxStreamEvent_Sandbox:
		out.Kind = KindStatus
		out.Status = statusFromProto(p.Sandbox)
	case *pb.SandboxStreamEvent_Log:
		out.Kind = KindLog
		out.Log = logFromProto(p.Log)
		if t := p.Log.GetEventTime(); t != nil {
			out.Time = t.AsTime()
		}
	case *pb.SandboxStreamEvent_Event:
		out.Kind = KindPlatform
		out.Platform = &Platform{Source: p.Event.GetSource(), Type: p.Event.GetType(), Reason: p.Event.GetReason(),
			Message: p.Event.GetMessage(), Metadata: p.Event.GetMetadata()}
		if t := p.Event.GetEventTime(); t != nil {
			out.Time = t.AsTime()
		}
	case *pb.SandboxStreamEvent_Warning:
		out.Kind = KindWarning
		out.Warning = &Warning{Message: p.Warning.GetMessage()}
	case *pb.SandboxStreamEvent_DraftPolicyUpdate:
		d := p.DraftPolicyUpdate
		out.Kind = KindDraft
		out.Draft = &DraftUpdate{DraftVersion: d.GetDraftVersion(), NewChunks: d.GetNewChunks(), TotalPending: d.GetTotalPending(), Summary: d.GetSummary()}
	default:
		return // a payload a newer gateway added
	}
	handle(out)
	if c := ev.GetCursor(); c != "" {
		// Cursors compare byte-wise within one cursor space; keep the
		// greatest processed one.
		if w.cursor == "" || c > w.cursor {
			w.cursor = c
			w.dirty = true
		}
		if w.now().Sub(w.lastSave) >= w.cfg.SaveInterval {
			w.flush(handle)
		}
	}
}

func (w *Watcher) remember(cursor string) {
	w.seen[cursor] = struct{}{}
	w.seenOrder = append(w.seenOrder, cursor)
	if len(w.seenOrder) > w.cfg.DedupeWindow {
		delete(w.seen, w.seenOrder[0])
		w.seenOrder = w.seenOrder[1:]
	}
}

// flush persists a changed cursor. A failing save is reported as a local
// warning; the watch goes on and retries at the next flush.
func (w *Watcher) flush(handle func(Event)) {
	if !w.dirty || w.cfg.SaveCursor == nil {
		return
	}
	w.lastSave = w.now()
	if err := w.cfg.SaveCursor(w.cursor); err != nil {
		handle(Event{Kind: KindWarning, Sandbox: w.cfg.Sandbox, Time: w.now(),
			Warning: &Warning{Message: "saving the stream cursor failed: " + err.Error(), Local: true}})
		return
	}
	w.dirty = false
}

func (w *Watcher) jitter(d time.Duration) time.Duration {
	j := w.cfg.Backoff.Jitter
	if j <= 0 {
		return d
	}
	if j > 1 {
		j = 1
	}
	return d - time.Duration(rand.Float64()*j*float64(d))
}

var phases = map[pb.SandboxPhase]openshell.SandboxPhase{
	pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING: openshell.PhaseProvisioning,
	pb.SandboxPhase_SANDBOX_PHASE_READY:        openshell.PhaseReady,
	pb.SandboxPhase_SANDBOX_PHASE_ERROR:        openshell.PhaseError,
	pb.SandboxPhase_SANDBOX_PHASE_DELETING:     openshell.PhaseDeleting,
	pb.SandboxPhase_SANDBOX_PHASE_UNKNOWN:      openshell.PhaseUnknown,
	pb.SandboxPhase_SANDBOX_PHASE_STOPPING:     openshell.PhaseStopping,
	pb.SandboxPhase_SANDBOX_PHASE_STOPPED:      openshell.PhaseStopped,
	pb.SandboxPhase_SANDBOX_PHASE_STARTING:     openshell.PhaseStarting,
	pb.SandboxPhase_SANDBOX_PHASE_COMPLETED:    openshell.PhaseCompleted,
}

var admissions = map[pb.ConfigurationAdmissionState]openshell.ConfigAdmissionState{
	pb.ConfigurationAdmissionState_CONFIGURATION_ADMISSION_STATE_PENDING:  openshell.AdmissionPending,
	pb.ConfigurationAdmissionState_CONFIGURATION_ADMISSION_STATE_ACCEPTED: openshell.AdmissionAccepted,
	pb.ConfigurationAdmissionState_CONFIGURATION_ADMISSION_STATE_REJECTED: openshell.AdmissionRejected,
}

func statusFromProto(sb *pb.Sandbox) *Status {
	st := &Status{ID: sb.GetMetadata().GetId(), Name: sb.GetMetadata().GetName(), Phase: openshell.PhaseUnknown}
	s := sb.GetStatus()
	if s == nil {
		return st
	}
	if p, ok := phases[s.GetPhase()]; ok {
		st.Phase = p
	}
	st.PolicyVersion = s.GetCurrentPolicyVersion()
	if s.ExitCode != nil {
		code := s.GetExitCode()
		st.ExitCode = &code
	}
	for _, c := range s.GetConditions() {
		st.Conditions = append(st.Conditions, Condition{Type: c.GetType(), Status: c.GetStatus(), Reason: c.GetReason(), Message: c.GetMessage()})
	}
	if adm := s.GetConfigurationAdmission(); adm != nil {
		st.Admission = openshell.AdmissionUnknown
		if a, ok := admissions[adm.GetState()]; ok {
			st.Admission = a
		}
		st.AdmissionError = adm.GetError()
	}
	return st
}

func logFromProto(l *pb.SandboxLogLine) *Log {
	out := &Log{SandboxID: l.GetSandboxId(), Level: l.GetLevel(), Target: l.GetTarget(), Message: l.GetMessage(),
		Source: l.GetSource(), Fields: l.GetFields()}
	if out.Source == "" {
		out.Source = "gateway"
	}
	if ocsf.IsShorthand(out.Level, out.Target) {
		if rec, err := ocsf.Parse(out.Message); err == nil {
			out.OCSF = &rec
		}
	}
	return out
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
